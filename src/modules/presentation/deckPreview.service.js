const crypto = require('crypto');
const logger = require('../../shared/utils/logger');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const presentationDao = require('./presentation.dao');
const { loadPresentationDeck } = require('./deckGeneration.service');
const s3Service = require('../s3/s3.service');
const { renderSlideScreenshots } = require('./export.service');

const PRESIGN_TTL_SEC = 3600;
const DEFAULT_POLL_MS = 1200;
/** Process a few slides per job so GET /preview can return partial URLs quickly. */
const BATCH_SIZE = 3;

/** Prevent concurrent Puppeteer snapshot jobs per deck. */
const runningDeckJobs = new Set();
/** Coalesce schedule calls while a job is already queued/running. */
const queuedDeckJobs = new Set();
/** Decks that hit a permanent renderer failure (e.g. missing Chrome). */
const blockedDeckJobs = new Set();
let chromeUnavailable = false;

function slideTitle(slide) {
  const content = slide?.content && typeof slide.content === 'object' ? slide.content : {};
  const candidates = [content.title, content.heading, content.headline, content.name];
  for (const value of candidates) {
    const text = String(value || '').trim();
    if (text) return text;
  }

  const elements = Array.isArray(slide?.elements?.elements) ? slide.elements.elements : [];
  const textEl = elements.find(
    (el) =>
      el &&
      (el.type === 'text' || el.type === 'heading' || el.role === 'title' || el.role === 'heading') &&
      String(el.content?.text || el.content || '').trim()
  );
  if (textEl) {
    const text = String(textEl.content?.text || textEl.content || '').trim();
    if (text) return text.split('\n')[0].slice(0, 120);
  }

  return `Slide ${(slide?.order ?? 0) + 1}`;
}

function stableThemeFingerprint(themeTokens) {
  if (!themeTokens || typeof themeTokens !== 'object') return '';
  const palette = themeTokens.palette || {};
  return [
    themeTokens.themeId || '',
    palette.bg || '',
    palette.primary || '',
    palette.secondary || '',
    palette.accent || '',
    palette.text || '',
    themeTokens.appearance || '',
  ].join('|');
}

function computePreviewHash(slide, deck) {
  const payload = {
    slideId: slide?.id,
    updatedAt: slide?.updatedAt ? new Date(slide.updatedAt).toISOString() : null,
    // Hash a compact fingerprint of the canvas, not the entire JSON tree twice.
    elementsSig: crypto
      .createHash('sha1')
      .update(JSON.stringify(slide?.elements || null))
      .digest('hex'),
    imageRefSig: crypto
      .createHash('sha1')
      .update(JSON.stringify(slide?.imageRef || null))
      .digest('hex'),
    aspectRatio: deck?.aspectRatio || null,
    theme: stableThemeFingerprint(deck?.themeTokens),
  };
  return crypto.createHash('sha1').update(JSON.stringify(payload)).digest('hex');
}

function isSnapshotFresh(slide, deck) {
  if (!slide?.previewS3Key) return false;
  if (String(slide.previewStatus || '').toUpperCase() === 'FAILED') return false;
  if (String(slide.previewStatus || '').toUpperCase() !== 'READY') return false;
  return slide.previewHash === computePreviewHash(slide, deck);
}

function buildEtag({ presentationId, deck, slides }) {
  const parts = [
    presentationId,
    deck?.updatedAt ? new Date(deck.updatedAt).toISOString() : '',
    ...slides.map((s) =>
      [
        s.id,
        s.order,
        s.updatedAt ? new Date(s.updatedAt).toISOString() : '',
        s.previewHash || '',
        s.previewStatus || '',
        s.previewS3Key || '',
      ].join(':')
    ),
  ];
  const hash = crypto.createHash('sha1').update(parts.join('|')).digest('hex');
  return `"deck-preview-${hash}"`;
}

async function presignPreview(key) {
  if (!key) return null;
  try {
    return await s3Service.getPresignedGetUrl(key, PRESIGN_TTL_SEC);
  } catch (err) {
    logger.warn?.('deck_preview_presign_failed', { key, error: err.message }) ||
      console.warn('deck preview presign failed', err.message);
    return null;
  }
}

function slidesNeedingSnapshot(slides, deck) {
  return slides.filter((slide) => !isSnapshotFresh(slide, deck));
}

function prioritizeSlides(slides) {
  return [...slides].sort((a, b) => {
    // Prefer first slide, then missing keys, then order.
    const aFirst = (a.order ?? 0) === 0 ? 0 : 1;
    const bFirst = (b.order ?? 0) === 0 ? 0 : 1;
    if (aFirst !== bFirst) return aFirst - bFirst;
    const aMissing = a.previewS3Key ? 1 : 0;
    const bMissing = b.previewS3Key ? 1 : 0;
    if (aMissing !== bMissing) return aMissing - bMissing;
    return (a.order ?? 0) - (b.order ?? 0);
  });
}

/**
 * Background: render stale/missing slides to JPEG and store on the slide rows.
 * Safe to call repeatedly — concurrent runs for the same deck are collapsed.
 */
function isChromeMissingError(err) {
  const msg = String(err?.message || err || '');
  return /could not find chrome|chrome.*not found|executable doesn't exist|browser was not found/i.test(
    msg
  );
}

function scheduleDeckPreviewRefresh(deckId, { force = false } = {}) {
  if (!deckId) return;
  if (force) {
    // Allow recovery after Chrome was missing / temporarily blocked.
    chromeUnavailable = false;
    blockedDeckJobs.delete(deckId);
  }
  if (chromeUnavailable && !force) return;
  if (blockedDeckJobs.has(deckId) && !force) return;
  if (runningDeckJobs.has(deckId) || queuedDeckJobs.has(deckId)) return;
  queuedDeckJobs.add(deckId);

  setImmediate(() => {
    queuedDeckJobs.delete(deckId);
    refreshDeckPreviews(deckId, { force }).catch((err) => {
      logger.error?.('deck_preview_refresh_failed', { deckId, error: err.message }) ||
        console.error('deck preview refresh failed', deckId, err);
    });
  });
}

async function resolveWorkspaceId(deck) {
  if (deck.project?.workspaceId) return deck.project.workspaceId;
  if (!deck.projectId) return 'unknown';
  const prisma = require('../../shared/config/prismaClient');
  const project = await prisma.project.findUnique({
    where: { id: deck.projectId },
    select: { workspaceId: true },
  });
  return project?.workspaceId || 'unknown';
}

async function persistSlidePreview({ wsId, deck, slide, image }) {
  const key = `presentations/${wsId}/${deck.id}/previews/${slide.id}.jpg`;
  await s3Service.uploadFileToKey(image.data, key, 'image/jpeg');
  await presentationDao.updateSlide(slide.id, {
    previewS3Key: key,
    previewHash: computePreviewHash(slide, deck),
    previewStatus: 'READY',
  });
  return key;
}

async function refreshDeckPreviews(deckId, { force = false } = {}) {
  if (!deckId || runningDeckJobs.has(deckId)) return;
  runningDeckJobs.add(deckId);
  try {
    const deck = await presentationDao.findDeckById(deckId);
    if (!deck) return;

    const slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);
    const targets = prioritizeSlides(force ? slides : slidesNeedingSnapshot(slides, deck));
    if (!targets.length) return;

    const batch = targets.slice(0, BATCH_SIZE);
    for (const slide of batch) {
      // eslint-disable-next-line no-await-in-loop
      await presentationDao.updateSlide(slide.id, { previewStatus: 'PENDING' }).catch(() => null);
    }

    const wsId = await resolveWorkspaceId(deck);
    const prisma = require('../../shared/config/prismaClient');

    await renderSlideScreenshots(deck, {
      slides: batch,
      format: 'jpeg',
      mode: 'preview',
      onSlide: async (image, slide, err) => {
        if (!image) {
          await presentationDao
            .updateSlide(slide.id, { previewStatus: 'FAILED' })
            .catch(() => null);
          logger.warn?.('deck_preview_slide_failed', {
            deckId,
            slideId: slide.id,
            error: err?.message,
          });
          return;
        }
        try {
          const key = await persistSlidePreview({ wsId, deck, slide, image });
          // Promote first slide to project thumbnail as soon as it lands.
          if ((slide.order ?? 0) === 0 && deck.projectId) {
            await prisma.project
              .update({
                where: { id: deck.projectId },
                data: { thumbnail: key },
              })
              .catch(() => null);
          }
        } catch (uploadErr) {
          await presentationDao
            .updateSlide(slide.id, { previewStatus: 'FAILED' })
            .catch(() => null);
          logger.warn?.('deck_preview_upload_failed', {
            deckId,
            slideId: slide.id,
            error: uploadErr.message,
          });
        }
      },
    });

    blockedDeckJobs.delete(deckId);

    const latest = await presentationDao.findDeckById(deckId);
    const stillNeeded = slidesNeedingSnapshot(latest?.slides || [], latest).filter((s) => {
      const st = String(s.previewStatus || '').toUpperCase();
      if (st === 'FAILED') return false;
      return true;
    });
    if (stillNeeded.length) {
      scheduleDeckPreviewRefresh(deckId);
    }
  } catch (err) {
    logger.error?.('deck_preview_refresh_error', { deckId, error: err.message }) ||
      console.error('deck preview refresh error', deckId, err);

    if (isChromeMissingError(err)) {
      chromeUnavailable = true;
      blockedDeckJobs.add(deckId);
      // Stop the frontend from polling forever with empty PENDING slides.
      try {
        const deck = await presentationDao.findDeckById(deckId);
        for (const slide of deck?.slides || []) {
          if (!slide.previewS3Key) {
            // eslint-disable-next-line no-await-in-loop
            await presentationDao.updateSlide(slide.id, { previewStatus: 'FAILED' });
          }
        }
      } catch {
        // ignore
      }
    }
  } finally {
    runningDeckJobs.delete(deckId);
  }
}

async function getDeckPreview({ workspaceId, presentationId, ifNoneMatch }) {
  const { project, deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  if (!project || !deck) {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }

  const slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  const etag = buildEtag({ presentationId, deck, slides });
  const incoming = String(ifNoneMatch || '').trim();
  if (incoming && incoming === etag) {
    return { notModified: true, etag };
  }

  const failedWithoutImage = slides.filter(
    (s) =>
      String(s.previewStatus || '').toUpperCase() === 'FAILED' && !s.previewS3Key
  );
  const needsWork = slidesNeedingSnapshot(slides, deck).filter(
    (s) => String(s.previewStatus || '').toUpperCase() !== 'FAILED'
  );
  if (needsWork.length) {
    scheduleDeckPreviewRefresh(deck.id);
  } else if (failedWithoutImage.length && !chromeUnavailable) {
    // Recover after a Chrome outage marked slides FAILED with no JPEG.
    scheduleDeckPreviewRefresh(deck.id, { force: true });
  }

  const slidePayload = await Promise.all(
    slides.map(async (slide) => {
      const fresh = isSnapshotFresh(slide, deck);
      const failed = String(slide.previewStatus || '').toUpperCase() === 'FAILED';
      const url = slide.previewS3Key ? await presignPreview(slide.previewS3Key) : null;
      let previewStatus = 'PENDING';
      if (fresh && url) previewStatus = 'READY';
      else if (failed && !url) previewStatus = 'FAILED';
      else if (url) previewStatus = 'READY'; // show prior JPEG while refresh runs
      return {
        id: slide.id,
        order: slide.order,
        status: slide.status,
        title: slideTitle(slide),
        previewImageUrl: url,
        previewStatus,
      };
    })
  );

  const readyCount = slidePayload.filter((s) => s.previewStatus === 'READY' && s.previewImageUrl).length;
  const failedCount = slidePayload.filter((s) => s.previewStatus === 'FAILED').length;
  let effectiveStatus = 'PENDING';
  if (!slidePayload.length) effectiveStatus = 'READY';
  else if (readyCount === slidePayload.length) effectiveStatus = 'READY';
  else if (readyCount > 0) effectiveStatus = 'PARTIAL';
  else if (failedCount === slidePayload.length) effectiveStatus = 'READY';

  // Keep polling only while at least one slide still has no image and isn't failed.
  const missingImages = slidePayload.filter(
    (s) => !s.previewImageUrl && s.previewStatus !== 'FAILED'
  ).length;

  return {
    notModified: false,
    etag,
    data: {
      id: presentationId,
      title: project.name || 'Presentation',
      status: deck.status,
      aspectRatio: deck.aspectRatio || '16:9',
      slideCount: slides.length,
      previewStatus: effectiveStatus,
      nextPollMs: missingImages > 0 ? DEFAULT_POLL_MS : 0,
      readyCount,
      slides: slidePayload,
    },
  };
}

module.exports = {
  getDeckPreview,
  scheduleDeckPreviewRefresh,
  refreshDeckPreviews,
  isSnapshotFresh,
  computePreviewHash,
};
