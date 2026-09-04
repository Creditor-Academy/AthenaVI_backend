/**
 * Dashboard / My Work slide JPEG snapshots (Canva-style).
 * Rasterizes the same HTML as export at native canvas size, then sharp-downscales.
 * Never runs on the request thread for rendering — callers enqueue via setImmediate.
 */

const crypto = require('crypto');
const sharp = require('sharp');
const { redisClient } = require('../../shared/config/redis');
const logger = require('../../shared/utils/logger');
const s3Service = require('../s3/s3.service');
const presentationDao = require('./presentation.dao');
const { buildDeckHtml } = require('./slideHtml');
const { CANVAS_WIDTH, CANVAS_HEIGHT, resolveAspectCanvas } = require('./presentation.constants');

const PRESIGN_TTL_SEC = 3600;
const JPEG_QUALITY = 72;
const SLIDE_RENDER_TIMEOUT_MS = 15_000;
const FONT_WAIT_MS = 3_000;
const LOCK_TTL_SEC = 90;
const BROWSER_LOCK_TTL_SEC = 120;
const DEBOUNCE_TTL_SEC = 2;
const FAIL_MAX_ATTEMPTS = 3;
const FAIL_COOLDOWN_SEC = 600;
const POLL_MS_WHEN_PENDING = 1000;

const PREVIEW_STATUS = Object.freeze({
  PENDING: 'PENDING',
  READY: 'READY',
  FAILED: 'FAILED',
});

/** Process-wide: only one Puppeteer browser at a time on this Node process. */
let localBrowserBusy = false;

function lockKey(slideId) {
  return `ppt:preview:lock:${slideId}`;
}
function debounceKey(slideId) {
  return `ppt:preview:debounce:${slideId}`;
}
function failKey(slideId) {
  return `ppt:preview:fail:${slideId}`;
}
const BROWSER_LOCK_KEY = 'ppt:preview:browser';

function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

function computePreviewHash({ elements, themeTokens, aspectRatio }) {
  const payload = stableStringify({
    elements: elements || null,
    themeTokens: themeTokens || null,
    aspectRatio: aspectRatio || '16:9',
  });
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function previewOutSize(aspectRatio) {
  const ar = String(aspectRatio || '16:9');
  if (ar === '4:3') return { width: 800, height: 600 };
  return { width: 960, height: 540 };
}

function previewS3Key({ workspaceId, deckId, slideId, hash }) {
  const hash8 = String(hash || 'pending').slice(0, 8);
  return `presentations/${workspaceId}/${deckId}/previews/${slideId}-${hash8}.jpg`;
}

async function redisSetNx(key, ttlSec) {
  try {
    const result = await redisClient.set(key, '1', { NX: true, EX: ttlSec });
    return result === 'OK';
  } catch (err) {
    logger.warn?.({ err: err.message, key }, 'ppt_preview_redis_setnx_failed');
    return true;
  }
}

async function redisDel(key) {
  try {
    await redisClient.del(key);
  } catch {
    // ignore
  }
}

async function redisIncrFail(slideId) {
  const key = failKey(slideId);
  try {
    const n = await redisClient.incr(key);
    if (n === 1) await redisClient.expire(key, FAIL_COOLDOWN_SEC);
    return n;
  } catch {
    return 1;
  }
}

async function redisFailCount(slideId) {
  try {
    const v = await redisClient.get(failKey(slideId));
    return Number(v) || 0;
  } catch {
    return 0;
  }
}

async function redisClearFail(slideId) {
  await redisDel(failKey(slideId));
}

/**
 * Debounced enqueue: at most one job kick per slide per DEBOUNCE_TTL_SEC.
 * @returns {boolean} true if enqueued
 */
async function enqueueSlidePreview(slideId, { force = false } = {}) {
  if (!slideId) return false;
  if (!force) {
    const acquired = await redisSetNx(debounceKey(slideId), DEBOUNCE_TTL_SEC);
    if (!acquired) return false;
  }
  setImmediate(() => {
    processSlidePreview(slideId).catch((err) => {
      logger.error?.({ err: err.message, slideId }, 'ppt_preview_process_failed') ||
        console.error('ppt_preview_process_failed', slideId, err);
    });
  });
  return true;
}

async function enqueueDeckPreviews(deckId, { force = false } = {}) {
  if (!deckId) return;
  const slides = await presentationDao.findSlidePreviewRowsByDeckId(deckId);
  const ready = (slides || [])
    .filter((s) => s.status === 'READY')
    .sort((a, b) => a.order - b.order);
  for (const slide of ready) {
    // eslint-disable-next-line no-await-in-loop
    await enqueueSlidePreview(slide.id, { force });
  }
}

async function enqueueDeckPreviewsIfStale(deckId) {
  if (!deckId) return;
  const deck = await presentationDao.findDeckPreviewMeta(deckId);
  if (!deck) return;
  const slides = await presentationDao.findSlidePreviewRowsByDeckId(deckId);
  const themeTokens = deck.themeTokens;
  const aspectRatio = deck.aspectRatio || '16:9';

  for (const slide of (slides || [])
    .filter((s) => s.status === 'READY')
    .sort((a, b) => a.order - b.order)) {
    const hash = computePreviewHash({
      elements: slide.elements,
      themeTokens,
      aspectRatio,
    });
    const needs =
      !slide.previewS3Key ||
      slide.previewHash !== hash ||
      slide.previewStatus !== PREVIEW_STATUS.READY;
    if (!needs) continue;

    if (slide.previewStatus === PREVIEW_STATUS.FAILED) {
      // eslint-disable-next-line no-await-in-loop
      const fails = await redisFailCount(slide.id);
      if (fails >= FAIL_MAX_ATTEMPTS) continue;
    }
    // eslint-disable-next-line no-await-in-loop
    await enqueueSlidePreview(slide.id);
  }
}

async function acquireBrowserSlot() {
  if (localBrowserBusy) return false;
  const ok = await redisSetNx(BROWSER_LOCK_KEY, BROWSER_LOCK_TTL_SEC);
  if (!ok) return false;
  localBrowserBusy = true;
  return true;
}

async function releaseBrowserSlot() {
  localBrowserBusy = false;
  await redisDel(BROWSER_LOCK_KEY);
}

async function waitForBrowserSlot(maxWaitMs = 60_000) {
  const started = Date.now();
  while (Date.now() - started < maxWaitMs) {
    // eslint-disable-next-line no-await-in-loop
    if (await acquireBrowserSlot()) return true;
    // eslint-disable-next-line no-await-in-loop
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function withPreviewBrowser(fn) {
  const got = await waitForBrowserSlot();
  if (!got) throw new Error('Preview browser slot unavailable');
  let browser;
  try {
    const puppeteer = require('puppeteer');
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
    const page = await browser.newPage();
    return await fn(page);
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
        // ignore
      }
    }
    await releaseBrowserSlot();
  }
}

async function deleteS3Quiet(key) {
  if (!key) return;
  try {
    await s3Service.deleteFile(key);
  } catch {
    // best-effort
  }
}

async function syncProjectThumbnailFromSlide(projectId, previewS3Key) {
  if (!projectId || !previewS3Key) return;
  try {
    const persistUrl = s3Service.buildPublicUrl(previewS3Key);
    await presentationDao.updateProjectThumbnail(projectId, persistUrl);
  } catch (err) {
    logger.warn?.({ err: err.message, projectId }, 'ppt_preview_thumbnail_sync_failed');
  }
}

async function processSlidePreview(slideId) {
  const locked = await redisSetNx(lockKey(slideId), LOCK_TTL_SEC);
  if (!locked) return;

  try {
    const ctx = await presentationDao.findSlidePreviewContext(slideId);
    if (!ctx?.slide || !ctx.deck) return;

    const { slide, deck, project } = ctx;
    if (slide.status !== 'READY') return;

    const hash = computePreviewHash({
      elements: slide.elements,
      themeTokens: deck.themeTokens,
      aspectRatio: deck.aspectRatio,
    });

    if (
      slide.previewHash === hash &&
      slide.previewS3Key &&
      slide.previewStatus === PREVIEW_STATUS.READY
    ) {
      return;
    }

    await presentationDao.updateSlide(slideId, {
      previewStatus: PREVIEW_STATUS.PENDING,
    });

    const canvas = slide.elements?.canvas || resolveAspectCanvas(deck.aspectRatio);
    const canvasW = Number(canvas.width) || CANVAS_WIDTH;
    const canvasH = Number(canvas.height) || CANVAS_HEIGHT;
    const out = previewOutSize(deck.aspectRatio);

    const html = await buildDeckHtml(
      {
        themeTokens: deck.themeTokens,
        aspectRatio: deck.aspectRatio,
        slides: [slide],
      },
      { inlineImages: true, injectFonts: true, slides: [slide] }
    );

    const pngBuf = await withPreviewBrowser(async (page) => {
      await page.setViewport({ width: canvasW, height: canvasH, deviceScaleFactor: 1 });
      await page.setContent(html, {
        waitUntil: 'domcontentloaded',
        timeout: SLIDE_RENDER_TIMEOUT_MS,
      });
      try {
        await Promise.race([
          page.evaluate(() => (document.fonts ? document.fonts.ready : Promise.resolve())),
          new Promise((r) => setTimeout(r, FONT_WAIT_MS)),
        ]);
      } catch {
        // fonts optional
      }
      return page.screenshot({
        type: 'png',
        fullPage: false,
      });
    });

    const jpegBuf = await sharp(Buffer.from(pngBuf))
      .resize(out.width, out.height, { fit: 'fill' })
      .jpeg({ quality: JPEG_QUALITY, mozjpeg: true })
      .toBuffer();

    const workspaceId = project?.workspaceId;
    if (!workspaceId) throw new Error('Missing workspaceId for preview upload');

    const newKey = previewS3Key({
      workspaceId,
      deckId: deck.id,
      slideId,
      hash,
    });
    const oldKey = slide.previewS3Key || null;

    await s3Service.uploadFileToKey(jpegBuf, newKey, 'image/jpeg');

    await presentationDao.updateSlide(slideId, {
      previewS3Key: newKey,
      previewHash: hash,
      previewStatus: PREVIEW_STATUS.READY,
    });

    if (oldKey && oldKey !== newKey) {
      await deleteS3Quiet(oldKey);
    }

    await redisClearFail(slideId);

    if (Number(slide.order) === 0) {
      await syncProjectThumbnailFromSlide(deck.projectId, newKey);
    }
  } catch (err) {
    logger.error?.({ err: err.message, slideId }, 'ppt_preview_raster_failed');
    try {
      await presentationDao.updateSlide(slideId, {
        previewStatus: PREVIEW_STATUS.FAILED,
      });
    } catch {
      // ignore
    }
    await redisIncrFail(slideId);
  } finally {
    await redisDel(lockKey(slideId));
  }
}

/**
 * Copy preview JPEG when duplicating a slide (no Puppeteer).
 */
async function copyPreviewOnDuplicate({ sourceSlide, newSlide, workspaceId, deckId }) {
  if (!sourceSlide?.previewS3Key || !newSlide?.id) return;
  const hash = sourceSlide.previewHash || 'copy';
  const destKey = previewS3Key({
    workspaceId,
    deckId,
    slideId: newSlide.id,
    hash,
  });
  try {
    await s3Service.copyFile(sourceSlide.previewS3Key, destKey);
    await presentationDao.updateSlide(newSlide.id, {
      previewS3Key: destKey,
      previewHash: sourceSlide.previewHash || null,
      previewStatus: sourceSlide.previewStatus || PREVIEW_STATUS.READY,
    });
  } catch (err) {
    logger.warn?.({ err: err.message }, 'ppt_preview_copy_failed');
    await enqueueSlidePreview(newSlide.id, { force: true });
  }
}

async function deletePreviewForSlide(slide) {
  if (!slide?.previewS3Key) return;
  await deleteS3Quiet(slide.previewS3Key);
}

function deckPreviewStatus(slides) {
  const readySlides = (slides || []).filter((s) => s.status === 'READY');
  if (!readySlides.length) return PREVIEW_STATUS.PENDING;
  const withJpeg = readySlides.filter(
    (s) => s.previewS3Key && s.previewStatus === PREVIEW_STATUS.READY
  );
  if (withJpeg.length === readySlides.length) return PREVIEW_STATUS.READY;
  if (withJpeg.length === 0) return PREVIEW_STATUS.PENDING;
  return 'PARTIAL';
}

function buildPreviewEtag({ presentationId, slides, aspectRatio, status }) {
  const parts = (slides || [])
    .map(
      (s) =>
        `${s.id}:${s.order}:${s.previewHash || ''}:${s.previewStatus || ''}:${s.previewS3Key || ''}`
    )
    .join('|');
  const digest = crypto
    .createHash('sha1')
    .update(`${presentationId}|${status}|${aspectRatio}|${parts}`)
    .digest('hex')
    .slice(0, 16);
  return `W/"ppt-prev-${digest}"`;
}

/**
 * Lean GET payload for dashboard modal. May kick background jobs.
 */
async function getPresentationPreview({ workspaceId, presentationId, ifNoneMatch }) {
  const row = await presentationDao.findPresentationPreview(workspaceId, presentationId);
  if (!row?.deck) {
    const AppError = require('../../shared/utils/AppError');
    const messages = require('../../shared/utils/messages');
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }

  const { deck } = row;
  const slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);

  setImmediate(() => {
    enqueueDeckPreviewsIfStale(deck.id).catch(() => {});
  });

  const etag = buildPreviewEtag({
    presentationId,
    slides,
    aspectRatio: deck.aspectRatio,
    status: deck.status,
  });

  if (ifNoneMatch && ifNoneMatch === etag) {
    return { notModified: true, etag };
  }

  const slidePayloads = await Promise.all(
    slides.map(async (s) => {
      let previewImageUrl = null;
      const previewStatus =
        s.previewStatus ||
        (s.previewS3Key ? PREVIEW_STATUS.READY : PREVIEW_STATUS.PENDING);
      if (s.previewS3Key && previewStatus === PREVIEW_STATUS.READY) {
        try {
          previewImageUrl = await s3Service.getPresignedGetUrl(s.previewS3Key, PRESIGN_TTL_SEC);
        } catch {
          previewImageUrl = null;
        }
      }
      const content = s.content && typeof s.content === 'object' ? s.content : {};
      return {
        id: s.id,
        order: s.order,
        status: s.status,
        title: content.title != null ? content.title : null,
        previewImageUrl,
        previewStatus,
      };
    })
  );

  const previewStatus = deckPreviewStatus(slides);
  const nextPollMs = previewStatus === PREVIEW_STATUS.READY ? 0 : POLL_MS_WHEN_PENDING;

  return {
    notModified: false,
    etag,
    data: {
      id: presentationId,
      title: row.name,
      status: deck.status,
      aspectRatio: deck.aspectRatio || '16:9',
      slideCount: slides.length,
      previewStatus,
      nextPollMs,
      slides: slidePayloads,
    },
  };
}

module.exports = {
  PREVIEW_STATUS,
  computePreviewHash,
  enqueueSlidePreview,
  enqueueDeckPreviews,
  enqueueDeckPreviewsIfStale,
  processSlidePreview,
  copyPreviewOnDuplicate,
  deletePreviewForSlide,
  getPresentationPreview,
  deckPreviewStatus,
  PRESIGN_TTL_SEC,
};
