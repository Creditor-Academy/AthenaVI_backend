/**
 * Shared deck render payload.
 *
 * Both the member preview (`GET /workspaces/:ws/presentations/:id/preview`) and the public
 * share link (`GET /api/p/:token`) serve the same thing: the slide documents the frontend
 * renderer draws. Keeping one builder means guest view mode and the dashboard preview can
 * never drift apart, and neither path rasterizes anything server-side.
 */

const zlib = require('zlib');
const {
  presignSlidesForPublic,
  buildContentVersion,
} = require('../presentationShare/presentationShare.presign');
const { enrichSlidesForClient } = require('./elementContent.normalize');
const { fontCssUrlFromThemeTokens } = require('../../shared/fonts/googleFontsCss');
const { redisClient } = require('../../shared/config/redis');
const presentationDao = require('./presentation.dao');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');

const DEFAULT_PAGE_LIMIT = 8;
const MAX_PAGE_LIMIT = 24;
const GENERATING_POLL_MS = 1500;

const RENDER_CACHE_TTL_SEC =
  Number(process.env.PPT_RENDER_CACHE_TTL_SEC) > 0
    ? Number(process.env.PPT_RENDER_CACHE_TTL_SEC)
    : 300;
/** While a deck generates the version rotates on every slide, so keep those keys short-lived. */
const RENDER_CACHE_GENERATING_TTL_SEC = 15;
/** Do not let one huge deck page dominate Redis memory. */
const RENDER_CACHE_MAX_BYTES = 1_000_000;

/** Strip internal storage pointers from element content before it leaves the server. */
function sanitizeElementsDoc(doc) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.elements)) {
    return doc || null;
  }

  return {
    ...doc,
    elements: doc.elements.map((el) => {
      if (!el || !el.content || typeof el.content !== 'object') return el;
      const { s3Key, assetId, ...content } = el.content;
      void s3Key;
      void assetId;
      return { ...el, content };
    }),
  };
}

/**
 * Render-only projection of a slide. `content` / `imageRef` are read from the DB (titles and
 * legacy hero keys live there) but never shipped — the renderer only reads `elements`.
 */
function toPublicSlide(slide, { includeProgress = false } = {}) {
  return {
    id: slide.id,
    order: slide.order,
    status: slide.status,
    ...(includeProgress ? { progressStatus: slide.progressStatus ?? null } : {}),
    ...(slide.title != null ? { title: slide.title } : {}),
    ...(slide.description != null ? { description: slide.description } : {}),
    elements: sanitizeElementsDoc(slide.elements),
  };
}

/** Presign media, normalize element content, then reduce to the render projection. */
async function buildRenderSlides(slides, { includeProgress = false } = {}) {
  const presigned = await presignSlidesForPublic(slides || []);
  return enrichSlidesForClient(presigned).map((slide) => toPublicSlide(slide, { includeProgress }));
}

/**
 * Deck envelope around already-rendered slides.
 * @param {{ project: object, deck: object, slides: object[], slideCount?: number,
 *   contentUpdatedAt?: string|null, extra?: object|null }} params
 */
function buildDeckRenderData({
  project,
  deck,
  slides,
  slideCount,
  contentUpdatedAt = null,
  extra = null,
}) {
  return {
    id: project?.id,
    title: project?.name,
    status: deck?.status,
    aspectRatio: deck?.aspectRatio,
    locale: deck?.locale ?? null,
    themeTokens: deck?.themeTokens,
    fontCssUrl: fontCssUrlFromThemeTokens(deck?.themeTokens),
    contentUpdatedAt,
    slideCount: slideCount != null ? slideCount : (slides || []).length,
    slides: slides || [],
    ...(extra || {}),
  };
}

/**
 * Full payload with ETag, for callers that already hold every slide they intend to serve.
 * @param {{ project: object, deck: object, slides: object[], share?: object|null,
 *   includeProgress?: boolean, extra?: object|null }} params
 */
async function buildDeckRenderPayload({
  project,
  deck,
  slides,
  share = null,
  includeProgress = false,
  extra = null,
}) {
  const version = buildContentVersion({ deck, slides, share });
  const rendered = await buildRenderSlides(slides, { includeProgress });

  return {
    etag: version.etag,
    contentUpdatedAt: version.contentUpdatedAt,
    data: buildDeckRenderData({
      project,
      deck,
      slides: rendered,
      slideCount: rendered.length,
      contentUpdatedAt: version.contentUpdatedAt,
      extra,
    }),
  };
}

function toMs(value) {
  const ms = value ? new Date(value).getTime() : 0;
  return Number.isFinite(ms) ? ms : 0;
}

/**
 * Version from the cheap aggregate probe, so a paginated read can answer `If-None-Match`
 * without loading a single slide row. Slide count is folded in because deletions do not
 * touch the Deck row and could otherwise revert to a previously served tag.
 *
 * @param {{ deckUpdatedAt: Date, slideUpdatedAt: Date|null, readySlideCount: number }|null} probe
 */
function buildDeckVersionFromProbe(probe) {
  const contentVersionMs = Math.max(toMs(probe?.deckUpdatedAt), toMs(probe?.slideUpdatedAt));
  return {
    contentVersionMs,
    contentUpdatedAt: contentVersionMs ? new Date(contentVersionMs).toISOString() : null,
    slideCount: Number(probe?.readySlideCount) || 0,
  };
}

/**
 * Express 5 exposes `req.query` through a getter, so the Joi middleware's coerced value never
 * lands back on the request: paging arrives here as strings. Coerce and clamp at the boundary
 * instead of trusting the caller.
 */
function normalizePaging({ offset, limit }) {
  const rawOffset = Math.floor(Number(offset));
  const rawLimit = Math.floor(Number(limit));
  return {
    offset: Number.isFinite(rawOffset) && rawOffset > 0 ? rawOffset : 0,
    limit: Number.isFinite(rawLimit)
      ? Math.min(Math.max(rawLimit, 1), MAX_PAGE_LIMIT)
      : DEFAULT_PAGE_LIMIT,
  };
}

const renderCacheKey = ({ presentationId, contentVersionMs, offset, limit }) =>
  `ppt:render:v1:${presentationId}:${contentVersionMs}:${offset}:${limit}`;

function renderEtag({ contentVersionMs, slideCount, offset, limit }) {
  return `W/"ppt-render-${contentVersionMs}-${slideCount}-${offset}-${limit}"`;
}

function etagMatches(ifNoneMatch, etag) {
  const header = String(ifNoneMatch || '').trim();
  if (!header) return false;
  if (header === '*') return true;
  return header
    .split(',')
    .map((value) => value.trim())
    .some((value) => value === etag);
}

/** Slide rows are cached unsigned: presigned URLs must never outlive their own TTL. */
async function readCachedSlidePage(key) {
  try {
    const cached = await redisClient.get(key);
    if (!cached) return null;
    return JSON.parse(zlib.gunzipSync(Buffer.from(cached, 'base64')).toString('utf8'));
  } catch (err) {
    logger.warn?.('ppt_render_cache_read_failed', { key, error: err.message });
    return null;
  }
}

async function writeCachedSlidePage(key, rows, ttlSec) {
  try {
    const packed = zlib.gzipSync(Buffer.from(JSON.stringify(rows), 'utf8'));
    if (packed.byteLength > RENDER_CACHE_MAX_BYTES) return;
    await redisClient.set(key, packed.toString('base64'), { EX: ttlSec });
  } catch (err) {
    logger.warn?.('ppt_render_cache_write_failed', { key, error: err.message });
  }
}

/**
 * The card thumbnail is a render of slide 1, so slide 1's own timestamp is the precise
 * comparison. Later pages cannot see it, and the frontend only captures from the first
 * page, so those fall back to the deck-wide max.
 */
function isCoverStale({ project, probe, firstSlide }) {
  if (!project?.thumbnail || !project.thumbnailUpdatedAt) return true;
  const capturedMs = toMs(project.thumbnailUpdatedAt);
  const contentMs = toMs(firstSlide?.updatedAt || probe?.slideUpdatedAt);
  return contentMs > capturedMs;
}

/**
 * Read-only render payload for the dashboard preview modal (and, with a large `limit`,
 * present mode). Nothing is rasterized, no background job is kicked, and no row is written.
 *
 * @param {{ workspaceId: string, presentationId: string, ifNoneMatch?: string|null,
 *   offset?: number, limit?: number }} params
 */
async function getPresentationRenderPreview({
  workspaceId,
  presentationId,
  ifNoneMatch = null,
  offset: rawOffset = 0,
  limit: rawLimit = DEFAULT_PAGE_LIMIT,
}) {
  const { offset, limit } = normalizePaging({ offset: rawOffset, limit: rawLimit });

  // Independent queries: the slide probe filters through the deck relation, so neither waits
  // on the other. One round trip of wall time is all a 304 costs.
  const [project, slideVersion] = await Promise.all([
    presentationDao.findPresentationRenderMeta(workspaceId, presentationId),
    presentationDao.findSlideVersionByProject(presentationId),
  ]);

  if (!project?.deck) {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }

  const { deck } = project;
  const probe = { deckUpdatedAt: deck.updatedAt, ...slideVersion };
  const version = buildDeckVersionFromProbe(probe);

  const etag = renderEtag({
    contentVersionMs: version.contentVersionMs,
    slideCount: version.slideCount,
    offset,
    limit,
  });

  // Answered before a single slide row is read.
  if (etagMatches(ifNoneMatch, etag)) {
    return { notModified: true, etag };
  }

  const cacheKey = renderCacheKey({
    presentationId,
    contentVersionMs: version.contentVersionMs,
    offset,
    limit,
  });

  let slideRows = await readCachedSlidePage(cacheKey);
  if (!slideRows) {
    slideRows = await presentationDao.findSlideRenderPage(deck.id, { offset, limit });
    // Populating the cache benefits the *next* reader; never make this one wait for it.
    void writeCachedSlidePage(
      cacheKey,
      slideRows,
      deck.status === 'GENERATING' ? RENDER_CACHE_GENERATING_TTL_SEC : RENDER_CACHE_TTL_SEC
    );
  }

  const slides = await buildRenderSlides(slideRows);
  const servedThrough = offset + slides.length;

  return {
    notModified: false,
    etag,
    data: buildDeckRenderData({
      project,
      deck,
      slides,
      slideCount: version.slideCount,
      contentUpdatedAt: version.contentUpdatedAt,
      extra: {
        offset,
        limit,
        nextOffset: servedThrough < version.slideCount ? servedThrough : null,
        coverStale: isCoverStale({
          project,
          probe,
          firstSlide: offset === 0 ? slideRows[0] : null,
        }),
        nextPollMs: deck.status === 'GENERATING' ? GENERATING_POLL_MS : 0,
      },
    }),
  };
}

module.exports = {
  DEFAULT_PAGE_LIMIT,
  sanitizeElementsDoc,
  toPublicSlide,
  buildRenderSlides,
  buildDeckRenderData,
  buildDeckRenderPayload,
  buildDeckVersionFromProbe,
  getPresentationRenderPreview,
};
