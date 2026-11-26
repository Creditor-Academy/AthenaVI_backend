'use strict';

/**
 * One log line per write to a slide's elements document, and a warning when a write removes
 * images (CANVAS_FIX_PLAN_25NOV2026, L-1). Lets us see which request removed a user's images.
 *
 * Never throws and never blocks a save: every step is best-effort.
 * Turn off with SLIDE_WRITE_LOG=off.
 */

const { AsyncLocalStorage } = require('async_hooks');
const logger = require('../../shared/utils/logger');

const requestContext = new AsyncLocalStorage();
const MAX_LISTED_IDS = 10;

function isEnabled() {
  return String(process.env.SLIDE_WRITE_LOG || '').toLowerCase() !== 'off';
}

/** Express middleware: remembers the request so DAO writes can name the route and user. */
function slideWriteContextMiddleware(req, _res, next) {
  requestContext.run({ req }, next);
}

function currentRequest() {
  try {
    const req = requestContext.getStore()?.req;
    if (!req) return {};
    return {
      route: `${req.method} ${String(req.originalUrl || req.url || '').split('?')[0]}`,
      userId: req.user?.id || null,
    };
  } catch {
    return {};
  }
}

function elementList(doc) {
  if (!doc || typeof doc !== 'object') return [];
  if (Array.isArray(doc)) return doc;
  return Array.isArray(doc.elements) ? doc.elements : [];
}

/** Image element ids, including images inside groups. */
function imageIds(doc) {
  const ids = [];
  const walk = (els) => {
    for (const el of els || []) {
      if (!el || typeof el !== 'object') continue;
      if (el.type === 'image') ids.push(String(el.id || '(no id)'));
      if (Array.isArray(el.children)) walk(el.children);
    }
  };
  walk(elementList(doc));
  return ids;
}

function hasBackgroundImage(doc) {
  return Boolean(doc && typeof doc === 'object' && !Array.isArray(doc) && doc.backgroundImage);
}

/** Pure: what changed between two elements documents (exported for tests). */
function describeSlideWrite(before, after) {
  const beforeImages = imageIds(before);
  const afterImages = new Set(imageIds(after));
  const removedImageIds = beforeImages.filter((id) => !afterImages.has(id));
  return {
    elementsBefore: before == null ? null : elementList(before).length,
    elementsAfter: elementList(after).length,
    imagesBefore: before == null ? null : beforeImages.length,
    imagesAfter: afterImages.size,
    removedImageIds: removedImageIds.slice(0, MAX_LISTED_IDS),
    removedImageCount: removedImageIds.length,
    backgroundImageRemoved: hasBackgroundImage(before) && !hasBackgroundImage(after),
    revision: after && typeof after === 'object' && !Array.isArray(after) ? after.revision ?? null : null,
  };
}

/**
 * Warn only when a write leaves the slide with fewer images (or drops its background image).
 * Not when an image only got a new id (layout re-save, same count), and not on the explicit
 * "delete this element" request: those are logged at info level with the removed ids.
 */
function shouldWarn(change, route) {
  const fewerImages = change.imagesBefore != null && change.imagesAfter < change.imagesBefore;
  if (!fewerImages && !change.backgroundImageRemoved) return false;
  if (/^DELETE \S*\/elements\/[^/]+$/.test(String(route || '')) && !change.backgroundImageRemoved) return false;
  return true;
}

/**
 * Wrap a slide write. `readBefore` returns the stored slide ({ elements, deckId }) or null;
 * `write` performs the update. Only `write` can throw.
 */
async function withSlideWriteLog(slideId, data, readBefore, write) {
  if (!isEnabled() || !data || data.elements === undefined) return write();

  let before = null;
  try {
    before = await readBefore();
  } catch {
    before = null;
  }

  const updated = await write();

  try {
    const change = describeSlideWrite(before?.elements ?? null, data.elements);
    const entry = {
      event: 'slide_write',
      slideId,
      deckId: updated?.deckId || before?.deckId || null,
      ...currentRequest(),
      ...change,
    };
    if (shouldWarn(change, entry.route)) logger.warn(`slide_write removed images ${JSON.stringify(entry)}`);
    else logger.info(`slide_write ${JSON.stringify(entry)}`);
  } catch {
    // Logging must never affect the save.
  }
  return updated;
}

module.exports = {
  slideWriteContextMiddleware,
  withSlideWriteLog,
  describeSlideWrite,
  shouldWarn,
};
