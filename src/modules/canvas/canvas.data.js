/**
 * Pure helpers for the CANVAS document stored on Project.data.
 * No database access, so they can be unit tested directly.
 */

const CANVAS_TYPE = 'CANVAS';

/** Max depth walked when scrubbing element content; content is shallow in practice. */
const MAX_SCRUB_DEPTH = 8;

function isLocalObjectUrl(value) {
  return typeof value === 'string' && value.trim().toLowerCase().startsWith('blob:');
}

/**
 * Replace `blob:` URLs with null. They only exist in the browser tab that created them,
 * so storing one guarantees a broken image on reopen. Older clients may still send them;
 * scrubbing (rather than rejecting) keeps the rest of their save.
 */
function scrubLocalUrls(value, depth = 0) {
  if (isLocalObjectUrl(value)) return { value: null, count: 1 };
  if (depth >= MAX_SCRUB_DEPTH || !value || typeof value !== 'object') {
    return { value, count: 0 };
  }

  let count = 0;
  if (Array.isArray(value)) {
    const next = value.map((item) => {
      const result = scrubLocalUrls(item, depth + 1);
      count += result.count;
      return result.value;
    });
    return { value: count ? next : value, count };
  }

  const next = {};
  for (const [key, item] of Object.entries(value)) {
    const result = scrubLocalUrls(item, depth + 1);
    count += result.count;
    next[key] = result.value;
  }
  return { value: count ? next : value, count };
}

/** Revision of a stored document. Documents saved before revisions existed count as 0. */
function readRevision(data) {
  const revision = Number(data?.revision);
  return Number.isInteger(revision) && revision >= 0 ? revision : 0;
}

/** True when the client edited an older revision than the one stored. */
function isRevisionConflict(baseRevision, storedRevision) {
  if (baseRevision === undefined || baseRevision === null) return false;
  return Number(baseRevision) !== storedRevision;
}

function buildDefaultCanvasData(size) {
  const width = Number(size?.width) > 0 ? Number(size.width) : 1080;
  const height = Number(size?.height) > 0 ? Number(size.height) : 1080;

  return {
    version: 1,
    docTitle: null,
    size: { width, height },
    canvases: [
      {
        id: `canvas-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        width,
        height,
        background: '#FFFFFF',
        elements: [],
      },
    ],
  };
}

/**
 * Normalise an incoming document for storage. `revision` is always set by the server,
 * never trusted from the client.
 */
function normalizeCanvasData(data, { fallbackSize, revision = 0 } = {}) {
  if (!data || !Array.isArray(data.canvases) || data.canvases.length === 0) {
    return { ...buildDefaultCanvasData(fallbackSize || data?.size), revision };
  }

  const { value: canvases } = scrubLocalUrls(data.canvases);

  return {
    version: data.version || 1,
    docTitle: data.docTitle ?? null,
    size: data.size || {
      width: data.canvases[0].width,
      height: data.canvases[0].height,
    },
    canvases,
    revision,
  };
}

module.exports = {
  CANVAS_TYPE,
  isLocalObjectUrl,
  scrubLocalUrls,
  readRevision,
  isRevisionConflict,
  buildDefaultCanvasData,
  normalizeCanvasData,
};
