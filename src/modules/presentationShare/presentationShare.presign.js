const { attachPresignedMedia } = require('../presentation/presignSlideMedia');

/**
 * Public preview uses the same per-element signing as the editor so icons,
 * device-frame screens, and gallery images keep working after write-time URLs expire.
 */
async function presignSlideForPublic(slide, cache) {
  return attachPresignedMedia(slide, cache);
}

async function presignSlidesForPublic(slides) {
  if (!Array.isArray(slides) || slides.length === 0) return [];
  const cache = new Map();
  return Promise.all(slides.map((slide) => attachPresignedMedia(slide, cache)));
}

function toMs(value) {
  const ms = value ? new Date(value).getTime() : 0;
  return Number.isFinite(ms) ? ms : 0;
}

/**
 * Slide/canvas edits go through presentationDao.updateSlide and never touch the Deck row, so
 * `deck.updatedAt` alone is not a valid version. Slide count is folded into the tag because
 * deletions also skip the Deck row, which could otherwise revert to a previously served ETag.
 *
 * @param {{ deck: object, slides: object[], share: object }} params
 */
function buildContentVersion({ deck, slides, share }) {
  const slideMs = (slides || []).reduce((max, slide) => Math.max(max, toMs(slide?.updatedAt)), 0);
  const contentVersionMs = Math.max(toMs(deck?.updatedAt), slideMs);
  const shareMs = toMs(share?.updatedAt);

  return {
    contentVersionMs,
    contentUpdatedAt: contentVersionMs ? new Date(contentVersionMs).toISOString() : null,
    etag: `W/"${contentVersionMs}-${(slides || []).length}-${shareMs}"`,
  };
}

module.exports = {
  presignSlideForPublic,
  presignSlidesForPublic,
  buildContentVersion,
};
