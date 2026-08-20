const s3Service = require('../s3/s3.service');
const { PRESIGN_TTL_SECONDS } = require('../presentation/presignSlideMedia');

/**
 * Public preview presign.
 *
 * The editor pass (presignSlideMedia) only signs `slide.imageRef.s3Key` and copies that single
 * URL onto every image element. Uploads / attached assets / stock store a per-element
 * `content.s3Key` (see slideMedia.applyImageToElements), so multi-image slides can carry
 * write-time URLs that expire. An editor user recovers by re-saving; a link guest cannot.
 */
async function signKey(key, cache) {
  if (!key) return null;
  if (cache.has(key)) return cache.get(key);

  let url = null;
  try {
    url = await s3Service.getPresignedGetUrl(key, PRESIGN_TTL_SECONDS);
  } catch {
    url = null;
  }
  cache.set(key, url);
  return url;
}

async function presignSlideForPublic(slide, cache) {
  if (!slide || typeof slide !== 'object') return slide;

  const next = { ...slide };
  let fallbackUrl = null;

  if (next.imageRef && typeof next.imageRef === 'object') {
    const imageRef = { ...next.imageRef };
    if (imageRef.s3Key) {
      const signed = await signKey(imageRef.s3Key, cache);
      if (signed) {
        imageRef.url = signed;
        fallbackUrl = signed;
      }
    }
    next.imageRef = imageRef;
  }

  const doc = next.elements;
  if (doc && typeof doc === 'object' && Array.isArray(doc.elements)) {
    const elements = await Promise.all(
      doc.elements.map(async (el) => {
        if (!el || el.type !== 'image' || !el.content || typeof el.content !== 'object') {
          return el;
        }

        const ownKey = el.content.s3Key;
        const signed = ownKey ? await signKey(ownKey, cache) : null;
        const url = signed || fallbackUrl || el.content.url || null;
        if (!url) return el;

        return {
          ...el,
          content: { ...el.content, url, ...(el.content.src != null ? { src: url } : {}) },
        };
      })
    );

    next.elements = { ...doc, elements };
  }

  return next;
}

async function presignSlidesForPublic(slides) {
  if (!Array.isArray(slides) || slides.length === 0) return [];
  const cache = new Map();
  return Promise.all(slides.map((slide) => presignSlideForPublic(slide, cache)));
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
