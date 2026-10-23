const s3Service = require('../s3/s3.service');

const PRESIGN_TTL_SECONDS =
  Number(process.env.PPT_IMAGE_PRESIGN_TTL_SEC) > 0
    ? Number(process.env.PPT_IMAGE_PRESIGN_TTL_SEC)
    : 3600;

const SIGNABLE_URL_FIELDS = ['url', 'src', 'screenUrl', 'thumbnailUrl', 'previewUrl'];

function isHeroMediaSlot(el) {
  const slotId = String(el?.slotId || '').toUpperCase();
  const role = String(el?.role || '').toLowerCase();
  return (
    slotId === 'BACKGROUND_IMAGE' ||
    slotId === 'HERO_IMAGE' ||
    role === 'background' ||
    Boolean(el?.content?.useAsBackground)
  );
}

function isPresignableElement(el) {
  if (!el || typeof el !== 'object' || !el.content || typeof el.content !== 'object') {
    return false;
  }
  const type = String(el.type || '').toLowerCase();
  if (type === 'image' || type === 'icon') return true;
  if (type !== 'shape') return false;
  return Boolean(
    el.content.s3Key ||
      el.content.deviceFrame ||
      el.content.shape === 'device-frame' ||
      SIGNABLE_URL_FIELDS.some((field) => el.content[field])
  );
}

function resolveElementMediaKey(content = {}) {
  if (content.s3Key) return content.s3Key;
  for (const field of SIGNABLE_URL_FIELDS) {
    const key = s3Service.extractS3KeyFromUrl(content[field]);
    if (key) return key;
  }
  return null;
}

function applySignedMedia(content, signed, elementKey) {
  const next = { ...content, url: signed };
  if (elementKey) next.s3Key = elementKey;
  for (const field of SIGNABLE_URL_FIELDS) {
    if (field !== 'url' && content[field]) next[field] = signed;
  }
  return next;
}

async function signKey(key, cache) {
  if (!key) return null;
  if (cache?.has(key)) return cache.get(key);
  const pending = s3Service
    .getPresignedGetUrl(key, PRESIGN_TTL_SECONDS)
    .catch(() => null);
  cache?.set(key, pending);
  return pending;
}

/**
 * Rewrite private S3 object URLs on a slide to time-limited GET URLs.
 * Persisted `url` / `s3Key` stay as-is in DB; this is response-only.
 * Prefers per-element `content.s3Key` so gallery slides do not all share hero URL.
 * @param {object|null|undefined} slide
 * @param {Map<string, string|null>} [cache]
 * @returns {Promise<object|null|undefined>}
 */
async function attachPresignedMedia(slide, cache) {
  if (!slide || typeof slide !== 'object') return slide;

  const signCache = cache || new Map();
  const next = { ...slide };
  let heroSignedUrl = null;
  const heroKey = next.imageRef?.s3Key || null;

  if (next.imageRef && typeof next.imageRef === 'object') {
    const imageRef = { ...next.imageRef };
    if (imageRef.s3Key) {
      heroSignedUrl = await signKey(imageRef.s3Key, signCache);
      if (heroSignedUrl) imageRef.url = heroSignedUrl;
    }
    next.imageRef = imageRef;
  }

  if (next.elements && typeof next.elements === 'object' && Array.isArray(next.elements.elements)) {
    const elementsDoc = {
      ...next.elements,
      elements: await Promise.all(
        next.elements.elements.map(async (el) => {
          if (!isPresignableElement(el)) return el;

          const elementKey = resolveElementMediaKey(el.content);
          let signed = null;
          if (elementKey) {
            signed = await signKey(elementKey, signCache);
          } else if (isHeroMediaSlot(el) && (heroSignedUrl || heroKey)) {
            signed = heroSignedUrl || (await signKey(heroKey, signCache));
          }

          if (!signed) return el;

          return {
            ...el,
            content: applySignedMedia(el.content, signed, elementKey),
          };
        })
      ),
    };
    next.elements = elementsDoc;
  }

  return next;
}

/**
 * @param {object[]} slides
 * @returns {Promise<object[]>}
 */
async function attachPresignedMediaToSlides(slides) {
  if (!Array.isArray(slides) || slides.length === 0) return slides || [];
  const cache = new Map();
  return Promise.all(slides.map((s) => attachPresignedMedia(s, cache)));
}

/**
 * Presign any `slide` / `slides` fields on a service payload, and hydrate their
 * assignee/assignedBy user summaries. This is the one choke point every slide-
 * returning service method flows through, so assignee never appears to reset
 * to unassigned after an unrelated edit (content patch, reorder, add element, …).
 * @param {object} data
 */
async function presignPresentationPayload(data) {
  if (!data || typeof data !== 'object') return data;
  const out = { ...data };
  if (out.slide) {
    out.slide = await attachPresignedMedia(out.slide);
    if (out.element && out.slide?.elements?.elements) {
      const match = out.slide.elements.elements.find((e) => e.id === out.element.id);
      if (match) out.element = match;
    }
    const { attachSlideAssignees } = require('./slideAssignment');
    [out.slide] = await attachSlideAssignees([out.slide]);
  }
  if (Array.isArray(out.slides)) {
    out.slides = await attachPresignedMediaToSlides(out.slides);
    const { attachSlideAssignees } = require('./slideAssignment');
    out.slides = await attachSlideAssignees(out.slides);
  }
  return out;
}

/**
 * Ensure image elements and imageRef carry stable S3 keys before export (avoids hung
 * fetches on expired presigned URLs stored in JSON).
 * @param {object} deck
 * @returns {object}
 */
function enrichDeckMediaKeysForExport(deck) {
  if (!deck || typeof deck !== 'object') return deck;
  const slides = (deck.slides || []).map((slide) => {
    if (!slide || typeof slide !== 'object') return slide;
    const next = { ...slide };

    if (next.imageRef && typeof next.imageRef === 'object') {
      const imageRef = { ...next.imageRef };
      if (!imageRef.s3Key) {
        const key = s3Service.extractS3KeyFromUrl(imageRef.url);
        if (key) imageRef.s3Key = key;
      }
      next.imageRef = imageRef;
    }

    if (next.elements && typeof next.elements === 'object' && Array.isArray(next.elements.elements)) {
      const heroKey = next.imageRef?.s3Key || null;
      next.elements = {
        ...next.elements,
        elements: next.elements.elements.map((el) => {
          if (!el || el.type !== 'image' || !el.content || typeof el.content !== 'object') {
            return el;
          }
          const content = { ...el.content };
          if (!content.s3Key) {
            const elementKey =
              s3Service.extractS3KeyFromUrl(content.url || content.src) || heroKey || null;
            if (elementKey) content.s3Key = elementKey;
          }
          return { ...el, content };
        }),
      };
    }

    return next;
  });

  return { ...deck, slides };
}

module.exports = {
  attachPresignedMedia,
  attachPresignedMediaToSlides,
  presignPresentationPayload,
  isPresignableElement,
  enrichDeckMediaKeysForExport,
  PRESIGN_TTL_SECONDS,
};
