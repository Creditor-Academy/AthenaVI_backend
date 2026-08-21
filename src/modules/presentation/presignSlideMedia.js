const s3Service = require('../s3/s3.service');

const PRESIGN_TTL_SECONDS =
  Number(process.env.PPT_IMAGE_PRESIGN_TTL_SEC) > 0
    ? Number(process.env.PPT_IMAGE_PRESIGN_TTL_SEC)
    : 3600;

async function signKey(key) {
  if (!key) return null;
  try {
    return await s3Service.getPresignedGetUrl(key, PRESIGN_TTL_SECONDS);
  } catch {
    return null;
  }
}

/**
 * Rewrite private S3 object URLs on a slide to time-limited GET URLs.
 * Persisted `url` / `s3Key` stay as-is in DB; this is response-only.
 * Prefers per-element `content.s3Key` so gallery slides do not all share hero URL.
 * @param {object|null|undefined} slide
 * @returns {Promise<object|null|undefined>}
 */
async function attachPresignedMedia(slide) {
  if (!slide || typeof slide !== 'object') return slide;

  const next = { ...slide };
  let heroSignedUrl = null;
  const heroKey = next.imageRef?.s3Key || null;

  if (next.imageRef && typeof next.imageRef === 'object') {
    const imageRef = { ...next.imageRef };
    if (imageRef.s3Key) {
      heroSignedUrl = await signKey(imageRef.s3Key);
      if (heroSignedUrl) imageRef.url = heroSignedUrl;
    }
    next.imageRef = imageRef;
  }

  if (next.elements && typeof next.elements === 'object' && Array.isArray(next.elements.elements)) {
    const elementsDoc = {
      ...next.elements,
      elements: await Promise.all(
        next.elements.elements.map(async (el) => {
          if (!el || el.type !== 'image' || !el.content || typeof el.content !== 'object') {
            return el;
          }

          const slotId = String(el.slotId || '').toUpperCase();
          const role = String(el.role || '').toLowerCase();
          const isHeroSlot =
            slotId === 'BACKGROUND_IMAGE' ||
            slotId === 'HERO_IMAGE' ||
            role === 'background' ||
            el.content.useAsBackground;

          const elementKey =
            el.content.s3Key ||
            s3Service.extractS3KeyFromUrl(el.content.url || el.content.src) ||
            null;

          let signed = null;
          if (elementKey) {
            signed = await signKey(elementKey);
          } else if (isHeroSlot && (heroSignedUrl || heroKey)) {
            signed = heroSignedUrl || (await signKey(heroKey));
          }

          if (!signed) return el;

          return {
            ...el,
            content: {
              ...el.content,
              ...(elementKey ? { s3Key: elementKey } : {}),
              url: signed,
            },
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
  return Promise.all(slides.map((s) => attachPresignedMedia(s)));
}

/**
 * Presign any `slide` / `slides` fields on a service payload.
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
  }
  if (Array.isArray(out.slides)) {
    out.slides = await attachPresignedMediaToSlides(out.slides);
  }
  return out;
}

module.exports = {
  attachPresignedMedia,
  attachPresignedMediaToSlides,
  presignPresentationPayload,
  PRESIGN_TTL_SECONDS,
};
