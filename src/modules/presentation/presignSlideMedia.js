const s3Service = require('../s3/s3.service');

const PRESIGN_TTL_SECONDS =
  Number(process.env.PPT_IMAGE_PRESIGN_TTL_SEC) > 0
    ? Number(process.env.PPT_IMAGE_PRESIGN_TTL_SEC)
    : 3600;

/**
 * Rewrite private S3 object URLs on a slide to time-limited GET URLs.
 * Persisted `url` / `s3Key` stay as-is in DB; this is response-only.
 * @param {object|null|undefined} slide
 * @returns {Promise<object|null|undefined>}
 */
async function attachPresignedMedia(slide) {
  if (!slide || typeof slide !== 'object') return slide;

  const next = { ...slide };
  let signedUrl = null;

  if (next.imageRef && typeof next.imageRef === 'object') {
    const imageRef = { ...next.imageRef };
    if (imageRef.s3Key) {
      try {
        signedUrl = await s3Service.getPresignedGetUrl(imageRef.s3Key, PRESIGN_TTL_SECONDS);
        imageRef.url = signedUrl;
      } catch {
        // keep stored url
      }
    }
    next.imageRef = imageRef;
  }

  if (next.elements && typeof next.elements === 'object' && Array.isArray(next.elements.elements)) {
    const elementsDoc = {
      ...next.elements,
      elements: next.elements.elements.map((el) => {
        if (!el || el.type !== 'image' || !el.content || typeof el.content !== 'object') {
          return el;
        }
        const key = next.imageRef?.s3Key;
        if (!signedUrl && !key) return el;
        return {
          ...el,
          content: {
            ...el.content,
            url: signedUrl || el.content.url || null,
          },
        };
      }),
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
  PRESIGN_TTL_SECONDS,
  attachPresignedMedia,
  attachPresignedMediaToSlides,
  presignPresentationPayload,
};
