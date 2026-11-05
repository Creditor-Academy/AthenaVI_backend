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

/**
 * S3 key for a URL that points at this app's own bucket (public or presigned form);
 * null for any other host, so external images are never rewritten into broken S3 links.
 */
function ownBucketKey(url) {
  const bucket = process.env.AWS_S3_BUCKET;
  if (!bucket || !url || typeof url !== 'string') return null;
  try {
    const u = new URL(url);
    const host = String(u.hostname || '').toLowerCase();
    const b = bucket.toLowerCase();
    if (host.startsWith(`${b}.s3.`) || host === `${b}.s3.amazonaws.com`) {
      return s3Service.extractS3KeyFromUrl(url);
    }
    if (/^s3[.-]/.test(host) || host === 's3.amazonaws.com') {
      const path = decodeURIComponent(u.pathname.replace(/^\//, ''));
      if (path.startsWith(`${bucket}/`)) return path.slice(bucket.length + 1) || null;
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * S3 key for a URL on an S3 host (this app's bucket first, then any S3 URL); null for any
 * other host. An external image (stock photo, any website) must keep its own URL: reading
 * its path as an S3 key gives a key that doesn't exist, so the image breaks in exports.
 */
function s3UrlKey(url) {
  const own = ownBucketKey(url);
  if (own) return own;
  if (!url || typeof url !== 'string') return null;
  try {
    const host = String(new URL(url).hostname || '').toLowerCase();
    const isS3Host =
      host === 's3.amazonaws.com' ||
      /^s3[.-][a-z0-9.-]*amazonaws\.com$/.test(host) ||
      /\.s3[.-]([a-z0-9-]+\.)*amazonaws\.com$/.test(host);
    return isS3Host ? s3Service.extractS3KeyFromUrl(url) : null;
  } catch {
    return null;
  }
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
    const key = s3UrlKey(content[field]);
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

  // Slide background image (Slide design → Background → Add image / "Use as background").
  // Stored in the elements doc; uploads live in the private bucket, so sign it like media.
  if (next.elements && typeof next.elements === 'object' && next.elements.backgroundImage) {
    const bgKey = ownBucketKey(next.elements.backgroundImage);
    const signedBg = bgKey ? await signKey(bgKey, signCache) : null;
    if (signedBg) next.elements = { ...next.elements, backgroundImage: signedBg };
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
        const key = s3UrlKey(imageRef.url);
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
            const ownUrl = content.url || content.src;
            // An external URL stays as it is; the slide's hero image only fills an element
            // that has no picture of its own.
            const elementKey = ownUrl ? s3UrlKey(ownUrl) : heroKey;
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
  ownBucketKey,
  s3UrlKey,
  attachPresignedMedia,
  attachPresignedMediaToSlides,
  presignPresentationPayload,
  isPresignableElement,
  enrichDeckMediaKeysForExport,
  PRESIGN_TTL_SECONDS,
};
