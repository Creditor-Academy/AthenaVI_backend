/**
 * Image crop stored by the editors as `content.crop = { x, y, width, height }` — the visible
 * region of the source image as fractions (0–1). Mirrors frontend src/utils/imageCrop.js.
 * The editor gives a cropped element the crop's aspect ratio, so exports draw the region
 * stretched to the element box.
 */
const MIN_CROP_FRACTION = 0.02;

const clamp01 = (n) => Math.min(1, Math.max(0, n));

function normalizeCrop(crop) {
  if (!crop || typeof crop !== 'object') return null;
  const x = clamp01(Number(crop.x) || 0);
  const y = clamp01(Number(crop.y) || 0);
  let width = Number(crop.width);
  let height = Number(crop.height);
  if (!Number.isFinite(width) || !Number.isFinite(height)) return null;
  width = Math.min(Math.max(MIN_CROP_FRACTION, width), 1 - x);
  height = Math.min(Math.max(MIN_CROP_FRACTION, height), 1 - y);
  if (width <= 0 || height <= 0) return null;
  const full = x < 0.001 && y < 0.001 && width > 0.999 && height > 0.999;
  return full ? null : { x, y, width, height };
}

/** Pixel rectangle for sharp.extract(), kept inside the image. */
function cropPixelRect(crop, imageWidth, imageHeight) {
  const c = normalizeCrop(crop);
  if (!c || !(imageWidth > 0) || !(imageHeight > 0)) return null;
  const left = Math.min(imageWidth - 1, Math.max(0, Math.round(c.x * imageWidth)));
  const top = Math.min(imageHeight - 1, Math.max(0, Math.round(c.y * imageHeight)));
  const width = Math.max(1, Math.min(imageWidth - left, Math.round(c.width * imageWidth)));
  const height = Math.max(1, Math.min(imageHeight - top, Math.round(c.height * imageHeight)));
  return { left, top, width, height };
}

/** Inline CSS for an <img> inside an overflow:hidden box so `crop` fills the box. */
function croppedImageCss(crop) {
  const c = normalizeCrop(crop);
  if (!c) return null;
  const pct = (n) => `${Number(n.toFixed(4))}%`;
  return [
    'position:absolute',
    `left:${pct((-c.x / c.width) * 100)}`,
    `top:${pct((-c.y / c.height) * 100)}`,
    `width:${pct(100 / c.width)}`,
    `height:${pct(100 / c.height)}`,
    'max-width:none',
    'max-height:none',
    'object-fit:fill',
  ].join(';');
}

module.exports = { normalizeCrop, cropPixelRect, croppedImageCss };
