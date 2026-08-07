const sharp = require('sharp');

/** Prefer contain (no text chop) when source vs target aspect differs by more than this. */
const ASPECT_DELTA_CONTAIN = 0.06;

/**
 * Sample a flat background color from image border pixels (for letterbox padding).
 * @param {Buffer} buffer
 * @returns {Promise<{ r: number, g: number, b: number, alpha: number }>}
 */
async function sampleEdgeBackground(buffer) {
  try {
    const { data, info } = await sharp(buffer)
      .resize(32, 32, { fit: 'fill' })
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });

    const w = info.width;
    const h = info.height;
    let r = 0;
    let g = 0;
    let b = 0;
    let n = 0;

    const push = (x, y) => {
      const i = (y * w + x) * 4;
      r += data[i];
      g += data[i + 1];
      b += data[i + 2];
      n += 1;
    };

    for (let x = 0; x < w; x += 1) {
      push(x, 0);
      push(x, h - 1);
    }
    for (let y = 1; y < h - 1; y += 1) {
      push(0, y);
      push(w - 1, y);
    }

    return {
      r: Math.round(r / n),
      g: Math.round(g / n),
      b: Math.round(b / n),
      alpha: 1,
    };
  } catch {
    return { r: 255, g: 255, b: 255, alpha: 1 };
  }
}

/**
 * Fit buffer to exact format dimensions; always output PNG.
 * Uses cover when aspects are close; contain + edge-color pad when they differ
 * so headline/body text is not center-cropped away (esp. banners / covers).
 *
 * @param {Buffer} buffer
 * @param {{ width: number, height: number } | null} format
 * @returns {Promise<{ buffer: Buffer, width: number, height: number, fit: string }>}
 */
async function cropToFormat(buffer, format) {
  if (!format || !format.width || !format.height) {
    const meta = await sharp(buffer).metadata();
    const out = await sharp(buffer).png().toBuffer();
    return {
      buffer: out,
      width: meta.width || 1024,
      height: meta.height || 1024,
      fit: 'none',
    };
  }

  const targetW = format.width;
  const targetH = format.height;
  const meta = await sharp(buffer).metadata();
  const srcW = meta.width || targetW;
  const srcH = meta.height || targetH;
  const srcAspect = srcW / Math.max(1, srcH);
  const tgtAspect = targetW / Math.max(1, targetH);
  const aspectDelta = Math.abs(srcAspect - tgtAspect) / tgtAspect;

  let fit = 'cover';
  let pipeline = sharp(buffer);

  if (aspectDelta > ASPECT_DELTA_CONTAIN) {
    fit = 'contain';
    const background = await sampleEdgeBackground(buffer);
    pipeline = pipeline.resize(targetW, targetH, {
      fit: 'contain',
      position: 'centre',
      background,
    });
  } else {
    pipeline = pipeline.resize(targetW, targetH, {
      fit: 'cover',
      position: 'centre',
    });
  }

  const out = await pipeline.png().toBuffer();
  return {
    buffer: out,
    width: targetW,
    height: targetH,
    fit,
  };
}

/**
 * Convert PNG buffer to JPEG.
 * @param {Buffer} buffer
 * @param {number} [quality=90]
 */
async function toJpeg(buffer, quality = 90) {
  return sharp(buffer).jpeg({ quality, mozjpeg: true }).toBuffer();
}

module.exports = {
  cropToFormat,
  toJpeg,
  sampleEdgeBackground,
  ASPECT_DELTA_CONTAIN,
};
