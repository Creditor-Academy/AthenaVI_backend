const sharp = require('sharp');

const CONTAIN_BACKGROUND = { r: 250, g: 250, b: 252, alpha: 1 };

/**
 * Fit buffer to exact format dimensions; always output PNG.
 * Default `cover` is for social full-bleed. Infographics should pass
 * `fit: 'contain'` so step rows are not clipped at the edges.
 *
 * @param {Buffer} buffer
 * @param {{ width: number, height: number } | null} format
 * @param {{ fit?: 'cover'|'contain' }} [options]
 * @returns {Promise<{ buffer: Buffer, width: number, height: number, fit: string }>}
 */
async function cropToFormat(buffer, format, options = {}) {
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
  const fit = options.fit === 'contain' ? 'contain' : 'cover';

  const meta = await sharp(buffer).metadata();
  if (meta.width === targetW && meta.height === targetH) {
    const out = await sharp(buffer).png().toBuffer();
    return {
      buffer: out,
      width: targetW,
      height: targetH,
      fit: 'none',
    };
  }

  const resize =
    fit === 'contain'
      ? {
          fit: 'contain',
          position: 'centre',
          background: CONTAIN_BACKGROUND,
        }
      : {
          fit: 'cover',
          position: 'centre',
        };

  const out = await sharp(buffer).resize(targetW, targetH, resize).png().toBuffer();

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
};
