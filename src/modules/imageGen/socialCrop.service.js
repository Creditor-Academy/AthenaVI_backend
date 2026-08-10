const sharp = require('sharp');

/**
 * Fit buffer to exact format dimensions (full-bleed); always output PNG.
 * Always uses cover + center so social banners/covers fill edge-to-edge
 * (no letterbox / solid side panels). Composition must be prompted for the
 * final aspect so text survives the crop.
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
  const out = await sharp(buffer)
    .resize(targetW, targetH, {
      fit: 'cover',
      position: 'centre',
    })
    .png()
    .toBuffer();

  return {
    buffer: out,
    width: targetW,
    height: targetH,
    fit: 'cover',
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
