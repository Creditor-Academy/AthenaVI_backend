const sharp = require('sharp');

/**
 * Cover-crop / resize buffer to exact format dimensions; always output PNG.
 * @param {Buffer} buffer
 * @param {{ width: number, height: number } | null} format
 * @returns {Promise<{ buffer: Buffer, width: number, height: number }>}
 */
async function cropToFormat(buffer, format) {
  if (!format || !format.width || !format.height) {
    const meta = await sharp(buffer).metadata();
    const out = await sharp(buffer).png().toBuffer();
    return {
      buffer: out,
      width: meta.width || 1024,
      height: meta.height || 1024,
    };
  }

  const out = await sharp(buffer)
    .resize(format.width, format.height, {
      fit: 'cover',
      position: 'centre',
    })
    .png()
    .toBuffer();

  return {
    buffer: out,
    width: format.width,
    height: format.height,
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
