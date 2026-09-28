const sharp = require('sharp');
const { bleedCanvasFor } = require('./catalogs/formats');

const CONTAIN_BACKGROUND = { r: 250, g: 250, b: 252, alpha: 1 };

/**
 * Fit buffer to exact format dimensions; always output PNG.
 * Default `cover` fills the canvas (generic square/landscape/portrait).
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
 * Centre the image on a canvas of the given width/height ratio, filling the margin
 * with a blurred stretch of itself. A later centred `cover` crop back to the source
 * ratio recovers exactly the original area.
 *
 * @param {Buffer} buffer
 * @param {number|null} aspect
 * @returns {Promise<Buffer>}
 */
async function padToAspect(buffer, aspect) {
  const meta = await sharp(buffer).metadata();
  const width = meta.width;
  const height = meta.height;
  if (!aspect || !width || !height) return buffer;

  const source = width / height;
  if (Math.abs(source - aspect) / aspect <= 0.01) return buffer;

  const canvasW = source > aspect ? width : Math.round(height * aspect);
  const canvasH = source > aspect ? Math.round(width / aspect) : height;

  const background = await sharp(buffer)
    .resize(canvasW, canvasH, { fit: 'cover', position: 'centre' })
    .blur(40)
    .toBuffer();

  return sharp(background)
    .composite([
      {
        input: buffer,
        left: Math.round((canvasW - width) / 2),
        top: Math.round((canvasH - height) / 2),
      },
    ])
    .png()
    .toBuffer();
}

/**
 * Cover-crop to the bleed canvas of a print format, then cut the trim box out of it.
 * Both PNGs carry the format DPI.
 *
 * @param {Buffer} buffer
 * @param {object} format print format (width/height are trim px)
 * @returns {Promise<{ trim: { buffer: Buffer, width: number, height: number, fit: string },
 *   bleed: { buffer: Buffer, width: number, height: number } }>}
 */
async function cropToPrint(buffer, format) {
  const canvas = bleedCanvasFor(format);
  const density = canvas.dpi;
  const bleedRaw = await sharp(buffer)
    .resize(canvas.width, canvas.height, { fit: 'cover', position: 'centre' })
    .png()
    .toBuffer();
  const bleedBuffer = await sharp(bleedRaw).withMetadata({ density }).png().toBuffer();
  const trimBuffer = await sharp(bleedRaw)
    .extract({
      left: canvas.offsetX,
      top: canvas.offsetY,
      width: format.width,
      height: format.height,
    })
    .withMetadata({ density })
    .png()
    .toBuffer();

  return {
    trim: { buffer: trimBuffer, width: format.width, height: format.height, fit: 'cover' },
    bleed: { buffer: bleedBuffer, width: canvas.width, height: canvas.height },
  };
}

/**
 * Convert PNG buffer to JPEG.
 * @param {Buffer} buffer
 * @param {number} [quality=90]
 * @param {{ density?: number }} [options] DPI to stamp (print formats)
 */
async function toJpeg(buffer, quality = 90, options = {}) {
  let pipeline = sharp(buffer).flatten({ background: '#ffffff' });
  if (options.density) pipeline = pipeline.withMetadata({ density: options.density });
  return pipeline.jpeg({ quality, mozjpeg: true }).toBuffer();
}

module.exports = {
  cropToFormat,
  cropToPrint,
  padToAspect,
  toJpeg,
};
