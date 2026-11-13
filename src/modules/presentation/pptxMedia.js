/**
 * Photos embedded natively in a PPTX are kept at the resolution the slide can show, so a deck
 * of AI-generated 2048px PNGs doesn't make a 20 MB file:
 *   - downscaled to ~200 pixels per inch of the size the photo is shown at (a crop or a
 *     "cover" fit shows only part of it, which needs more pixels of the whole);
 *   - an opaque PNG photo is re-encoded as a high-quality JPEG; anything with transparency
 *     stays PNG (logos, cut-outs).
 * The photo stays the whole photo, so crops and masks keep working in PowerPoint.
 */

const sharp = require('sharp');

/** Pixels per inch kept: sharp on screen and print, well above PowerPoint's 150 ppi default. */
const TARGET_PPI = 200;
/** Smaller files aren't worth re-encoding. */
const MIN_BYTES = 300 * 1024;

function decodeDataUrl(data) {
  const m = /^(?:data:)?([\w/+.-]+);base64,(.*)$/s.exec(String(data || ''));
  return m ? { mime: m[1], buffer: Buffer.from(m[2], 'base64') } : null;
}

/**
 * Inches of slide per source pixel for a photo shown in a box.
 * @param {{width:number,height:number}} image  source pixels
 * @param {{w:number,h:number}} box  inches
 * @param {{ fit?: string, crop?: {width:number,height:number}|null }} [opts]
 */
function inchesPerPixel(image, box, { fit = 'cover', crop = null } = {}) {
  const W = Number(image?.width) || 0;
  const H = Number(image?.height) || 0;
  if (!W || !H || !(box?.w > 0) || !(box?.h > 0)) return null;
  if (crop && crop.width > 0 && crop.height > 0) return Math.max(box.w / (crop.width * W), box.h / (crop.height * H));
  if (String(fit).toLowerCase() === 'contain') return Math.min(box.w / W, box.h / H);
  return Math.max(box.w / W, box.h / H);
}

/**
 * A smaller copy of a fetched photo ({ data, width, height }) for a box `box` (inches), or the
 * photo unchanged when it is already small enough or can't be read.
 * @returns {Promise<{ data: string, width: number, height: number, shrunk?: boolean }>}
 */
async function shrinkPhotoForPptx(image, box, opts = {}) {
  const decoded = decodeDataUrl(image?.data);
  if (!decoded || !/^image\/(png|jpe?g)$/i.test(decoded.mime) || decoded.buffer.length < MIN_BYTES) return image;
  const perPx = inchesPerPixel(image, box, opts);
  if (!perPx) return image;
  try {
    const meta = await sharp(decoded.buffer).metadata();
    const scale = Math.min(1, TARGET_PPI * perPx);
    const width = Math.max(1, Math.round((meta.width || image.width) * scale));
    let pipeline = sharp(decoded.buffer).rotate();
    if (scale < 0.98) pipeline = pipeline.resize({ width, withoutEnlargement: true });
    // An alpha channel that is fully opaque doesn't need PNG.
    let opaque = !meta.hasAlpha;
    if (meta.hasAlpha) {
      const stats = await sharp(decoded.buffer).stats();
      opaque = stats.isOpaque === true;
    }
    const out = opaque
      ? await pipeline.flatten({ background: '#ffffff' }).jpeg({ quality: 90, mozjpeg: true }).toBuffer({ resolveWithObject: true })
      : await pipeline.png({ compressionLevel: 9 }).toBuffer({ resolveWithObject: true });
    if (out.data.length >= decoded.buffer.length) return image;
    const mime = opaque ? 'image/jpeg' : 'image/png';
    return { data: `${mime};base64,${out.data.toString('base64')}`, width: out.info.width, height: out.info.height, shrunk: true };
  } catch {
    return image;
  }
}

module.exports = { shrinkPhotoForPptx, inchesPerPixel, TARGET_PPI };
