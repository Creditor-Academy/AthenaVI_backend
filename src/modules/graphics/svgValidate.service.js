const AppError = require('../../shared/utils/AppError');

const MAX_SVG_BYTES = Math.round(1.5 * 1024 * 1024);
const SVG_MIME = new Set(['image/svg+xml', 'image/svg', 'text/xml', 'application/xml']);

const DANGEROUS_TAG = /<\s*(script|foreignObject|iframe|embed|object|html|body)\b/i;
const EVENT_HANDLER = /\son[a-z]+\s*=/i;
const JS_PROTOCOL = /javascript\s*:/i;
const EXTERNAL_HREF =
  /(?:xlink:)?href\s*=\s*["']\s*(https?:|\/\/)/i;

function asUtf8(buffer) {
  if (Buffer.isBuffer(buffer)) return buffer.toString('utf8');
  return String(buffer || '');
}

function looksLikeSvgMime(mime) {
  const raw = String(mime || '').split(';')[0].trim().toLowerCase();
  return SVG_MIME.has(raw) || raw === '';
}

function extractAttr(svg, name) {
  const re = new RegExp(`\\b${name}\\s*=\\s*["']([^"']+)["']`, 'i');
  const m = svg.match(re);
  return m ? m[1].trim() : '';
}

/**
 * Validate SVG bytes. Throws AppError on failure.
 * @returns {{ viewBox: string|null, width: string|null, height: string|null, bytes: number }}
 */
function validateSvgBuffer(buffer, { mimeType } = {}) {
  if (!buffer || !Buffer.isBuffer(buffer) && typeof buffer !== 'string') {
    throw new AppError('SVG file is required', 400);
  }
  const bytes = Buffer.isBuffer(buffer) ? buffer.length : Buffer.byteLength(buffer);
  if (bytes <= 0) throw new AppError('SVG file is empty', 400);
  if (bytes > MAX_SVG_BYTES) {
    throw new AppError('SVG must be 1.5MB or smaller', 400);
  }
  if (mimeType && !looksLikeSvgMime(mimeType)) {
    throw new AppError('File must be image/svg+xml', 400);
  }

  const text = asUtf8(buffer).replace(/^\uFEFF/, '').trim();
  if (!text) throw new AppError('SVG file is empty', 400);
  if (!/<svg[\s\S]*<\/svg>/i.test(text)) {
    throw new AppError('File is not a valid SVG document', 400);
  }
  if (DANGEROUS_TAG.test(text)) {
    throw new AppError('SVG contains unsupported or unsafe tags', 400);
  }
  if (EVENT_HANDLER.test(text) || JS_PROTOCOL.test(text)) {
    throw new AppError('SVG contains JavaScript or event handlers', 400);
  }
  if (EXTERNAL_HREF.test(text)) {
    throw new AppError('SVG contains unsafe external resources', 400);
  }

  const open = (text.match(/<svg\b/gi) || []).length;
  const close = (text.match(/<\/svg>/gi) || []).length;
  if (open < 1 || open !== close) {
    throw new AppError('Invalid SVG structure', 400);
  }

  const viewBox = extractAttr(text, 'viewBox') || null;
  const width = extractAttr(text, 'width') || null;
  const height = extractAttr(text, 'height') || null;
  if (!viewBox && (!width || !height)) {
    throw new AppError('SVG must include a viewBox or width and height', 400);
  }

  return { viewBox, width, height, bytes };
}

module.exports = {
  MAX_SVG_BYTES,
  validateSvgBuffer,
};
