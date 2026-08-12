const path = require('path');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const {
  isDocument,
  isImage,
  extractTextFromContextFile,
  resolveMimeAndExt,
} = require('../../shared/utils/contextDocumentParse');
const { summarizeReferenceImage } = require('../../shared/services/ai/vision.service');

const EXCERPT_LEN = 500;

function classifyRole(fileLike) {
  if (isImage(fileLike)) return 'reference_image';
  if (isDocument(fileLike)) return 'document';
  throw new AppError(messages.IMAGE_GEN_CONTEXT_UNSUPPORTED_TYPE, 400);
}

function mimeForFile(fileLike) {
  const { mime, ext } = resolveMimeAndExt(fileLike);
  if (mime) return mime;
  const map = {
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.pdf': 'application/pdf',
    '.docx':
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.doc': 'application/msword',
    '.md': 'text/markdown',
    '.markdown': 'text/markdown',
    '.txt': 'text/plain',
  };
  return map[ext] || 'application/octet-stream';
}

function excerpt(text, max = EXCERPT_LEN) {
  const raw = String(text || '').trim();
  if (raw.length <= max) return raw;
  return `${raw.slice(0, max - 1)}…`;
}

/**
 * Parse a document buffer into extracted text.
 */
async function parseDocumentFile(fileLike) {
  const result = await extractTextFromContextFile(fileLike);
  return {
    role: 'document',
    extractedText: result.text,
    truncated: result.truncated,
    format: result.format,
    excerpt: excerpt(result.text),
  };
}

/**
 * Summarize a reference image buffer.
 */
async function parseReferenceImage(fileLike, hint = '') {
  const mime = mimeForFile(fileLike);
  const { summary } = await summarizeReferenceImage({
    buffer: fileLike.buffer,
    mimeType: mime,
    hint,
  });
  return {
    role: 'reference_image',
    imageSummary: summary,
    summary,
  };
}

/**
 * Classify and parse one upload/asset file-like object.
 * @param {{ buffer: Buffer, originalname?: string, name?: string, mimetype?: string, mimeType?: string }} fileLike
 * @param {{ hint?: string }} opts
 */
async function parseContextFile(fileLike, { hint = '' } = {}) {
  const role = classifyRole(fileLike);
  const name = fileLike.originalname || fileLike.name || 'file';
  const mimeType = mimeForFile(fileLike);

  if (role === 'document') {
    const parsed = await parseDocumentFile(fileLike);
    return {
      name: path.basename(name),
      mimeType,
      role,
      extractedText: parsed.extractedText,
      imageSummary: null,
      truncated: parsed.truncated,
      excerpt: parsed.excerpt,
    };
  }

  const parsed = await parseReferenceImage(fileLike, hint);
  return {
    name: path.basename(name),
    mimeType,
    role,
    extractedText: null,
    imageSummary: parsed.imageSummary,
    truncated: false,
    excerpt: null,
  };
}

module.exports = {
  classifyRole,
  mimeForFile,
  parseContextFile,
  excerpt,
};
