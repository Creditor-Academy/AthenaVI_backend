const path = require('path');
const AppError = require('./AppError');
const messages = require('./messages');
const presentationDocumentParse = require('../../modules/presentation/documentParse.service');

const MAX_EXTRACT_CHARS =
  Number(process.env.IMAGE_GEN_CONTEXT_MAX_CHARS) > 0
    ? Number(process.env.IMAGE_GEN_CONTEXT_MAX_CHARS)
    : Number(process.env.PPT_DOCUMENT_MAX_CHARS) > 0
      ? Number(process.env.PPT_DOCUMENT_MAX_CHARS)
      : 100_000;

function resolveMimeAndExt(file) {
  const originalName = file?.originalname || file?.name || '';
  const ext = path.extname(originalName).toLowerCase();
  const mime = String(file?.mimetype || file?.mimeType || '').toLowerCase();
  return { ext, mime, originalName };
}

function isPdf(file) {
  const { ext, mime } = resolveMimeAndExt(file);
  return ext === '.pdf' || mime === 'application/pdf';
}

function isDocx(file) {
  const { ext, mime } = resolveMimeAndExt(file);
  return (
    ext === '.docx' ||
    mime ===
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
    mime === 'application/msword'
  );
}

function isMarkdown(file) {
  const { ext, mime } = resolveMimeAndExt(file);
  return (
    ext === '.md' ||
    ext === '.markdown' ||
    mime === 'text/markdown' ||
    mime === 'text/x-markdown'
  );
}

function isPlainText(file) {
  const { ext, mime } = resolveMimeAndExt(file);
  return ext === '.txt' || mime === 'text/plain';
}

function isDocument(file) {
  return isPdf(file) || isDocx(file) || isMarkdown(file) || isPlainText(file);
}

function isImage(file) {
  const { ext, mime } = resolveMimeAndExt(file);
  if (mime.startsWith('image/')) {
    return (
      mime === 'image/png' ||
      mime === 'image/jpeg' ||
      mime === 'image/jpg' ||
      mime === 'image/webp'
    );
  }
  return ['.png', '.jpg', '.jpeg', '.webp'].includes(ext);
}

function truncateText(text, maxChars = MAX_EXTRACT_CHARS) {
  const raw = String(text || '').replace(/\u0000/g, '').trim();
  if (raw.length <= maxChars) {
    return { text: raw, truncated: false };
  }
  return { text: raw.slice(0, maxChars), truncated: true };
}

function extractUtf8Text(buffer, maxChars = MAX_EXTRACT_CHARS) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_UNPARSEABLE, 400);
  }
  return truncateText(buffer.toString('utf8'), maxChars);
}

/**
 * Extract plain text from PDF, DOCX, MD, or TXT.
 * @param {{ buffer: Buffer, mimetype?: string, mimeType?: string, originalname?: string, name?: string }} file
 * @returns {Promise<{ text: string, format: string, truncated: boolean }>}
 */
async function extractTextFromContextFile(file) {
  if (!file || !Buffer.isBuffer(file.buffer) || file.buffer.length === 0) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_UNPARSEABLE, 400);
  }

  try {
    if (isPdf(file) || isDocx(file)) {
      const result = await presentationDocumentParse.extractTextFromUpload({
        buffer: file.buffer,
        mimetype: file.mimetype || file.mimeType,
        originalname: file.originalname || file.name,
      });
      const capped = truncateText(result.text, MAX_EXTRACT_CHARS);
      return {
        text: capped.text,
        format: result.format,
        truncated: Boolean(result.truncated || capped.truncated),
      };
    }

    if (isMarkdown(file)) {
      const capped = extractUtf8Text(file.buffer);
      if (!capped.text) {
        throw new AppError(messages.IMAGE_GEN_CONTEXT_UNPARSEABLE, 400);
      }
      return { text: capped.text, format: 'md', truncated: capped.truncated };
    }

    if (isPlainText(file)) {
      const capped = extractUtf8Text(file.buffer);
      if (!capped.text) {
        throw new AppError(messages.IMAGE_GEN_CONTEXT_UNPARSEABLE, 400);
      }
      return { text: capped.text, format: 'txt', truncated: capped.truncated };
    }

    throw new AppError(messages.IMAGE_GEN_CONTEXT_UNSUPPORTED_TYPE, 400);
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(messages.IMAGE_GEN_CONTEXT_UNPARSEABLE, 400);
  }
}

module.exports = {
  MAX_EXTRACT_CHARS,
  isPdf,
  isDocx,
  isMarkdown,
  isPlainText,
  isDocument,
  isImage,
  truncateText,
  extractTextFromContextFile,
  resolveMimeAndExt,
};
