const path = require('path');
const mammoth = require('mammoth');
const { PDFParse } = require('pdf-parse');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const MAX_EXTRACT_CHARS = Number(process.env.PPT_DOCUMENT_MAX_CHARS) > 0
  ? Number(process.env.PPT_DOCUMENT_MAX_CHARS)
  : 100_000;

function resolveMimeAndExt(file) {
  const originalName = file?.originalname || file?.name || '';
  const ext = path.extname(originalName).toLowerCase();
  const mime = String(file?.mimetype || '').toLowerCase();
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

function truncateText(text) {
  const raw = String(text || '').replace(/\u0000/g, '').trim();
  if (raw.length <= MAX_EXTRACT_CHARS) return raw;
  return raw.slice(0, MAX_EXTRACT_CHARS);
}

async function extractPdfText(buffer) {
  const parser = new PDFParse({ data: buffer });
  try {
    const result = await parser.getText();
    return truncateText(result?.text || '');
  } finally {
    try {
      await parser.destroy();
    } catch {
      // ignore destroy errors
    }
  }
}

async function extractDocxText(buffer) {
  const result = await mammoth.extractRawText({ buffer });
  return truncateText(result?.value || '');
}

/**
 * Extract plain text from an uploaded PDF or DOCX (multer file).
 * @param {{ buffer: Buffer, mimetype?: string, originalname?: string }} file
 * @returns {Promise<{ text: string, format: 'pdf'|'docx', truncated: boolean }>}
 */
async function extractTextFromUpload(file) {
  if (!file || !Buffer.isBuffer(file.buffer) || file.buffer.length === 0) {
    throw new AppError(messages.PRESENTATION_DOCUMENT_UNPARSEABLE, 400);
  }

  try {
    let text = '';
    let format;

    if (isPdf(file)) {
      format = 'pdf';
      text = await extractPdfText(file.buffer);
    } else if (isDocx(file)) {
      format = 'docx';
      text = await extractDocxText(file.buffer);
    } else {
      throw new AppError(messages.PRESENTATION_DOCUMENT_UNPARSEABLE, 400);
    }

    if (!text || !String(text).trim()) {
      throw new AppError(messages.PRESENTATION_DOCUMENT_UNPARSEABLE, 400);
    }

    const fullLength = String(text).length;
    return {
      text,
      format,
      truncated: fullLength >= MAX_EXTRACT_CHARS,
    };
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(messages.PRESENTATION_DOCUMENT_UNPARSEABLE, 400);
  }
}

module.exports = {
  extractTextFromUpload,
  MAX_EXTRACT_CHARS,
};
