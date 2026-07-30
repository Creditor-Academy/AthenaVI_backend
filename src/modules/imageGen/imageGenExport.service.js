const { PDFDocument } = require('pdf-lib');
const AppError = require('../../shared/utils/AppError');
const { getObjectBuffer, streamObjectToResponse } = require('../s3/s3.service');
const { toJpeg } = require('./socialCrop.service');

const DOWNLOAD_FORMATS = Object.freeze(['png', 'jpg', 'jpeg', 'pdf']);

function normalizeDownloadFormat(format) {
  const f = String(format || 'png').toLowerCase().trim();
  if (!DOWNLOAD_FORMATS.includes(f)) {
    throw new AppError('Invalid download format. Use png, jpg, jpeg, or pdf.', 400);
  }
  return f;
}

function sanitizeFilename(name, ext) {
  const base = String(name || 'image')
    .replace(/\.[^.]+$/, '')
    .replace(/[^\w.\-]+/g, '_')
    .slice(0, 120);
  return `${base || 'image'}.${ext}`;
}

/**
 * Build download payload (buffer + headers) for a generation's master PNG.
 */
async function buildDownloadPayload({ s3Key, format, filenameBase }) {
  const fmt = normalizeDownloadFormat(format);
  const pngBuffer = await getObjectBuffer(s3Key);

  if (fmt === 'png') {
    return {
      buffer: pngBuffer,
      contentType: 'image/png',
      filename: sanitizeFilename(filenameBase, 'png'),
      streamFromS3: true,
    };
  }

  if (fmt === 'jpg' || fmt === 'jpeg') {
    const jpeg = await toJpeg(pngBuffer, 90);
    return {
      buffer: jpeg,
      contentType: 'image/jpeg',
      filename: sanitizeFilename(filenameBase, fmt === 'jpg' ? 'jpg' : 'jpeg'),
      streamFromS3: false,
    };
  }

  // pdf — single page sized to image pixels (pdf points ≈ pixels at 72dpi)
  const pdfDoc = await PDFDocument.create();
  const pngImage = await pdfDoc.embedPng(pngBuffer);
  const page = pdfDoc.addPage([pngImage.width, pngImage.height]);
  page.drawImage(pngImage, {
    x: 0,
    y: 0,
    width: pngImage.width,
    height: pngImage.height,
  });
  const pdfBytes = await pdfDoc.save();

  return {
    buffer: Buffer.from(pdfBytes),
    contentType: 'application/pdf',
    filename: sanitizeFilename(filenameBase, 'pdf'),
    streamFromS3: false,
  };
}

/**
 * Send download response for Express.
 */
async function sendDownload(req, res, { s3Key, format, filenameBase }) {
  const payload = await buildDownloadPayload({ s3Key, format, filenameBase });
  const disposition = `attachment; filename="${payload.filename}"`;

  if (payload.streamFromS3 && normalizeDownloadFormat(format) === 'png') {
    return streamObjectToResponse(req, res, s3Key, {
      contentDisposition: disposition,
    });
  }

  res.setHeader('Content-Type', payload.contentType);
  res.setHeader('Content-Disposition', disposition);
  res.setHeader('Content-Length', String(payload.buffer.length));
  res.setHeader('Cache-Control', 'private, no-cache');
  return res.status(200).send(payload.buffer);
}

module.exports = {
  DOWNLOAD_FORMATS,
  normalizeDownloadFormat,
  buildDownloadPayload,
  sendDownload,
  sanitizeFilename,
};
