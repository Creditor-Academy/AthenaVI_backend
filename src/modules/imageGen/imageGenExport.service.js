const { PDFDocument, cmyk } = require('pdf-lib');
const AppError = require('../../shared/utils/AppError');
const { getObjectBuffer, streamObjectToResponse } = require('../s3/s3.service');
const { toJpeg } = require('./socialCrop.service');
const { resolveFormat, bleedCanvasFor, MM_PER_INCH } = require('./catalogs/formats');

const DOWNLOAD_FORMATS = Object.freeze(['png', 'jpg', 'jpeg', 'pdf']);

const POINTS_PER_INCH = 72;
const MARK_MARGIN_MM = 10;
const MARK_GAP_MM = 1;
const MARK_LENGTH_MM = 5;
const MARK_THICKNESS_PT = 0.25;

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
    .replace(/[^\w.-]+/g, '_')
    .slice(0, 120);
  return `${base || 'image'}.${ext}`;
}

function mmToPt(mm) {
  return (mm / MM_PER_INCH) * POINTS_PER_INCH;
}

function pxToPt(px, dpi) {
  return (px / dpi) * POINTS_PER_INCH;
}

/** Print format of a printable generation, or null for every other mode. */
function printFormatFor(generation) {
  if (!generation || generation.mode !== 'printable') return null;
  const format = resolveFormat(generation.formatId);
  return format && format.category === 'print' ? format : null;
}

/** One page at the image pixel size (points ≈ pixels at 72 DPI). */
async function pixelPdf(pngBuffer) {
  const pdfDoc = await PDFDocument.create();
  const pngImage = await pdfDoc.embedPng(pngBuffer);
  const page = pdfDoc.addPage([pngImage.width, pngImage.height]);
  page.drawImage(pngImage, { x: 0, y: 0, width: pngImage.width, height: pngImage.height });
  return pdfDoc.save();
}

/** One page at the physical trim size of the print format. */
async function trimPdf(pngBuffer, format) {
  const pdfDoc = await PDFDocument.create();
  const pngImage = await pdfDoc.embedPng(pngBuffer);
  const width = mmToPt(format.widthMm);
  const height = mmToPt(format.heightMm);
  const page = pdfDoc.addPage([width, height]);
  page.drawImage(pngImage, { x: 0, y: 0, width, height });
  page.setTrimBox(0, 0, width, height);
  return pdfDoc.save();
}

function drawCropMarks(page, { trimX, trimY, trimW, trimH, offset }) {
  const gap = offset + mmToPt(MARK_GAP_MM);
  const length = mmToPt(MARK_LENGTH_MM);
  const color = cmyk(1, 1, 1, 1);
  const line = (start, end) =>
    page.drawLine({ start, end, thickness: MARK_THICKNESS_PT, color });

  const xs = [trimX, trimX + trimW];
  const ys = [trimY, trimY + trimH];
  for (const x of xs) {
    for (const y of ys) {
      const dirX = x === trimX ? -1 : 1;
      const dirY = y === trimY ? -1 : 1;
      line({ x: x + dirX * gap, y }, { x: x + dirX * (gap + length), y });
      line({ x, y: y + dirY * gap }, { x, y: y + dirY * (gap + length) });
    }
  }
}

/**
 * Trim size + bleed + a mark margin, with crop marks at the trim corners and
 * TrimBox/BleedBox set for the printer.
 */
async function bleedPdf(bleedBuffer, format) {
  const canvas = bleedCanvasFor(format);
  const pdfDoc = await PDFDocument.create();
  const pngImage = await pdfDoc.embedPng(bleedBuffer);

  const margin = mmToPt(MARK_MARGIN_MM);
  const bleed = pxToPt(canvas.bleedPx, canvas.dpi);
  const trimW = mmToPt(format.widthMm);
  const trimH = mmToPt(format.heightMm);
  const bleedW = trimW + bleed * 2;
  const bleedH = trimH + bleed * 2;

  const page = pdfDoc.addPage([bleedW + margin * 2, bleedH + margin * 2]);
  page.drawImage(pngImage, { x: margin, y: margin, width: bleedW, height: bleedH });
  page.setBleedBox(margin, margin, bleedW, bleedH);
  page.setTrimBox(margin + bleed, margin + bleed, trimW, trimH);

  drawCropMarks(page, {
    trimX: margin + bleed,
    trimY: margin + bleed,
    trimW,
    trimH,
    offset: bleed,
  });

  return pdfDoc.save();
}

/**
 * Build download payload (buffer + headers) for a generation's master PNG.
 * Printable generations export at physical size; `bleed` adds the bleed PDF.
 */
async function buildDownloadPayload({ s3Key, format, filenameBase, generation = null, bleed = false }) {
  const fmt = normalizeDownloadFormat(format);
  const printFormat = printFormatFor(generation);

  if (bleed) {
    if (!printFormat) {
      throw new AppError('bleed is only available for printable generations', 400);
    }
    if (fmt !== 'pdf') {
      throw new AppError('bleed is only available with format=pdf', 400);
    }
    const bleedKey = generation.request?.print?.bleedKey;
    if (!bleedKey) {
      throw new AppError('This generation has no bleed file. Regenerate it to get one.', 400);
    }
    const pdfBytes = await bleedPdf(await getObjectBuffer(bleedKey), printFormat);
    return {
      buffer: Buffer.from(pdfBytes),
      contentType: 'application/pdf',
      filename: sanitizeFilename(`${filenameBase}_bleed`, 'pdf'),
      streamFromS3: false,
    };
  }

  if (fmt === 'png') {
    return {
      buffer: null,
      contentType: 'image/png',
      filename: sanitizeFilename(filenameBase, 'png'),
      streamFromS3: true,
    };
  }

  const pngBuffer = await getObjectBuffer(s3Key);

  if (fmt === 'jpg' || fmt === 'jpeg') {
    const jpeg = await toJpeg(pngBuffer, 90, { density: printFormat?.dpi });
    return {
      buffer: jpeg,
      contentType: 'image/jpeg',
      filename: sanitizeFilename(filenameBase, fmt === 'jpg' ? 'jpg' : 'jpeg'),
      streamFromS3: false,
    };
  }

  const pdfBytes = printFormat ? await trimPdf(pngBuffer, printFormat) : await pixelPdf(pngBuffer);
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
async function sendDownload(req, res, { s3Key, format, filenameBase, generation = null, bleed = false }) {
  const payload = await buildDownloadPayload({ s3Key, format, filenameBase, generation, bleed });
  const disposition = `attachment; filename="${payload.filename}"`;

  if (payload.streamFromS3) {
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
