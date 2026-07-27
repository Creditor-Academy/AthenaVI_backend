const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const { loadPresentationDeck } = require('./deckGeneration.service');
const s3Service = require('../s3/s3.service');
const inboxService = require('../inbox/inbox.service');
const { PPT_FEATURE } = require('../../shared/config/presentationCreditPricing');
const { downloadRemote } = require('../../shared/utils/downloadRemote');

const PRESIGN_EXPIRES_SEC = 3600;

async function notifyExportFinished({
  userId,
  workspaceId,
  projectId,
  deckId,
  exportId,
  format,
  status,
  projectName,
  error,
}) {
  try {
    const ok = status === 'READY';
    await inboxService.notifyUser({
      userId,
      type: ok ? 'PRESENTATION_EXPORT_COMPLETED' : 'PRESENTATION_EXPORT_FAILED',
      referenceId: exportId,
      workspaceId,
      title: ok ? 'Presentation export ready' : 'Presentation export failed',
      message: ok
        ? `"${projectName || 'Presentation'}" ${format} export is ready.`
        : `"${projectName || 'Presentation'}" ${format} export failed${error ? `: ${error}` : '.'}`,
      metadata: {
        workspaceId,
        projectId,
        deckId,
        exportId,
        format,
        status,
        actionUrl: `${process.env.FRONTEND_URL || ''}/workspaces/${workspaceId}/presentations/${projectId}`,
      },
    });
  } catch (notifyErr) {
    logger.error?.('presentation_export_notify_failed', notifyErr) ||
      console.error('presentation export notify failed', notifyErr);
  }
}

function bulletsFromContent(content) {
  if (!content || typeof content !== 'object') return [];
  if (Array.isArray(content.bullets)) {
    return content.bullets
      .map((b) => (typeof b === 'string' ? b : b?.text || ''))
      .filter(Boolean);
  }
  return [];
}

async function fetchImageAsBase64(url) {
  if (!url || !/^https?:\/\//i.test(String(url))) return null;
  try {
    const buffer = await downloadRemote(url, { maxBytes: 12 * 1024 * 1024 });
    return buffer.toString('base64');
  } catch {
    return null;
  }
}

async function buildPptxBuffer(deck) {
  const PptxGenJS = require('pptxgenjs');
  const pptx = new PptxGenJS();
  pptx.defineLayout({ name: 'LAYOUT_16x9', width: 13.333, height: 7.5 });
  pptx.layout = 'LAYOUT_16x9';

  const palette = deck.themeTokens?.palette || {};
  const slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  const bgColor = String(palette.bg || 'FFFFFF').replace(/^#/, '');
  const textColor = String(palette.text || '111111').replace(/^#/, '');

  for (const slide of slides) {
    const s = pptx.addSlide({ background: { color: bgColor } });

    const content = slide.content || {};
    const title = content.title || `Slide ${slide.order}`;

    s.addText(String(title), {
      x: 0.5,
      y: 0.4,
      w: 8.5,
      h: 0.8,
      fontSize: 28,
      bold: true,
      color: textColor,
    });

    if (content.subtitle) {
      s.addText(String(content.subtitle), {
        x: 0.5,
        y: 1.2,
        w: 8.5,
        h: 0.5,
        fontSize: 16,
        color: textColor,
      });
    }

    const bullets = bulletsFromContent(content);
    if (bullets.length) {
      s.addText(
        bullets.map((t) => ({ text: t, options: { bullet: true, breakLine: true } })),
        {
          x: 0.5,
          y: 1.9,
          w: 7.5,
          h: 4.5,
          fontSize: 16,
          color: textColor,
          valign: 'top',
        }
      );
    } else if (content.body) {
      s.addText(String(content.body), {
        x: 0.5,
        y: 1.9,
        w: 7.5,
        h: 4.5,
        fontSize: 16,
        color: textColor,
        valign: 'top',
      });
    }

    const imageUrl = slide.imageRef?.url;
    if (imageUrl) {
      const b64 = await fetchImageAsBase64(imageUrl);
      if (b64) {
        s.addImage({
          data: b64,
          x: 8.4,
          y: 1.6,
          w: 4.4,
          h: 4.4,
        });
      }
    }

    if (content.notes) {
      s.addNotes(String(content.notes));
    }
  }

  const out = await pptx.write({ outputType: 'nodebuffer' });
  return Buffer.isBuffer(out) ? out : Buffer.from(out);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function buildPdfHtml(deck) {
  const palette = deck.themeTokens?.palette || {};
  const bg = palette.bg || '#ffffff';
  const text = palette.text || '#111111';
  const slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);

  const pages = slides
    .map((slide) => {
      const content = slide.content || {};
      const bullets = bulletsFromContent(content)
        .map((b) => `<li>${escapeHtml(b)}</li>`)
        .join('');
      const image = slide.imageRef?.url
        ? `<img src="${escapeHtml(slide.imageRef.url)}" alt="" />`
        : '';
      return `
      <section class="slide">
        <div class="text">
          <h1>${escapeHtml(content.title || `Slide ${slide.order}`)}</h1>
          ${content.subtitle ? `<h2>${escapeHtml(content.subtitle)}</h2>` : ''}
          ${content.body ? `<p>${escapeHtml(content.body)}</p>` : ''}
          ${bullets ? `<ul>${bullets}</ul>` : ''}
        </div>
        <div class="media">${image}</div>
      </section>`;
    })
    .join('\n');

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    @page { size: 13.333in 7.5in; margin: 0; }
    body { margin: 0; font-family: Arial, Helvetica, sans-serif; color: ${escapeHtml(text)}; }
    .slide {
      width: 13.333in; height: 7.5in; page-break-after: always;
      box-sizing: border-box; padding: 0.6in; display: flex; gap: 0.4in;
      background: ${escapeHtml(bg)};
    }
    .text { flex: 1; }
    .media { width: 4.5in; display: flex; align-items: center; justify-content: center; }
    .media img { max-width: 100%; max-height: 5.5in; object-fit: contain; }
    h1 { font-size: 36px; margin: 0 0 12px; }
    h2 { font-size: 20px; margin: 0 0 16px; font-weight: normal; }
    p, li { font-size: 18px; line-height: 1.4; }
    ul { padding-left: 1.2em; }
  </style>
</head>
<body>${pages}</body>
</html>`;
}

async function buildPdfBuffer(deck) {
  let browser;
  try {
    const puppeteer = require('puppeteer');
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 720 });
    await page.setContent(buildPdfHtml(deck), { waitUntil: 'networkidle0', timeout: 60000 });
    const pdf = await page.pdf({
      width: '13.333in',
      height: '7.5in',
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
    });
    return Buffer.from(pdf);
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
        // ignore
      }
    }
  }
}

async function processExport({ exportId, workspaceId, userId, projectId, projectName }) {
  const row = await presentationDao.findExport(exportId);
  if (!row) return;

  try {
    await presentationDao.updateExport(exportId, { status: 'RENDERING' });
    const deck = await presentationDao.findDeckById(row.deckId);
    if (!deck) {
      throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
    }

    const format = String(row.format || '').toUpperCase();
    let buffer;
    let contentType;
    let ext;

    if (format === 'PPTX') {
      buffer = await buildPptxBuffer(deck);
      contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
      ext = 'pptx';
    } else if (format === 'PDF') {
      buffer = await buildPdfBuffer(deck);
      contentType = 'application/pdf';
      ext = 'pdf';
    } else {
      throw new AppError(`Unsupported export format: ${format}`, 400);
    }

    const s3Key = `presentations/${workspaceId}/${deck.id}/exports/${exportId}.${ext}`;
    await s3Service.uploadFileToKey(buffer, s3Key, contentType);

    const chargeResult = await presentationCredit.chargeFlat({
      workspaceId,
      userId,
      feature: PPT_FEATURE.EXPORT,
      idempotencyKey: `ppt:export:${exportId}`,
      metadata: { deckId: deck.id, exportId, format },
    });

    const creditsCharged = chargeResult.skipped
      ? 0
      : chargeResult.charged || chargeResult.pricing?.athenaCredits || 0;

    if (!chargeResult.skipped && creditsCharged > 0) {
      await presentationDao.incrementDeckCreditsCharged(deck.id, creditsCharged);
    }

    await presentationDao.updateExport(exportId, {
      status: 'READY',
      s3Key,
      creditCharged: !chargeResult.skipped,
      creditsCharged,
      error: null,
    });

    await notifyExportFinished({
      userId,
      workspaceId,
      projectId: projectId || deck.projectId,
      deckId: deck.id,
      exportId,
      format,
      status: 'READY',
      projectName,
    });
  } catch (err) {
    logger.error?.('processExport failed', err) || console.error('processExport failed', err);
    await presentationDao.updateExport(exportId, {
      status: 'FAILED',
      error: String(err.message || err).slice(0, 2000),
    });
    await notifyExportFinished({
      userId,
      workspaceId,
      projectId,
      deckId: row.deckId,
      exportId,
      format: row.format,
      status: 'FAILED',
      projectName,
      error: err.message,
    });
  }
}

async function queueExport({ workspaceId, presentationId, userId, format }) {
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });

  const normalizedFormat = String(format || '').toUpperCase();
  if (normalizedFormat !== 'PPTX' && normalizedFormat !== 'PDF') {
    throw new AppError('format must be PPTX or PDF', 400);
  }

  const exportAc = presentationCredit.getFlatAc(PPT_FEATURE.EXPORT);
  await presentationCredit.assertAfford(workspaceId, userId, exportAc);

  const exportRow = await presentationDao.createExport({
    deckId: deck.id,
    format: normalizedFormat,
    status: 'QUEUED',
    creditCharged: false,
  });

  setImmediate(() => {
    processExport({
      exportId: exportRow.id,
      workspaceId,
      userId,
      projectId: project.id,
      projectName: project.name,
    });
  });

  return {
    exportId: exportRow.id,
    format: normalizedFormat,
    status: 'QUEUED',
    estimatedCredits: exportAc,
  };
}

async function getExport({ workspaceId, presentationId, exportId }) {
  const { deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  const row = await presentationDao.findExport(exportId);
  if (!row || row.deckId !== deck.id) {
    throw new AppError(messages.PRESENTATION_EXPORT_NOT_FOUND, 404);
  }

  const payload = {
    exportId: row.id,
    format: row.format,
    status: row.status,
    error: row.error || null,
    creditsCharged: row.creditsCharged ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };

  if (row.status === 'READY' && row.s3Key) {
    const presignedUrl = await s3Service.getPresignedGetUrl(row.s3Key, PRESIGN_EXPIRES_SEC);
    payload.presignedUrl = presignedUrl;
    payload.expiresIn = PRESIGN_EXPIRES_SEC;
    payload.s3Key = row.s3Key;
  }

  return payload;
}

module.exports = {
  queueExport,
  processExport,
  getExport,
  PRESIGN_EXPIRES_SEC,
};
