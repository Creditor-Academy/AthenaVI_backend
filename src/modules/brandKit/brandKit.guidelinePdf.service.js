const s3Service = require('../s3/s3.service');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const brandKitDao = require('./brandKit.dao');
const { buildGuidelinePdfHtml } = require('./brandKit.guidelinePdf.template');

function sanitizeFilename(name) {
  const base = String(name || 'Brand_Kit')
    .replace(/[^\w\s-]+/g, '')
    .trim()
    .replace(/\s+/g, '_');
  return `${base || 'Brand_Kit'}_Brand_Guidelines.pdf`;
}

async function bufferToDataUrl(buffer, mimeType) {
  const mime = mimeType || 'image/png';
  return `data:${mime};base64,${Buffer.from(buffer).toString('base64')}`;
}

async function loadMediaDataUrls(media = [], kind) {
  const items = [];
  const wanted = String(kind || '').toLowerCase();
  for (const m of media) {
    if (String(m.kind || '').toLowerCase() !== wanted) continue;
    let dataUrl = null;
    if (m.s3Key) {
      try {
        const buf = await s3Service.getObjectBuffer(m.s3Key);
        dataUrl = await bufferToDataUrl(buf, m.mimeType || 'image/png');
      } catch {
        dataUrl = null;
      }
    }
    items.push({
      id: m.id,
      role: String(m.role || '').toLowerCase() || null,
      name: m.name || null,
      templateId: m.templateId || m.meta?.templateId || null,
      dataUrl,
    });
  }
  return items;
}

async function withBrowserPage(fn) {
  let browser;
  try {
    const puppeteer = require('puppeteer');
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
    const page = await browser.newPage();
    return await fn(page);
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

/**
 * Build a printable brand guideline PDF for a kit.
 * @returns {Promise<{ buffer: Buffer, filename: string, contentType: string }>}
 */
async function generateGuidelinePdf({ workspaceId, brandKitId }) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);

  const media = kit.media || [];
  const [logos, mockups] = await Promise.all([
    loadMediaDataUrls(media, 'logo'),
    loadMediaDataUrls(media, 'mockup'),
  ]);
  const html = buildGuidelinePdfHtml({
    kitName: kit.name || 'Brand Kit',
    data: kit.data || {},
    logos,
    mockups,
    subtitle: kit.data?.meta?.tagline || '',
  });

  const buffer = await withBrowserPage(async (page) => {
    await page.setViewport({ width: 794, height: 1123, deviceScaleFactor: 2 });
    await page.setContent(html, {
      waitUntil: 'networkidle0',
      timeout: 60000,
    });
    // Give webfonts a brief moment to apply
    await page.evaluate(() => document.fonts?.ready?.catch?.(() => null));
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      preferCSSPageSize: true,
      // Content inset comes from @page { margin } in the HTML template
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
    });
    return Buffer.from(pdf);
  });

  return {
    buffer,
    filename: sanitizeFilename(kit.name),
    contentType: 'application/pdf',
  };
}

module.exports = {
  generateGuidelinePdf,
  sanitizeFilename,
};
