const sharp = require('sharp');
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

function isSvgBuffer(buffer, mimeType) {
  const mime = String(mimeType || '').toLowerCase();
  if (mime === 'image/svg+xml') return true;
  if (!buffer?.length) return false;
  const head = buffer.slice(0, 64).toString('utf8').trimStart().toLowerCase();
  return head.startsWith('<svg') || head.startsWith('<?xml');
}

async function normalizeImageBuffer(buffer, mimeType) {
  if (!buffer?.length) return null;
  if (isSvgBuffer(buffer, mimeType)) {
    const png = await sharp(buffer, { density: 300 }).png().toBuffer();
    return { buffer: png, mimeType: 'image/png' };
  }
  const mime = String(mimeType || '').toLowerCase();
  if (mime === 'image/jpeg' || mime === 'image/jpg') {
    return { buffer, mimeType: 'image/jpeg' };
  }
  if (mime === 'image/webp') {
    const png = await sharp(buffer).png().toBuffer();
    return { buffer: png, mimeType: 'image/png' };
  }
  return { buffer, mimeType: mime || 'image/png' };
}

async function fetchUrlToBuffer(url) {
  if (!url) return null;
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (!res.ok) return null;
  const ab = await res.arrayBuffer();
  return Buffer.from(ab);
}

async function mediaToDataUrl(media) {
  const mimeType = media?.mimeType || 'image/png';
  let buffer = null;

  if (media?.s3Key) {
    try {
      buffer = await s3Service.getObjectBuffer(media.s3Key);
    } catch {
      buffer = null;
    }
  }

  if (!buffer?.length && media?.s3Key) {
    try {
      const url = await s3Service.getPresignedGetUrl(media.s3Key, 3600);
      buffer = await fetchUrlToBuffer(url);
    } catch {
      buffer = null;
    }
  }

  if (!buffer?.length) {
    const publicUrl =
      media?.url ||
      (media?.s3Key ? s3Service.buildPublicUrl(media.s3Key) : null);
    if (publicUrl && /^https?:\/\//i.test(publicUrl)) {
      try {
        buffer = await fetchUrlToBuffer(publicUrl);
      } catch {
        buffer = null;
      }
    }
  }

  if (!buffer?.length) return null;

  try {
    const normalized = await normalizeImageBuffer(buffer, mimeType);
    if (!normalized?.buffer?.length) return null;
    return bufferToDataUrl(normalized.buffer, normalized.mimeType);
  } catch {
    return null;
  }
}

async function loadMediaDataUrls(media = [], kind) {
  const items = [];
  const wanted = String(kind || '').toLowerCase();
  for (const m of media) {
    if (String(m.kind || '').toLowerCase() !== wanted) continue;
    const dataUrl = await mediaToDataUrl(m);
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
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--font-render-hinting=none'],
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
      waitUntil: 'load',
      timeout: 90000,
    });
    await page.evaluate(async () => {
      if (document.fonts?.ready) {
        await Promise.race([
          document.fonts.ready.catch(() => null),
          new Promise((resolve) => setTimeout(resolve, 4000)),
        ]);
      }
    });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      preferCSSPageSize: true,
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
  mediaToDataUrl,
};
