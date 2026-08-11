const sharp = require('sharp');
const AppError = require('../../shared/utils/AppError');
const s3Service = require('../s3/s3.service');
const brandKitDao = require('./brandKit.dao');

const VARIANT_ROLES = ['light', 'dark', 'black', 'white', 'with-name-below', 'with-name-adjacent'];

function normalizeRole(role) {
  const r = String(role || '').toLowerCase();
  if (r === 'light-mode') return 'light';
  if (r === 'dark-mode') return 'dark';
  return r;
}

async function loadPrimaryLogoBuffer(kit) {
  const primary =
    (kit.media || []).find((m) => m.kind === 'logo' && m.role === 'primary') ||
    (kit.media || []).find((m) => m.kind === 'logo');
  if (!primary?.s3Key) {
    throw new AppError('Primary logo is required to generate variants', 400);
  }
  const buf = await s3Service.getObjectBuffer(primary.s3Key);
  if (!buf?.length) throw new AppError('Could not read primary logo from storage', 502);
  const mimeType = primary.mimeType || 'image/png';
  const normalized = await normalizeLogoBuffer(buf, mimeType);
  return { buffer: normalized, mimeType: 'image/png', primary };
}

async function normalizeLogoBuffer(buffer, mimeType) {
  const mime = String(mimeType || '').toLowerCase();
  const isSvg =
    mime === 'image/svg+xml' ||
    (buffer.length > 4 && buffer.slice(0, 5).toString('utf8').trimStart().startsWith('<'));
  if (!isSvg) return buffer;
  return sharp(buffer, { density: 300 }).png().toBuffer();
}

async function renderOnBackground(logoBuffer, bgHex, padding = 0.15) {
  const meta = await sharp(logoBuffer).metadata();
  const w = meta.width || 512;
  const h = meta.height || 512;
  const pad = Math.round(Math.max(w, h) * padding);
  const canvasW = w + pad * 2;
  const canvasH = h + pad * 2;
  const bg = String(bgHex).replace(/^#/, '');
  return sharp({
    create: {
      width: canvasW,
      height: canvasH,
      channels: 4,
      background: `#${bg}`,
    },
  })
    .composite([{ input: logoBuffer, top: pad, left: pad }])
    .png()
    .toBuffer();
}

async function renderMonochrome(logoBuffer, fillHex) {
  const { data, info } = await sharp(logoBuffer)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  const fill = String(fillHex).replace(/^#/, '');
  const fr = parseInt(fill.slice(0, 2), 16);
  const fg = parseInt(fill.slice(2, 4), 16);
  const fb = parseInt(fill.slice(4, 6), 16);
  for (let i = 0; i < data.length; i += 4) {
    const a = data[i + 3];
    if (a > 16) {
      data[i] = fr;
      data[i + 1] = fg;
      data[i + 2] = fb;
    }
  }
  return sharp(data, { raw: { width: info.width, height: info.height, channels: 4 } })
    .png()
    .toBuffer();
}

async function renderLockup(logoBuffer, brandName, tagline, layout) {
  const meta = await sharp(logoBuffer).metadata();
  const logoW = Math.min(meta.width || 256, 320);
  const logoH = Math.round((logoW / (meta.width || 256)) * (meta.height || 256));
  const resizedLogo = await sharp(logoBuffer).resize(logoW, logoH, { fit: 'inside' }).png().toBuffer();

  const name = String(brandName || 'Brand').slice(0, 48);
  const sub = String(tagline || '').slice(0, 80);
  const fontSize = layout === 'adjacent' ? 36 : 32;
  const subSize = 18;
  const canvasW = layout === 'adjacent' ? logoW + 420 : logoW + 80;
  const canvasH = layout === 'adjacent' ? Math.max(logoH + 40, 120) : logoH + 120;

  const svg =
    layout === 'adjacent'
      ? `<svg width="${canvasW}" height="${canvasH}" xmlns="http://www.w3.org/2000/svg">
  <text x="${logoW + 24}" y="${Math.round(canvasH / 2) - 8}" font-family="Arial, sans-serif" font-size="${fontSize}" font-weight="700" fill="#111111">${escapeXml(name)}</text>
  ${sub ? `<text x="${logoW + 24}" y="${Math.round(canvasH / 2) + 24}" font-family="Arial, sans-serif" font-size="${subSize}" fill="#444444">${escapeXml(sub)}</text>` : ''}
</svg>`
      : `<svg width="${canvasW}" height="${canvasH}" xmlns="http://www.w3.org/2000/svg">
  <text x="${Math.round(logoW / 2)}" y="${logoH + 48}" text-anchor="middle" font-family="Arial, sans-serif" font-size="${fontSize}" font-weight="700" fill="#111111">${escapeXml(name)}</text>
  ${sub ? `<text x="${Math.round(logoW / 2)}" y="${logoH + 80}" text-anchor="middle" font-family="Arial, sans-serif" font-size="${subSize}" fill="#444444">${escapeXml(sub)}</text>` : ''}
</svg>`;

  const textBuf = Buffer.from(svg);
  const textImg = await sharp(textBuf).png().toBuffer();
  const textMeta = await sharp(textImg).metadata();

  const finalW = layout === 'adjacent' ? canvasW : Math.max(logoW + 80, textMeta.width || canvasW);
  const finalH =
    layout === 'adjacent'
      ? Math.max(canvasH, logoH)
      : logoH + (textMeta.height || 100);

  const composites = [{ input: resizedLogo, top: 0, left: 0 }];
  if (layout === 'adjacent') {
    composites.push({ input: textImg, top: 0, left: 0 });
  } else {
    composites.push({ input: textImg, top: logoH, left: 0 });
  }

  return sharp({
    create: {
      width: finalW,
      height: finalH,
      channels: 4,
      background: { r: 255, g: 255, b: 255, alpha: 0 },
    },
  })
    .composite(composites)
    .png()
    .toBuffer();
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function generateVariantBuffer(role, logoBuffer, kit) {
  const normalized = normalizeRole(role);
  const data = kit.data || {};
  const palette = data.colors || [];
  const roles = data.colorRoles || {};
  const colorMap = new Map(palette.map((c) => [c.id, c.hex]));
  const bgLight = colorMap.get(roles.bg) || '#F7F3F3';
  const bgDark = colorMap.get(roles.bgDark) || '#1B1110';

  switch (normalized) {
    case 'light':
      return renderOnBackground(logoBuffer, bgLight);
    case 'dark':
      return renderOnBackground(logoBuffer, bgDark);
    case 'black':
      return renderMonochrome(logoBuffer, '#000000');
    case 'white':
      return renderMonochrome(logoBuffer, '#FFFFFF');
    case 'with-name-below':
      return renderLockup(logoBuffer, kit.name, data.meta?.tagline, 'below');
    case 'with-name-adjacent':
      return renderLockup(logoBuffer, kit.name, data.meta?.tagline, 'adjacent');
    default:
      throw new AppError(`Unsupported logo variant role: ${role}`, 400);
  }
}

async function suggestLogoVariants({ workspaceId, brandKitId, applyRoles = [] }) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError('Brand kit not found', 404);

  const { buffer: logoBuffer } = await loadPrimaryLogoBuffer(kit);
  const existingRoles = new Set(
    (kit.media || [])
      .filter((m) => m.kind === 'logo' && m.role)
      .map((m) => normalizeRole(m.role))
  );

  const missingRoles = VARIANT_ROLES.filter((r) => !existingRoles.has(normalizeRole(r)));
  const rolesToGenerate =
    applyRoles.length > 0
      ? applyRoles.map(normalizeRole)
      : missingRoles;

  const variants = [];
  for (const role of rolesToGenerate) {
    let variantBuffer;
    try {
      variantBuffer = await generateVariantBuffer(role, logoBuffer, kit);
    } catch (err) {
      variants.push({
        role,
        url: null,
        s3Key: null,
        mediaId: null,
        applied: false,
        preview: applyRoles.length === 0,
        error: err.message || 'Variant generation failed',
      });
      continue;
    }

    if (applyRoles.length === 0) {
      variants.push({
        role,
        url: `data:image/png;base64,${variantBuffer.toString('base64')}`,
        s3Key: null,
        mediaId: null,
        applied: false,
        preview: true,
      });
      continue;
    }

    const uploaded = await s3Service.uploadFile(
      variantBuffer,
      'workspace',
      workspaceId,
      `brand-kits/${brandKitId}/logo`,
      `${role}-variant.png`,
      'image/png'
    );

    const existingRows = await brandKitDao.findAllMediaByKindRole(brandKitId, 'logo', role);
    for (const existing of existingRows) {
      await brandKitDao.deleteMedia(existing.id);
      try {
        await s3Service.deleteFile(existing.s3Key);
      } catch {
        // best-effort
      }
    }

    const sortOrder = (await brandKitDao.maxSortOrder(brandKitId, 'logo')) + 1;
    const mediaRecord = await brandKitDao.createMedia({
      brandKitId,
      kind: 'logo',
      role,
      name: `${role} variant`,
      assetId: null,
      s3Key: uploaded.key,
      mimeType: 'image/png',
      sortOrder,
    });

    let url = uploaded.url;
    try {
      url = await s3Service.getPresignedGetUrl(uploaded.key, 3600);
    } catch {
      // keep public url
    }

    variants.push({
      role,
      url,
      s3Key: uploaded.key,
      mediaId: mediaRecord?.id || null,
      applied: true,
      preview: false,
    });
  }

  return {
    generated: variants.length,
    missingRoles,
    variants,
  };
}

module.exports = {
  VARIANT_ROLES,
  suggestLogoVariants,
  generateVariantBuffer,
};
