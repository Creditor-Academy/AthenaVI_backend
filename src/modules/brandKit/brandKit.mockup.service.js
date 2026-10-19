const crypto = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const s3Service = require('../s3/s3.service');
const { generateImageWithReferences } = require('../../shared/services/ai/image.service');
const brandKitDao = require('./brandKit.dao');
const brandKitCredit = require('./brandKitCredit.service');
const brandKitService = require('./brandKit.service');
const mockupRateLimit = require('./brandKit.mockupRateLimit.service');
const {
  MOCKUP_FREE_LIMIT,
  getTemplate,
  listTemplates,
  buildMockupPrompt,
  resolveApparelLogoPosition,
  supportsApparelLogoPosition,
} = require('./brandKit.mockupCatalog');
const sharp = require('sharp');

function normalizeLogoRole(role) {
  const r = String(role || '').toLowerCase();
  if (r === 'light-mode') return 'light';
  if (r === 'dark-mode') return 'dark';
  return r;
}

async function normalizeLogoBuffer(buffer, mimeType) {
  const mime = String(mimeType || '').toLowerCase();
  const isSvg =
    mime === 'image/svg+xml' ||
    (buffer.length > 4 && buffer.slice(0, 5).toString('utf8').trimStart().startsWith('<'));
  if (!isSvg) return buffer;
  return sharp(buffer, { density: 300 }).png().toBuffer();
}

function getFreeUsed(kit) {
  const n = Number(kit?.data?.meta?.mockupFreeUsed);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function buildBilling(freeUsed, charged, athenaCredits) {
  const used = Math.min(MOCKUP_FREE_LIMIT, Math.max(0, freeUsed));
  return {
    charged: Boolean(charged),
    freeUsed: used,
    freeLimit: MOCKUP_FREE_LIMIT,
    freeRemaining: Math.max(0, MOCKUP_FREE_LIMIT - used),
    athenaCredits: charged ? athenaCredits : 0,
    feature: brandKitCredit.BRAND_KIT_FEATURE.LOGO_MOCKUP,
  };
}

function resolvePaletteHints(kit) {
  try {
    const map = brandKitService.colorMap(kit.data);
    const roles = kit.data?.colorRoles || {};
    return {
      primaryHex: brandKitService.resolveHex(map, roles.primary, null),
      bgHex: brandKitService.resolveHex(map, roles.bg, null),
    };
  } catch {
    return { primaryHex: null, bgHex: null };
  }
}

function pickLogoMedia(kit, logoRole) {
  const logos = (kit.media || []).filter((m) => m.kind === 'logo' && m.s3Key);
  if (!logos.length) return null;

  const byRole = new Map();
  for (const m of logos) {
    const r = normalizeLogoRole(m.role);
    if (r && !byRole.has(r)) byRole.set(r, m);
    if (m.role === 'light-mode' && !byRole.has('light')) byRole.set('light', m);
    if (m.role === 'dark-mode' && !byRole.has('dark')) byRole.set('dark', m);
  }

  if (logoRole) {
    const wanted = normalizeLogoRole(logoRole);
    return byRole.get(wanted) || logos.find((m) => normalizeLogoRole(m.role) === wanted) || null;
  }

  return (
    byRole.get('primary') ||
    logos.find((m) => m.role === 'primary') ||
    logos[0] ||
    null
  );
}

async function loadLogoBuffer(media) {
  if (!media?.s3Key) {
    throw new AppError(messages.BRAND_KIT_MOCKUP_LOGO_REQUIRED, 400);
  }
  const buf = await s3Service.getObjectBuffer(media.s3Key);
  if (!buf?.length) throw new AppError('Could not read logo from storage', 502);
  const normalized = await normalizeLogoBuffer(buf, media.mimeType || 'image/png');
  return normalized;
}

async function replaceMockupRole(brandKitId, templateId) {
  const existingRows = await brandKitDao.findAllMediaByKindRole(brandKitId, 'mockup', templateId);
  for (const existing of existingRows) {
    await brandKitDao.deleteMedia(existing.id);
    try {
      await s3Service.deleteFile(existing.s3Key);
    } catch {
      // best-effort
    }
  }
}

async function uploadMockupBuffer({
  workspaceId,
  brandKitId,
  buffer,
  folder,
  filename,
}) {
  const uploaded = await s3Service.uploadFile(
    buffer,
    'workspace',
    workspaceId,
    `brand-kits/${brandKitId}/${folder}`,
    filename,
    'image/png'
  );
  let url = uploaded.url;
  try {
    url = await s3Service.getPresignedGetUrl(uploaded.key, 3600);
  } catch {
    // keep public url
  }
  return { key: uploaded.key, url };
}

function getQuotaFromKit(kit) {
  const freeUsed = getFreeUsed(kit);
  return buildBilling(freeUsed, false, 0);
}

async function getCatalog(workspaceId, brandKitId) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  return {
    templates: listTemplates(),
    billing: getQuotaFromKit(kit),
  };
}

async function listSavedMockups(workspaceId, brandKitId) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);

  const mockups = await Promise.all(
    (kit.media || [])
      .filter((m) => m.kind === 'mockup')
      .map(async (m) => {
        let url = null;
        try {
          url = await s3Service.getPresignedGetUrl(m.s3Key, 3600);
        } catch {
          url = s3Service.buildPublicUrl(m.s3Key);
        }
        return { ...m, url };
      })
  );

  return {
    mockups,
    billing: getQuotaFromKit(kit),
  };
}

function normalizeOptionalHex(value) {
  const hex = String(value || '').trim();
  return hex || null;
}

function normalizeOptionalLogoRole(value) {
  const role = String(value || '').trim();
  return role || null;
}

async function generateMockup({
  workspaceId,
  userId,
  brandKitId,
  templateId,
  logoRole,
  itemColor,
  logoPosition,
  save = false,
}) {
  await mockupRateLimit.assertGenerateAllowed(userId, workspaceId);

  const template = getTemplate(templateId);
  if (!template) {
    throw new AppError(`Unknown mockup template: ${templateId}`, 400);
  }

  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);

  const requestedLogoRole = normalizeOptionalLogoRole(logoRole);
  const requestedItemColor = normalizeOptionalHex(itemColor);
  const requestedLogoPosition = String(logoPosition || '').trim();
  const resolvedLogoPosition = resolveApparelLogoPosition(template.id, logoPosition);
  if (supportsApparelLogoPosition(template.id) && requestedLogoPosition && !resolvedLogoPosition) {
    throw new AppError(`Invalid logoPosition for ${template.id}: ${requestedLogoPosition}`, 400);
  }

  const logoMedia = pickLogoMedia(kit, requestedLogoRole);
  if (!logoMedia) {
    throw new AppError(messages.BRAND_KIT_MOCKUP_LOGO_REQUIRED, 400);
  }

  const freeUsed = getFreeUsed(kit);
  const isFree = freeUsed < MOCKUP_FREE_LIMIT;
  const feature = brandKitCredit.BRAND_KIT_FEATURE.LOGO_MOCKUP;
  const estimatedAc = brandKitCredit.getFlatAc(feature);

  if (!isFree) {
    await brandKitCredit.assertAfford(workspaceId, userId, estimatedAc);
  }

  const logoBuffer = await loadLogoBuffer(logoMedia);
  const { primaryHex, bgHex } = resolvePaletteHints(kit);
  const prompt = buildMockupPrompt({
    template,
    brandName: kit.name,
    tagline: kit.data?.meta?.tagline,
    primaryHex,
    bgHex,
    itemColor: requestedItemColor,
    logoPosition: resolvedLogoPosition,
  });

  const model = process.env.BRAND_KIT_MOCKUP_MODEL || 'gpt-image-1';
  const { buffer } = await generateImageWithReferences({
    prompt,
    referenceBuffers: [logoBuffer],
    quality: 'medium',
    model,
    size: template.size || '1024x1024',
  });

  const stamp = crypto.randomBytes(4).toString('hex');
  let preview = await uploadMockupBuffer({
    workspaceId,
    brandKitId,
    buffer,
    folder: 'mockup-preview',
    filename: `${template.id}-${stamp}.png`,
  });

  let mediaId = null;
  let saved = false;
  let s3Key = preview.key;
  let url = preview.url;

  if (save) {
    await replaceMockupRole(brandKitId, template.id);
    const finalUpload = await uploadMockupBuffer({
      workspaceId,
      brandKitId,
      buffer,
      folder: 'mockup',
      filename: `${template.id}.png`,
    });
    const sortOrder = (await brandKitDao.maxSortOrder(brandKitId, 'mockup')) + 1;
    const mediaRecord = await brandKitDao.createMedia({
      brandKitId,
      kind: 'mockup',
      role: template.id,
      name: `${template.label} mockup`,
      assetId: null,
      s3Key: finalUpload.key,
      mimeType: 'image/png',
      sortOrder,
    });
    mediaId = mediaRecord.id;
    saved = true;
    s3Key = finalUpload.key;
    url = finalUpload.url;
  }

  let nextFreeUsed = freeUsed;
  let charged = false;
  let athenaCredits = 0;

  if (isFree) {
    nextFreeUsed = freeUsed + 1;
    const updatedData = {
      ...(kit.data && typeof kit.data === 'object' ? kit.data : {}),
      meta: {
        ...((kit.data && kit.data.meta) || {}),
        mockupFreeUsed: nextFreeUsed,
      },
    };
    await brandKitDao.updateKit({
      workspaceId,
      brandKitId,
      data: updatedData,
    });
  } else {
    const charge = await brandKitCredit.chargeFlat({
      workspaceId,
      userId,
      feature,
      idempotencyKey: `brandKit:logo_mockup:${workspaceId}:${brandKitId}:${template.id}:${Date.now()}`,
      metadata: {
        brandKitId,
        action: 'logo_mockup',
        templateId: template.id,
      },
    });
    charged = true;
    athenaCredits = charge?.pricing?.athenaCredits ?? estimatedAc;
  }

  return {
    mockup: {
      templateId: template.id,
      logoRoleUsed: normalizeLogoRole(logoMedia.role) || 'primary',
      itemColorUsed: requestedItemColor,
      logoPositionUsed: resolvedLogoPosition,
      url,
      s3Key,
      mediaId,
      saved,
    },
    billing: buildBilling(nextFreeUsed, charged, athenaCredits),
  };
}

module.exports = {
  getCatalog,
  listSavedMockups,
  generateMockup,
  MOCKUP_FREE_LIMIT,
  getTemplate,
};
