const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const s3Service = require('../s3/s3.service');
const themeService = require('../presentation/theme.service');
const brandKitDao = require('./brandKit.dao');

const LOGO_ROLES = new Set(['primary', 'secondary', 'icon', 'light', 'dark']);
const IMAGE_MIME = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/svg+xml',
]);

function colorMap(data) {
  const map = new Map();
  for (const c of data?.colors || []) {
    if (c?.id) map.set(String(c.id), c);
  }
  return map;
}

function resolveHex(map, colorId, fallback) {
  if (!colorId) return fallback;
  const entry = map.get(String(colorId));
  return entry?.hex || fallback;
}

function relativeLuminance(hex) {
  const raw = String(hex || '')
    .trim()
    .replace(/^#/, '');
  if (!/^[0-9a-fA-F]{3}$|^[0-9a-fA-F]{6}$/.test(raw)) return 0.5;
  const full =
    raw.length === 3
      ? raw
          .split('')
          .map((ch) => ch + ch)
          .join('')
      : raw;
  const toLin = (n) => {
    const c = n / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  const r = toLin(parseInt(full.slice(0, 2), 16));
  const g = toLin(parseInt(full.slice(2, 4), 16));
  const b = toLin(parseInt(full.slice(4, 6), 16));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function validateBrandKitData(data) {
  if (!data || typeof data !== 'object') {
    throw new AppError('Brand kit data is required', 400);
  }
  const map = colorMap(data);
  const roles = data.colorRoles || {};
  for (const key of ['bg', 'text', 'primary']) {
    if (!roles[key] || !map.has(String(roles[key]))) {
      throw new AppError(`colorRoles.${key} must reference a color id`, 400);
    }
  }
  for (const key of ['secondary', 'accent', 'muted']) {
    if (roles[key] && !map.has(String(roles[key]))) {
      throw new AppError(`colorRoles.${key} must reference a color id`, 400);
    }
  }
  if (Array.isArray(data.chartStyles?.colorIds)) {
    for (const id of data.chartStyles.colorIds) {
      if (!map.has(String(id))) {
        throw new AppError(`chartStyles.colorIds contains unknown id: ${id}`, 400);
      }
    }
  }
}

/**
 * Map a brand kit (+ media) to presentation themeTokens.
 */
function brandKitToThemeTokens(kit, { includeMediaUrls = true } = {}) {
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  validateBrandKitData(kit.data);

  const data = kit.data;
  const map = colorMap(data);
  const roles = data.colorRoles || {};
  const palette = {
    bg: resolveHex(map, roles.bg, '#FFFFFF'),
    text: resolveHex(map, roles.text, '#0F172A'),
    primary: resolveHex(map, roles.primary, '#2563EB'),
    secondary: resolveHex(map, roles.secondary || roles.primary, '#0EA5E9'),
    surface: resolveHex(map, roles.accent || roles.secondary || roles.bg, '#F8FAFC'),
    muted: resolveHex(map, roles.muted || roles.text, '#64748B'),
    accent: resolveHex(map, roles.accent || roles.primary, '#3B82F6'),
    divider: 'rgba(0,0,0,0.1)',
    cardBg: 'rgba(0,0,0,0.04)',
    gradientStart: resolveHex(map, roles.bg, '#FFFFFF'),
    gradientEnd: resolveHex(map, roles.accent || roles.secondary || roles.bg, '#F8FAFC'),
    shadow: 'rgba(0,0,0,0.12)',
  };

  themeService.assertContrast(palette);

  const chartColors = (data.chartStyles?.colorIds || [])
    .map((id) => resolveHex(map, id, null))
    .filter(Boolean);

  const logos = {};
  const photos = [];
  const graphics = [];

  for (const m of kit.media || []) {
    const url = includeMediaUrls && m.s3Key ? s3Service.buildPublicUrl(m.s3Key) : null;
    const entry = {
      id: m.id,
      role: m.role || null,
      name: m.name || null,
      s3Key: m.s3Key,
      assetId: m.assetId || null,
      mimeType: m.mimeType || null,
      url,
    };
    if (m.kind === 'logo' && m.role) {
      logos[m.role] = entry;
    } else if (m.kind === 'photo') {
      photos.push(entry);
    } else if (m.kind === 'graphic') {
      graphics.push(entry);
    }
  }

  const heading = data.fonts?.heading || {};
  const body = data.fonts?.body || {};

  return {
    palette,
    fontPairingId: heading.fontPairingId || body.fontPairingId || 'inter_space',
    fonts: {
      heading: heading.family || null,
      body: body.family || null,
      tertiary: data.fonts?.tertiary?.family || null,
      headingWeight: 700,
      bodyWeight: 400,
    },
    typeScale: { display: 56, title: 44, subtitle: 28, body: 18, caption: 14, stat: 64 },
    scaleRatio: 1.333,
    spacingScale: { xs: 4, sm: 8, md: 16, lg: 24 },
    imageStyle: data.imageStyle || 'brand-safe professional photography, no text overlay',
    colorTreatment: `brand primary ${palette.primary}`,
    brand: {
      brandKitId: kit.id,
      name: kit.name,
      voice: data.voice || null,
      chartColors,
      logos,
      photos,
      graphics,
      namedColors: data.colors || [],
    },
  };
}

function pickLogoForBackground(themeTokens) {
  const logos = themeTokens?.brand?.logos || {};
  const bg = themeTokens?.palette?.bg || '#FFFFFF';
  const darkBg = relativeLuminance(bg) < 0.45;
  if (darkBg && logos.light) return logos.light;
  if (!darkBg && logos.dark) return logos.dark;
  return logos.primary || logos.secondary || logos.icon || logos.light || logos.dark || null;
}

function buildBrandVoiceBrief(themeTokens) {
  const voice = themeTokens?.brand?.voice;
  if (!voice || typeof voice !== 'object') return '';
  const parts = [];
  if (voice.tone) parts.push(`Brand voice tone: ${voice.tone}`);
  if (voice.audience) parts.push(`Brand audience: ${voice.audience}`);
  if (Array.isArray(voice.dos) && voice.dos.length) {
    parts.push(`Brand dos: ${voice.dos.join('; ')}`);
  }
  if (Array.isArray(voice.donts) && voice.donts.length) {
    parts.push(`Brand don'ts: ${voice.donts.join('; ')}`);
  }
  if (Array.isArray(voice.vocabulary) && voice.vocabulary.length) {
    parts.push(`Preferred vocabulary: ${voice.vocabulary.join(', ')}`);
  }
  return parts.join('\n');
}

async function attachPresignedMedia(kit) {
  if (!kit) return kit;
  const media = await Promise.all(
    (kit.media || []).map(async (m) => {
      let url = null;
      try {
        url = await s3Service.getPresignedGetUrl(m.s3Key, 3600);
      } catch {
        url = s3Service.buildPublicUrl(m.s3Key);
      }
      return { ...m, url };
    })
  );
  return { ...kit, media };
}

function serializeKitSummary(kit) {
  return {
    id: kit.id,
    workspaceId: kit.workspaceId,
    name: kit.name,
    isDefault: kit.isDefault,
    data: kit.data,
    mediaCount: kit._count?.media ?? (kit.media || []).length,
    createdBy: kit.createdBy,
    createdAt: kit.createdAt,
    updatedAt: kit.updatedAt,
  };
}

async function listBrandKits(workspaceId) {
  const kits = await brandKitDao.listByWorkspace(workspaceId);
  return kits.map(serializeKitSummary);
}

async function getBrandKit(workspaceId, brandKitId) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  return attachPresignedMedia(kit);
}

async function createBrandKit({ workspaceId, userId, name, data, isDefault }) {
  validateBrandKitData(data);
  // Ensure contrast via mapper
  brandKitToThemeTokens({ id: 'new', name, data, media: [] }, { includeMediaUrls: false });
  const kit = await brandKitDao.createKit({
    workspaceId,
    name,
    data,
    isDefault: Boolean(isDefault),
    createdBy: userId,
  });
  return attachPresignedMedia(kit);
}

async function updateBrandKit({ workspaceId, brandKitId, name, data, isDefault }) {
  if (data) {
    validateBrandKitData(data);
    brandKitToThemeTokens({ id: brandKitId, name: name || 'kit', data, media: [] }, {
      includeMediaUrls: false,
    });
  }
  const kit = await brandKitDao.updateKit({
    workspaceId,
    brandKitId,
    name,
    data,
    isDefault,
  });
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  return attachPresignedMedia(kit);
}

async function setDefaultBrandKit(workspaceId, brandKitId) {
  const kit = await brandKitDao.setDefault(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  return attachPresignedMedia(kit);
}

async function deleteBrandKit(workspaceId, brandKitId) {
  const kit = await brandKitDao.deleteKit(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  for (const m of kit.media || []) {
    try {
      await s3Service.deleteFile(m.s3Key);
    } catch {
      // best-effort
    }
  }
  return { id: brandKitId, deleted: true };
}

async function uploadMedia({
  workspaceId,
  brandKitId,
  file,
  kind,
  role,
  name,
}) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  if (!file?.buffer) throw new AppError(messages.INVALID_FILE_TYPE, 400);
  if (!IMAGE_MIME.has(file.mimetype)) {
    throw new AppError(messages.INVALID_IMAGE_TYPE, 400);
  }

  const mediaKind = String(kind || '').toLowerCase();
  if (!['logo', 'photo', 'graphic'].includes(mediaKind)) {
    throw new AppError('kind must be logo, photo, or graphic', 400);
  }

  let mediaRole = role ? String(role).toLowerCase() : null;
  if (mediaKind === 'logo') {
    if (!mediaRole || !LOGO_ROLES.has(mediaRole)) {
      throw new AppError('logo uploads require role: primary|secondary|icon|light|dark', 400);
    }
  } else {
    mediaRole = null;
  }

  const uploaded = await s3Service.uploadFile(
    file.buffer,
    'workspace',
    workspaceId,
    `brand-kits/${brandKitId}/${mediaKind}`,
    file.originalname || `${mediaKind}.png`,
    file.mimetype
  );

  const sortOrder = (await brandKitDao.maxSortOrder(brandKitId, mediaKind)) + 1;
  const media = await brandKitDao.createMedia({
    brandKitId,
    kind: mediaKind,
    role: mediaRole,
    name: name || file.originalname || null,
    assetId: null,
    s3Key: uploaded.key,
    mimeType: file.mimetype,
    sortOrder,
  });

  let url = uploaded.url;
  try {
    url = await s3Service.getPresignedGetUrl(media.s3Key, 3600);
  } catch {
    // keep public url
  }

  return { ...media, url };
}

async function deleteMedia({ workspaceId, brandKitId, mediaId }) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  const media = await brandKitDao.findMedia(brandKitId, mediaId);
  if (!media) throw new AppError(messages.BRAND_KIT_MEDIA_NOT_FOUND, 404);
  await brandKitDao.deleteMedia(mediaId);
  try {
    await s3Service.deleteFile(media.s3Key);
  } catch {
    // best-effort
  }
  return { id: mediaId, deleted: true };
}

async function loadKitThemeTokens(workspaceId, brandKitId) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  return brandKitToThemeTokens(kit);
}

module.exports = {
  listBrandKits,
  getBrandKit,
  createBrandKit,
  updateBrandKit,
  setDefaultBrandKit,
  deleteBrandKit,
  uploadMedia,
  deleteMedia,
  brandKitToThemeTokens,
  pickLogoForBackground,
  buildBrandVoiceBrief,
  loadKitThemeTokens,
  validateBrandKitData,
  relativeLuminance,
};
