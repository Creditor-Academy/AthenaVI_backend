const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const s3Service = require('../s3/s3.service');
const themeService = require('../presentation/theme.service');
const brandKitDao = require('./brandKit.dao');

const LOGO_ROLES = new Set([
  'primary',
  'secondary',
  'icon',
  'light',
  'dark',
  'main',
  'light-mode',
  'dark-mode',
  'with-name-below',
  'with-name-adjacent',
  'with-name-below-dark',
  'with-name-adjacent-dark',
  'black',
  'white',
]);
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

function resolveWordmarkTextHex(data, mode = 'light') {
  return resolveFontRoleTextHex(data, 'heading', mode);
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

function buildPaletteFromRoles(map, roles, prefix = '') {
  const bgKey = prefix ? `bg${prefix}` : 'bg';
  const textKey = prefix ? `text${prefix}` : 'text';
  const primaryKey = prefix ? `primary${prefix}` : 'primary';

  const bgRole = roles[bgKey] || roles.bg;
  const textRole = roles[textKey] || roles.text;
  const primaryRole = roles[primaryKey] || roles.primary;

  return {
    bg: resolveHex(map, bgRole, prefix ? '#1B1110' : '#FFFFFF'),
    text: resolveHex(map, textRole, prefix ? '#F7F3F3' : '#0F172A'),
    primary: resolveHex(map, primaryRole, '#2563EB'),
    secondary: resolveHex(map, roles.secondary || primaryRole, '#0EA5E9'),
    surface: resolveHex(map, roles.accent || roles.secondary || bgRole, '#F8FAFC'),
    muted: resolveHex(map, roles.muted || textRole, '#64748B'),
    accent: resolveHex(map, roles.accent || primaryRole, '#3B82F6'),
    divider: prefix ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.1)',
    cardBg: prefix ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.04)',
    gradientStart: resolveHex(map, bgRole, prefix ? '#1B1110' : '#FFFFFF'),
    gradientEnd: resolveHex(
      map,
      roles.accent || roles.secondary || bgRole,
      prefix ? '#121A2B' : '#F8FAFC'
    ),
    shadow: prefix ? 'rgba(0,0,0,0.4)' : 'rgba(0,0,0,0.12)',
  };
}

function contrastInkForHex(hex) {
  return relativeLuminance(hex) > 0.55 ? '#0F172A' : '#FFFFFF';
}

function resolveOneButtonToken(style = {}, map, roles, kind = 'primary') {
  const primaryId = roles.primary;
  const bgId = roles.bg;
  const textId = roles.text;
  const defaults =
    kind === 'secondary'
      ? {
          label: 'Secondary',
          backgroundColorId: bgId,
          textColorId: primaryId,
          borderColorId: primaryId,
          borderWidthPx: 1,
          borderRadiusPx: 10,
          paddingXPx: 20,
          paddingYPx: 10,
          fontWeight: 600,
          fontSizePx: 14,
        }
      : {
          label: 'Primary',
          backgroundColorId: primaryId,
          textColorId: null,
          borderColorId: null,
          borderWidthPx: 0,
          borderRadiusPx: 10,
          paddingXPx: 20,
          paddingYPx: 10,
          fontWeight: 600,
          fontSizePx: 14,
        };

  const merged = { ...defaults, ...(style || {}) };
  const background = resolveHex(
    map,
    merged.backgroundColorId,
    kind === 'secondary' ? '#F8FAFC' : '#2563EB'
  );
  const text = resolveHex(
    map,
    merged.textColorId,
    kind === 'secondary' ? resolveHex(map, primaryId, '#2563EB') : contrastInkForHex(background)
  );
  const border = resolveHex(
    map,
    merged.borderColorId,
    kind === 'secondary' ? resolveHex(map, primaryId, '#2563EB') : background
  );

  return {
    label: merged.label || defaults.label,
    background,
    text,
    border,
    borderWidthPx: Number(merged.borderWidthPx) || 0,
    borderRadiusPx: Number(merged.borderRadiusPx) || 0,
    paddingXPx: Number(merged.paddingXPx) || 16,
    paddingYPx: Number(merged.paddingYPx) || 10,
    fontWeight: Number(merged.fontWeight) || 600,
    fontSizePx: Number(merged.fontSizePx) || 14,
    backgroundColorId: merged.backgroundColorId || null,
    textColorId: merged.textColorId || null,
    borderColorId: merged.borderColorId || null,
  };
}

function resolveButtonTokens(data, map, roles) {
  const buttons = data?.buttons || {};
  return {
    primary: resolveOneButtonToken(buttons.primary, map, roles, 'primary'),
    secondary: resolveOneButtonToken(buttons.secondary, map, roles, 'secondary'),
  };
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
  for (const key of [
    'secondary',
    'accent',
    'muted',
    'bgDark',
    'textDark',
    'primaryDark',
  ]) {
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
  for (const kind of ['primary', 'secondary']) {
    const style = data.buttons?.[kind];
    if (!style || typeof style !== 'object') continue;
    for (const key of ['backgroundColorId', 'textColorId', 'borderColorId']) {
      const id = style[key];
      if (id && !map.has(String(id))) {
        throw new AppError(`buttons.${kind}.${key} must reference a color id`, 400);
      }
    }
  }
  const seenColorIds = new Set();
  for (const c of data.colors || []) {
    const id = String(c?.id || '');
    if (!id) continue;
    if (seenColorIds.has(id)) {
      throw new AppError(`Duplicate color id: ${id}`, 400);
    }
    seenColorIds.add(id);
  }
}

function buildTypeScale(fonts = {}) {
  const heading = fonts.heading || {};
  const subheading = fonts.subheading || {};
  const body = fonts.body || {};
  return {
    display: heading.sizePx ? Math.round(heading.sizePx * 1.4) : 56,
    title: heading.sizePx || 44,
    subtitle: subheading.sizePx || 28,
    body: body.sizePx || 18,
    caption: body.sizePx ? Math.round(body.sizePx * 0.85) : 14,
    stat: heading.sizePx ? Math.round(heading.sizePx * 1.5) : 64,
  };
}

function resolveFontRoleTextHex(data, roleKey, mode = 'light') {
  const map = colorMap(data);
  const colorRoles = data?.colorRoles || {};
  const face = data?.fonts?.[roleKey] || {};
  const isDark = String(mode).toLowerCase() === 'dark';
  const colorId = isDark
    ? face.darkTextColorId || colorRoles.textDark || colorRoles.text
    : face.lightTextColorId || colorRoles.text;
  return resolveHex(map, colorId, isDark ? '#F8FAFC' : '#0F172A');
}

function buildTypographyColors(data = {}) {
  const roles = ['heading', 'subheading', 'body'];
  const out = {};
  for (const roleKey of roles) {
    out[roleKey] = {
      light: resolveFontRoleTextHex(data, roleKey, 'light'),
      dark: resolveFontRoleTextHex(data, roleKey, 'dark'),
    };
  }
  return out;
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
  const palette = buildPaletteFromRoles(map, roles);

  themeService.assertContrast(palette);

  let paletteDark = null;
  if (roles.bgDark || roles.textDark || roles.primaryDark) {
    paletteDark = buildPaletteFromRoles(map, roles, 'Dark');
    try {
      themeService.assertContrast(paletteDark);
    } catch {
      // dark pair optional — do not block kit save if incomplete
    }
  }

  const chartColors = (data.chartStyles?.colorIds || [])
    .map((id) => resolveHex(map, id, null))
    .filter(Boolean);

  const logos = {};
  const photos = [];
  const graphics = [];

  for (const m of kit.media || []) {
    const url =
      includeMediaUrls && m.s3Key
        ? m.url || s3Service.buildPublicUrl(m.s3Key)
        : includeMediaUrls && m.url
          ? m.url
          : null;
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
  const subheading = data.fonts?.subheading || {};
  const body = data.fonts?.body || {};

  const tokens = {
    palette,
    fontSource: 'brand_kit',
    fontPairingId: heading.fontPairingId || body.fontPairingId || 'inter_space',
    fonts: {
      heading: heading.family || null,
      subheading: subheading.family || null,
      body: body.family || null,
      tertiary: data.fonts?.tertiary?.family || null,
      headingWeight: heading.weight ?? 700,
      subheadingWeight: subheading.weight ?? 600,
      bodyWeight: body.weight ?? 400,
      headingLineHeight: heading.lineHeight ?? 1.2,
      subheadingLineHeight: subheading.lineHeight ?? 1.4,
      bodyLineHeight: body.lineHeight ?? 1.6,
    },
    typeScale: buildTypeScale(data.fonts),
    typographyColors: buildTypographyColors(data),
    buttons: resolveButtonTokens(data, map, roles),
    scaleRatio: 1.333,
    spacingScale: { xs: 4, sm: 8, md: 16, lg: 24 },
    imageStyle: data.imageStyle || 'brand-safe professional photography, no text overlay',
    colorTreatment: null,
    brand: {
      brandKitId: kit.id,
      name: kit.name,
      tagline: data.meta?.tagline || null,
      voice: data.voice || null,
      usage: data.usage || null,
      chartColors,
      logos,
      photos,
      graphics,
      namedColors: data.colors || [],
      buttons: data.buttons || null,
    },
  };

  if (paletteDark) {
    tokens.paletteDark = paletteDark;
  }

  return tokens;
}

/**
 * Merge brand kit tokens into wizard/catalog theme tokens (Brand Kit + Color Theme mode).
 * Kit supplies palette, fonts, logo, voice; wizard theme accents can remain as secondary palette hints.
 */
function mergeBrandKitWithThemeTokens(wizardTokens, kitTokens) {
  if (!kitTokens) return wizardTokens || {};
  if (!wizardTokens || typeof wizardTokens !== 'object') return kitTokens;

  const merged = {
    ...wizardTokens,
    ...kitTokens,
    palette: {
      ...(wizardTokens.palette || {}),
      ...(kitTokens.palette || {}),
    },
    fonts: {
      ...(wizardTokens.fonts || {}),
      ...(kitTokens.fonts || {}),
    },
    buttons: kitTokens.buttons || wizardTokens.buttons,
    typeScale: kitTokens.typeScale || wizardTokens.typeScale,
    brand: kitTokens.brand || wizardTokens.brand,
    imageStyle: kitTokens.imageStyle || wizardTokens.imageStyle,
    colorTreatment: wizardTokens.colorTreatment ?? kitTokens.colorTreatment ?? null,
  };

  if (kitTokens.paletteDark) merged.paletteDark = kitTokens.paletteDark;
  return merged;
}

function pickLogoForBackground(themeTokens) {
  const logos = themeTokens?.brand?.logos || {};
  const bg = themeTokens?.palette?.bg || '#FFFFFF';
  const darkBg = relativeLuminance(bg) < 0.45;
  if (darkBg && (logos.light || logos['light-mode'])) {
    return logos.light || logos['light-mode'];
  }
  if (!darkBg && (logos.dark || logos['dark-mode'])) {
    return logos.dark || logos['dark-mode'];
  }
  if (darkBg && logos.white) return logos.white;
  if (!darkBg && logos.black) return logos.black;
  return (
    logos.primary ||
    logos.secondary ||
    logos.icon ||
    logos.light ||
    logos.dark ||
    null
  );
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

async function resolveBrandKitId(workspaceId, brandKitId) {
  if (brandKitId) return String(brandKitId).trim();
  const defaultKit = await brandKitDao.findDefaultByWorkspace(workspaceId);
  return defaultKit?.id || null;
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
  if (!['logo', 'photo', 'graphic', 'mockup'].includes(mediaKind)) {
    throw new AppError('kind must be logo, photo, graphic, or mockup', 400);
  }

  let mediaRole = role ? String(role).toLowerCase() : null;
  if (mediaKind === 'logo') {
    if (!mediaRole || !LOGO_ROLES.has(mediaRole)) {
      throw new AppError('logo uploads require a valid role', 400);
    }
    const existingRows = await brandKitDao.findAllMediaByKindRole(brandKitId, mediaKind, mediaRole);
    for (const existing of existingRows) {
      await brandKitDao.deleteMedia(existing.id);
      try {
        await s3Service.deleteFile(existing.s3Key);
      } catch {
        // best-effort
      }
    }
  } else if (mediaKind === 'mockup') {
    const { getTemplate } = require('./brandKit.mockupCatalog');
    if (!mediaRole || !getTemplate(mediaRole)) {
      throw new AppError('mockup uploads require a valid template role', 400);
    }
    const existingRows = await brandKitDao.findAllMediaByKindRole(brandKitId, mediaKind, mediaRole);
    for (const existing of existingRows) {
      await brandKitDao.deleteMedia(existing.id);
      try {
        await s3Service.deleteFile(existing.s3Key);
      } catch {
        // best-effort
      }
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
  const kitWithUrls = await attachPresignedMedia(kit);
  return brandKitToThemeTokens(kitWithUrls);
}

async function loadKitThemeTokensResolved(workspaceId, brandKitId) {
  const resolvedId = await resolveBrandKitId(workspaceId, brandKitId);
  if (!resolvedId) return { themeTokens: null, brandKitId: null };
  const themeTokens = await loadKitThemeTokens(workspaceId, resolvedId);
  return { themeTokens, brandKitId: resolvedId };
}

async function streamMedia({ workspaceId, brandKitId, mediaId, req, res }) {
  const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
  if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
  const media = await brandKitDao.findMedia(brandKitId, mediaId);
  if (!media || !media.s3Key) throw new AppError(messages.BRAND_KIT_MEDIA_NOT_FOUND, 404);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  return s3Service.streamObjectToResponse(req, res, media.s3Key);
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
  streamMedia,
  loadKitThemeTokens,
  loadKitThemeTokensResolved,
  resolveBrandKitId,
  brandKitToThemeTokens,
  mergeBrandKitWithThemeTokens,
  pickLogoForBackground,
  buildBrandVoiceBrief,
  validateBrandKitData,
  relativeLuminance,
  colorMap,
  resolveHex,
  resolveWordmarkTextHex,
  buildPaletteFromRoles,
  buildTypeScale,
  buildTypographyColors,
  resolveFontRoleTextHex,
  LOGO_ROLES,
  IMAGE_MIME,
};
