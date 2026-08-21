const zlib = require('zlib');
const wizardColorThemes = require('./wizardColorThemes.json');
const s3Service = require('../s3/s3.service');
const { CANVAS_WIDTH, CANVAS_HEIGHT } = require('./presentation.constants');
const layoutCatalogPolicy = require('./layoutCatalogPolicy');

const PLACEHOLDER_S3_KEY = 'presentations/_system/placeholder-image.png';
const PLACEHOLDER_VARIANT_COLORS = [
  [180, 186, 194],
  [168, 178, 190],
  [190, 184, 176],
  [176, 190, 186],
  [186, 176, 190],
  [172, 182, 198],
  [198, 182, 172],
  [182, 190, 176],
];

const IMAGE_STYLE_PHRASES = {
  scene: 'cinematic environmental scene photography',
  photo: 'realistic professional photography',
  'still-life': 'still-life product photography, clean studio light',
  'spot-color': 'spot-color graphic treatment, selective color',
  illustration: 'modern flat illustration, clean shapes',
  'flat-line': 'flat line-art illustration',
  'modern-art': 'modern abstract art composition',
  isometric: 'isometric 3D illustration',
  gouache: 'gouache painted illustration',
  'bold-poster': 'bold poster graphic design',
  watercolor: 'soft watercolor illustration',
  bauhaus: 'bauhaus geometric design',
  '3d': 'polished 3D render',
  'neon-glow': 'neon glow futuristic visual',
  cinematic: 'cinematic dramatic photography',
  mesh: 'gradient mesh abstract background',
};

const CANVAS_BY_ASPECT = {
  '16:9': { aspectRatio: '16:9', width: 1920, height: 1080 },
  '4:3': { aspectRatio: '4:3', width: 1600, height: 1200 },
};

const BASE_TEMPLATE_BIAS = {
  'corp-pitch': {
    preferredContentTypes: ['title', 'stat', 'image+text', 'bullet_list', 'closing'],
    preferImageSlot: true,
  },
  marketing: {
    preferredContentTypes: ['image+text', 'stat', 'comparison', 'closing'],
    preferImageSlot: true,
  },
  social: {
    preferredContentTypes: ['image+text', 'quote', 'stat', 'title'],
    preferImageSlot: true,
  },
  portfolio: {
    preferredContentTypes: ['image+text', 'team', 'timeline', 'closing'],
    preferImageSlot: true,
  },
};

let placeholderCache = null;
const placeholderVariantCache = new Map();

function normalizeGenerationFlow(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const selections =
    raw.selections && typeof raw.selections === 'object' ? { ...raw.selections } : {};
  return {
    version: Number(raw.version) > 0 ? Number(raw.version) : 1,
    source: raw.source != null ? String(raw.source) : 'ai_ppt_wizard',
    selections,
    availableOptions:
      raw.availableOptions && typeof raw.availableOptions === 'object'
        ? raw.availableOptions
        : undefined,
  };
}

function mapTextContentToDensity(textContent) {
  const t = String(textContent || '')
    .trim()
    .toLowerCase();
  if (t === 'minimal' || t === 'concise') return 'concise';
  if (t === 'detailed' || t === 'extensive') return 'detailed';
  return null;
}

function resolveImageStylePhrase(imageStyle, imageStyleFilter) {
  const id = String(imageStyle || '')
    .trim()
    .toLowerCase();
  const filter = String(imageStyleFilter || '')
    .trim()
    .toLowerCase();
  const base = IMAGE_STYLE_PHRASES[id] || (id ? `${id} visual style` : '');
  if (!filter || filter === 'suggested') return base || 'professional presentation photography';
  if (filter === 'photo') return `${base || 'photography'}, photorealistic`;
  if (filter === 'illustration') return `${base || 'illustration'}, illustrated, non-photographic`;
  if (filter === 'abstract') return `${base || 'abstract'}, abstract geometric forms`;
  return base || 'professional presentation photography';
}

function normalizeWizardThemeId(colorTheme) {
  const id = String(colorTheme || '').trim();
  if (!id) return '';
  // FE PDF may send underscores; wizard catalog uses hyphens
  return id.replace(/_/g, '-');
}

function getWizardThemeById(colorTheme) {
  const id = normalizeWizardThemeId(colorTheme);
  if (!id) return null;
  return (
    wizardColorThemes.find((t) => t.id === id) ||
    wizardColorThemes.find((t) => t.id === String(colorTheme || '').trim()) ||
    null
  );
}

function resolveWizardThemeTokens(colorTheme, imageStyle, imageStyleFilter) {
  const theme = getWizardThemeById(colorTheme);
  if (!theme) return null;
  const stylePhrase = resolveImageStylePhrase(imageStyle, imageStyleFilter);
  return {
    palette: {
      bg: theme.background,
      surface: theme.backgroundSecondary || theme.background,
      cardBg: theme.backgroundSecondary || theme.background,
      primary: theme.primary,
      secondary: theme.secondary,
      text: theme.textPrimary,
      muted: theme.textSecondary,
      accent: theme.accent,
      border: theme.border,
      overlayScrim: 'rgba(0,0,0,0.5)',
      textOnImage: '#FFFFFF',
      textOnImageMuted: 'rgba(255,255,255,0.85)',
    },
    typeScale: { title: 42, subtitle: 26, body: 18 },
    spacingScale: { xs: 4, sm: 8, md: 16, lg: 24 },
    imageStyle: stylePhrase,
    colorTreatment: `${theme.vibe}; primary ${theme.primary}, accent ${theme.accent}`,
    wizardColorThemeId: theme.id,
  };
}

function buildWizardBrief(selections = {}) {
  const s = selections || {};
  const parts = [];
  if (s.voiceAndTone) parts.push(`Voice & tone: ${s.voiceAndTone}`);
  if (s.audience) parts.push(`Audience: ${s.audience}`);
  if (s.purpose) parts.push(`Purpose: ${s.purpose}`);
  if (s.style) parts.push(`Visual style preference: ${s.style}`);
  if (s.color) parts.push(`Color preference: ${s.color}`);
  if (Array.isArray(s.industries) && s.industries.length) {
    parts.push(`Industries: ${s.industries.join(', ')}`);
  }
  if (s.outlineNotes) parts.push(`Outline notes: ${s.outlineNotes}`);
  if (s.baseTemplate) parts.push(`Base template vibe: ${s.baseTemplate}`);
  if (s.imageStyle) parts.push(`Image style: ${s.imageStyle}`);
  if (s.imageStyleFilter) parts.push(`Image style filter: ${s.imageStyleFilter}`);
  return parts.join('\n');
}

function resolveImageMode(imageType) {
  const t = String(imageType || 'ai')
    .trim()
    .toLowerCase();
  if (t === 'none') return { preferVisuals: false, imageSource: 'none' };
  if (t === 'placeholders' || t === 'placeholder') {
    return { preferVisuals: true, imageSource: 'placeholder' };
  }
  if (t === 'stock' || t === 'web') return { preferVisuals: true, imageSource: 'stock' };
  return { preferVisuals: true, imageSource: 'ai' };
}

function resolveCanvas(canvasSize) {
  const key = String(canvasSize || '16:9').trim();
  return CANVAS_BY_ASPECT[key] || {
    aspectRatio: '16:9',
    width: CANVAS_WIDTH,
    height: CANVAS_HEIGHT,
  };
}

function baseTemplateBias(baseTemplate) {
  const id = String(baseTemplate || '')
    .trim()
    .toLowerCase();
  return BASE_TEMPLATE_BIAS[id] || null;
}

/**
 * Minimal valid gray PNG (1x1 scaled conceptually — actual small solid).
 * Builds an uncompressed-then-zlib IDAT RGB PNG.
 */
function buildSolidGrayPng(width = 64, height = 64, rgb = [180, 186, 194]) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  function crc32(buf) {
    let c = 0xffffffff;
    for (let i = 0; i < buf.length; i += 1) {
      c ^= buf[i];
      for (let k = 0; k < 8; k += 1) {
        c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      }
    }
    const out = Buffer.alloc(4);
    out.writeUInt32BE((c ^ 0xffffffff) >>> 0, 0);
    return out;
  }

  function chunk(type, data) {
    const typeBuf = Buffer.from(type, 'ascii');
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length, 0);
    const crcInput = Buffer.concat([typeBuf, data]);
    return Buffer.concat([len, typeBuf, data, crc32(crcInput)]);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const row = Buffer.alloc(1 + width * 3);
  row[0] = 0;
  for (let x = 0; x < width; x += 1) {
    const o = 1 + x * 3;
    row[o] = rgb[0];
    row[o + 1] = rgb[1];
    row[o + 2] = rgb[2];
  }
  const raw = Buffer.concat(Array.from({ length: height }, () => row));
  const idat = zlib.deflateSync(raw);

  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function placeholderS3KeyForSlot(slotIndex) {
  const idx = Math.max(0, Number(slotIndex) || 0);
  if (idx === 0) return PLACEHOLDER_S3_KEY;
  return `presentations/_system/placeholder-image-v${idx}.png`;
}

/**
 * System placeholder image. Pass slotIndex for distinct per-gallery-slot URLs
 * so multi-image dedupe does not wipe secondary cells.
 * @param {{ slotIndex?: number, seed?: string|number }} [opts]
 */
async function ensurePlaceholderImage(opts = {}) {
  const slotIndex = Math.max(0, Number(opts.slotIndex) || 0);
  if (slotIndex === 0 && !opts.seed) {
    if (placeholderCache) return { ...placeholderCache, source: 'placeholder' };
    try {
      await s3Service.headObjectMeta(PLACEHOLDER_S3_KEY);
      const url = s3Service.buildPublicUrl(PLACEHOLDER_S3_KEY);
      placeholderCache = { s3Key: PLACEHOLDER_S3_KEY, url };
      return { ...placeholderCache, source: 'placeholder' };
    } catch {
      // missing — upload
    }
    const buffer = buildSolidGrayPng(512, 512, PLACEHOLDER_VARIANT_COLORS[0]);
    const uploaded = await s3Service.uploadFileToKey(buffer, PLACEHOLDER_S3_KEY, 'image/png');
    placeholderCache = { s3Key: uploaded.key, url: uploaded.url };
    return { ...placeholderCache, source: 'placeholder' };
  }

  const cacheKey = opts.seed != null ? `seed:${opts.seed}` : `slot:${slotIndex}`;
  if (placeholderVariantCache.has(cacheKey)) {
    return { ...placeholderVariantCache.get(cacheKey), source: 'placeholder' };
  }

  const s3Key = opts.seed != null
    ? `presentations/_system/placeholder-image-${String(opts.seed).replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40) || 'x'}.png`
    : placeholderS3KeyForSlot(slotIndex);
  const color = PLACEHOLDER_VARIANT_COLORS[slotIndex % PLACEHOLDER_VARIANT_COLORS.length];

  try {
    await s3Service.headObjectMeta(s3Key);
    const url = s3Service.buildPublicUrl(s3Key);
    const entry = { s3Key, url };
    placeholderVariantCache.set(cacheKey, entry);
    return { ...entry, source: 'placeholder' };
  } catch {
    // missing — upload tinted variant
  }
  const buffer = buildSolidGrayPng(512, 512, color);
  const uploaded = await s3Service.uploadFileToKey(buffer, s3Key, 'image/png');
  const entry = { s3Key: uploaded.key, url: uploaded.url };
  placeholderVariantCache.set(cacheKey, entry);
  return { ...entry, source: 'placeholder' };
}

/**
 * Resolve wizard flow into generate/regenerate ctx fields.
 * @param {object|null} generationFlow
 * @param {{ topLevelDensity?: string }} opts
 */
function resolveFlowToGenerateCtx(generationFlow, opts = {}) {
  const flow = normalizeGenerationFlow(generationFlow);
  if (!flow) {
    return {
      generationFlow: null,
      density: opts.topLevelDensity || null,
      wizardBrief: '',
      imageSource: null,
      preferVisuals: null,
      imageStylePhrase: null,
      themeTokens: null,
      canvas: null,
      locale: null,
      title: null,
      userPrompt: null,
      baseTemplateBias: null,
      slideCountMeta: null,
      packId: null,
      brandKitId: null,
    };
  }

  const s = flow.selections || {};
  const fromText = mapTextContentToDensity(s.textContent);
  const density =
    opts.topLevelDensity ||
    (s.density && ['concise', 'balanced', 'detailed'].includes(s.density) ? s.density : null) ||
    fromText ||
    null;

  const imageMode = resolveImageMode(s.imageType || 'ai');
  const imageStylePhrase = resolveImageStylePhrase(s.imageStyle, s.imageStyleFilter);
  const themeMode = String(s.themeMode || '').toLowerCase();
  const useWizardPalette =
    themeMode === 'palette' || (!themeMode && !s.packId && !s.brandKitId && s.colorTheme);
  const themeTokens = useWizardPalette
    ? layoutCatalogPolicy.biasPaletteFromSourceText(
        resolveWizardThemeTokens(s.colorTheme, s.imageStyle, s.imageStyleFilter),
        s.prompt || s.outlineNotes || ''
      )
    : null;
  if (themeTokens && imageStylePhrase) {
    themeTokens.imageStyle = imageStylePhrase;
  }

  const canvas = s.canvasSize ? resolveCanvas(s.canvasSize) : null;
  const bias = baseTemplateBias(s.baseTemplate);

  return {
    generationFlow: flow,
    density,
    wizardBrief: buildWizardBrief(s),
    imageSource: imageMode.imageSource,
    preferVisuals: imageMode.preferVisuals,
    imageStylePhrase,
    themeTokens,
    themeMode: themeMode || (s.packId ? 'template' : s.brandKitId ? 'brand' : s.colorTheme ? 'palette' : null),
    canvas,
    locale: s.locale ? String(s.locale).trim() : null,
    title: s.title ? String(s.title).trim().slice(0, 255) : null,
    userPrompt: s.prompt ? String(s.prompt).trim() : null,
    baseTemplateBias: bias,
    slideCountMeta: s.slideCount != null ? Number(s.slideCount) : null,
    outlineNotes: s.outlineNotes ? String(s.outlineNotes).trim() : null,
    packId: s.packId ? String(s.packId).trim() : null,
    brandKitId: s.brandKitId ? String(s.brandKitId).trim() : null,
  };
}

module.exports = {
  PLACEHOLDER_S3_KEY,
  normalizeGenerationFlow,
  mapTextContentToDensity,
  resolveWizardThemeTokens,
  buildWizardBrief,
  resolveImageMode,
  resolveCanvas,
  baseTemplateBias,
  ensurePlaceholderImage,
  resolveFlowToGenerateCtx,
  resolveImageStylePhrase,
  getWizardThemeById,
  CANVAS_BY_ASPECT,
};
