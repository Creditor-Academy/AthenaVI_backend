const crypto = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { chatJson } = require('../../shared/services/ai/llm.service');
const { getOpenAI } = require('../../shared/services/ai/openai.client');
const { DEFAULT_SLIDE_MODEL } = require('../../shared/services/ai/llm.service');
const { moderateText } = require('../../shared/services/ai/moderation.service');
const s3Service = require('../s3/s3.service');
const themeService = require('../presentation/theme.service');
const brandKitDao = require('./brandKit.dao');
const brandKitCredit = require('./brandKitCredit.service');
const brandKitService = require('./brandKit.service');
const {
  COLORS_SUGGEST_SYSTEM,
  COLORS_SUGGEST_SCHEMA,
  FONTS_SUGGEST_SYSTEM,
  FONTS_SUGGEST_SCHEMA,
  FONT_PAIRING_CATALOG,
  VOICE_SUGGEST_SYSTEM,
  VOICE_SUGGEST_SCHEMA,
  IMAGE_STYLE_SUGGEST_SYSTEM,
  IMAGE_STYLE_SUGGEST_SCHEMA,
} = require('./brandKit.prompts');

function idempotencyKey(workspaceId, action, payload) {
  const hash = crypto
    .createHash('sha256')
    .update(JSON.stringify(payload || {}))
    .digest('hex')
    .slice(0, 16);
  return `brandKit:${action}:${workspaceId}:${hash}`;
}

async function loadLogoImageForVision({ workspaceId, brandKitId, mediaId, file }) {
  if (file?.buffer) {
    const mime = file.mimetype || 'image/png';
    const b64 = file.buffer.toString('base64');
    return {
      imagePart: {
        type: 'image_url',
        image_url: { url: `data:${mime};base64,${b64}` },
      },
    };
  }
  if (mediaId) {
    if (!brandKitId) throw new AppError('brandKitId is required when mediaId is provided', 400);
    const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
    if (!kit) throw new AppError(messages.BRAND_KIT_NOT_FOUND, 404);
    const media = await brandKitDao.findMedia(brandKitId, mediaId);
    if (!media?.s3Key) throw new AppError('Logo media not found', 404);
    const url = await s3Service.getPresignedGetUrl(media.s3Key, 3600);
    return { imagePart: { type: 'image_url', image_url: { url } } };
  }
  throw new AppError('Upload a logo file or provide mediaId', 400);
}

async function visionColorsFromLogo({ imagePart, tone, tagline }) {
  const openai = getOpenAI();
  const model = process.env.BRAND_KIT_VISION_MODEL || DEFAULT_SLIDE_MODEL;
  const userText = [
    tone ? `Brand tone: ${tone}` : null,
    tagline ? `Tagline: ${tagline}` : null,
    'Extract a complete brand palette with light and dark theme roles from this logo.',
  ]
    .filter(Boolean)
    .join('\n');

  const completion = await openai.chat.completions.create({
    model,
    temperature: 0.3,
    response_format: { type: 'json_object' },
    messages: [
      {
        role: 'system',
        content: `${COLORS_SUGGEST_SYSTEM}\n\nJSON shape hint:\n${JSON.stringify(COLORS_SUGGEST_SCHEMA)}`,
      },
      {
        role: 'user',
        content: [{ type: 'text', text: userText }, imagePart],
      },
    ],
  });

  const raw = completion?.choices?.[0]?.message?.content;
  if (!raw) throw new AppError('AI returned empty color suggestion', 502);
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new AppError('AI returned invalid color JSON', 502);
  }
  return { data, usage: completion?.usage || {} };
}

function validateSuggestedColors(data) {
  brandKitService.validateBrandKitData({
    colors: data.colors,
    colorRoles: data.colorRoles,
  });
  const palette = brandKitService.buildPaletteFromRoles(
    brandKitService.colorMap({ colors: data.colors }),
    data.colorRoles
  );
  themeService.assertContrast(palette);
  if (data.colorRoles.bgDark && data.colorRoles.textDark) {
    const darkPalette = brandKitService.buildPaletteFromRoles(
      brandKitService.colorMap({ colors: data.colors }),
      data.colorRoles,
      'Dark'
    );
    themeService.assertContrast(darkPalette);
  }
}

async function suggestColors({ workspaceId, userId, tone, tagline, brandKitId, mediaId, file }) {
  const payload = { tone, tagline, brandKitId, mediaId };
  const feature = brandKitCredit.BRAND_KIT_FEATURE.SUGGEST_COLORS;
  const estimatedAc = brandKitCredit.getFlatAc(feature);
  await brandKitCredit.assertAfford(workspaceId, userId, estimatedAc);

  if (tone) await moderateText(tone);
  if (tagline) await moderateText(tagline);

  const { imagePart } = await loadLogoImageForVision({
    workspaceId,
    brandKitId,
    mediaId,
    file,
  });
  const { data } = await visionColorsFromLogo({ imagePart, tone, tagline });
  validateSuggestedColors(data);

  await brandKitCredit.chargeFlat({
    workspaceId,
    userId,
    feature,
    idempotencyKey: idempotencyKey(workspaceId, 'suggest_colors', payload),
    metadata: { brandKitId: brandKitId || null, action: 'suggest_colors' },
  });

  return {
    colors: data.colors,
    colorRoles: data.colorRoles,
    rationale: data.rationale || '',
  };
}

async function suggestFonts({ workspaceId, userId, tone, primaryHex, brandKitId }) {
  const feature = brandKitCredit.BRAND_KIT_FEATURE.SUGGEST_FONTS;
  const estimatedAc = brandKitCredit.getFlatAc(feature);
  await brandKitCredit.assertAfford(workspaceId, userId, estimatedAc);

  if (tone) await moderateText(tone);

  let context = '';
  if (brandKitId) {
    const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
    if (kit) {
      context = `Brand name: ${kit.name}. Tagline: ${kit.data?.meta?.tagline || ''}.`;
    }
  }

  const { data } = await chatJson({
    system: FONTS_SUGGEST_SYSTEM,
    user: [
      context,
      tone ? `Tone: ${tone}` : null,
      primaryHex ? `Primary color: ${primaryHex}` : null,
      `Available pairings: ${FONT_PAIRING_CATALOG.map((p) => p.id).join(', ')}`,
    ]
      .filter(Boolean)
      .join('\n'),
    schemaHint: FONTS_SUGGEST_SCHEMA,
    temperature: 0.5,
  });

  await brandKitCredit.chargeFlat({
    workspaceId,
    userId,
    feature,
    idempotencyKey: idempotencyKey(workspaceId, 'suggest_fonts', { tone, primaryHex, brandKitId }),
    metadata: { brandKitId: brandKitId || null, action: 'suggest_fonts' },
  });

  return {
    fonts: data.fonts,
    rationale: data.rationale || '',
  };
}

async function suggestVoice({ workspaceId, userId, name, tagline, tone, brandKitId }) {
  const feature = brandKitCredit.BRAND_KIT_FEATURE.SUGGEST_VOICE;
  const estimatedAc = brandKitCredit.getFlatAc(feature);
  await brandKitCredit.assertAfford(workspaceId, userId, estimatedAc);

  await moderateText(`${name} ${tagline || ''} ${tone || ''}`);

  const { data } = await chatJson({
    system: VOICE_SUGGEST_SYSTEM,
    user: [`Brand name: ${name}`, tagline ? `Tagline: ${tagline}` : null, tone ? `Seed tone: ${tone}` : null]
      .filter(Boolean)
      .join('\n'),
    schemaHint: VOICE_SUGGEST_SCHEMA,
    temperature: 0.5,
  });

  await brandKitCredit.chargeFlat({
    workspaceId,
    userId,
    feature,
    idempotencyKey: idempotencyKey(workspaceId, 'suggest_voice', { name, tagline, tone, brandKitId }),
    metadata: { brandKitId: brandKitId || null, action: 'suggest_voice' },
  });

  return { voice: data.voice, rationale: data.rationale || '' };
}

async function suggestImageStyle({ workspaceId, userId, tone, colors, colorRoles, brandKitId }) {
  const feature = brandKitCredit.BRAND_KIT_FEATURE.SUGGEST_IMAGE_STYLE;
  const estimatedAc = brandKitCredit.getFlatAc(feature);
  await brandKitCredit.assertAfford(workspaceId, userId, estimatedAc);

  if (tone) await moderateText(tone);

  let paletteDesc = '';
  if (brandKitId && (!colors || !colorRoles)) {
    const kit = await brandKitDao.findInWorkspace(workspaceId, brandKitId);
    if (kit?.data) {
      colors = kit.data.colors;
      colorRoles = kit.data.colorRoles;
    }
  }
  if (Array.isArray(colors)) {
    paletteDesc = colors.map((c) => `${c.name || c.id}: ${c.hex}`).join(', ');
  }

  const { data } = await chatJson({
    system: IMAGE_STYLE_SUGGEST_SYSTEM,
    user: [
      tone ? `Tone: ${tone}` : null,
      paletteDesc ? `Palette: ${paletteDesc}` : null,
      colorRoles ? `Roles: ${JSON.stringify(colorRoles)}` : null,
    ]
      .filter(Boolean)
      .join('\n'),
    schemaHint: IMAGE_STYLE_SUGGEST_SCHEMA,
    temperature: 0.4,
  });

  if (Array.isArray(data.chartStyles?.colorIds)) {
    const colorSource = Array.isArray(colors) && colors.length ? colors : null;
    if (colorSource) {
      const map = brandKitService.colorMap({ colors: colorSource });
      for (const id of data.chartStyles.colorIds) {
        if (!map.has(String(id))) {
          throw new AppError(`Suggested chartStyles.colorIds contains unknown id: ${id}`, 502);
        }
      }
    }
  }

  await brandKitCredit.chargeFlat({
    workspaceId,
    userId,
    feature,
    idempotencyKey: idempotencyKey(workspaceId, 'suggest_image_style', {
      tone,
      brandKitId,
    }),
    metadata: { brandKitId: brandKitId || null, action: 'suggest_image_style' },
  });

  return {
    imageStyle: data.imageStyle,
    chartStyles: data.chartStyles || { colorIds: [] },
    rationale: data.rationale || '',
  };
}

module.exports = {
  suggestColors,
  suggestFonts,
  suggestVoice,
  suggestImageStyle,
};
