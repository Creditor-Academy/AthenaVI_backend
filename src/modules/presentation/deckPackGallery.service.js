const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const presentationDao = require('./presentation.dao');
const templateMediaService = require('../templates/templateMedia.service');

function pickPreviewImageUrl(media, { slideOrder } = {}) {
  const rows = Array.isArray(media) ? media : [];
  if (slideOrder != null) {
    const hint = templateMediaService.slotHintForSlideOrder(slideOrder);
    const slideMedia =
      rows.find((m) => m.slotHint === hint) ||
      rows.find((m) => String(m.slotHint || '').startsWith(`${hint}:`)) ||
      null;
    if (slideMedia?.url) return slideMedia.url;
  }
  const previewMedia =
    rows.find((m) => m.kind === 'preview') ||
    rows.find((m) => m.slotHint === 'preview') ||
    rows.find((m) => String(m.slotHint || '').startsWith('slide:1')) ||
    rows[0] ||
    null;
  return previewMedia?.url || null;
}

function hydrateValueWithMediaUrls(value, keyMap) {
  if (value == null) return value;
  if (Array.isArray(value)) {
    return value.map((item) => hydrateValueWithMediaUrls(item, keyMap));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if ((k === 's3Key' || k === 'key') && typeof v === 'string' && keyMap.has(v)) {
        const mapped = keyMap.get(v);
        out[k] = mapped.s3Key;
        if (mapped.url) {
          out.url = mapped.url;
        }
      } else if (k === 'url' && typeof v === 'string') {
        out[k] = v;
      } else {
        out[k] = hydrateValueWithMediaUrls(v, keyMap);
      }
    }
    if (typeof out.s3Key === 'string' && keyMap.has(out.s3Key) && keyMap.get(out.s3Key).url) {
      out.url = keyMap.get(out.s3Key).url;
    }
    return out;
  }
  return value;
}

async function hydrateDeckPackSchema(schema, mediaRows) {
  if (!schema || typeof schema !== 'object') return schema;
  const keyMap = new Map();
  for (const m of mediaRows || []) {
    if (!m?.s3Key) continue;
    const url = m.url || (await templateMediaService.resolveMediaUrl(m.s3Key));
    keyMap.set(m.s3Key, { s3Key: m.s3Key, url });
  }
  if (!keyMap.size) return schema;
  return hydrateValueWithMediaUrls(schema, keyMap);
}

function buildSlidePreviews(pack) {
  const slides = Array.isArray(pack.schema?.slides) ? pack.schema.slides : [];
  const media = pack.media || [];
  return slides.map((slide) => ({
    order: slide.order,
    contentType: slide.contentType || null,
    title:
      (slide.placeholder && typeof slide.placeholder.title === 'string'
        ? slide.placeholder.title.trim()
        : '') || null,
    previewImageUrl: pickPreviewImageUrl(media, { slideOrder: slide.order }),
    layoutId: slide.layout_id || null,
  }));
}

function formatDeckPackSummary(pack) {
  if (!pack) return pack;
  const previewImageUrl = pickPreviewImageUrl(pack.media);
  const basePreview =
    pack.schema?.preview && typeof pack.schema.preview === 'object'
      ? { ...pack.schema.preview }
      : {};
  return {
    id: pack.id,
    name: pack.name,
    packId: pack.schema?.pack_id || pack.id,
    themeId: pack.schema?.themeId || null,
    aspectRatio: pack.schema?.aspectRatio || '16:9',
    slideCount: Array.isArray(pack.schema?.slides) ? pack.schema.slides.length : 0,
    meta: pack.schema?.meta || null,
    narrative: pack.schema?.narrative || null,
    preview: {
      ...basePreview,
      imageUrl: previewImageUrl,
      thumbnailUrl: previewImageUrl,
    },
    previewImageUrl,
    thumbnailUrl: previewImageUrl,
    media: pack.media || [],
    generationDefaults: pack.schema?.generationDefaults || null,
    variant: pack.variant,
    version: pack.version,
  };
}

async function formatDeckPackDetail(pack) {
  const summary = formatDeckPackSummary(pack);
  const hydratedSchema = await hydrateDeckPackSchema(pack.schema, pack.media);
  const packWithHydratedSchema = { ...pack, schema: hydratedSchema };
  return {
    ...summary,
    schema: hydratedSchema,
    slidePreviews: buildSlidePreviews(packWithHydratedSchema),
  };
}

async function listActiveDeckPacks() {
  const packs = await presentationDao.findActiveDeckPacks();
  const withMedia = await templateMediaService.withMediaAttachedMany(packs);
  return withMedia.map(formatDeckPackSummary);
}

async function getActiveDeckPack(packId) {
  const pack = await prisma.template.findFirst({
    where: { id: packId, type: 'DECK_PACK', isActive: true },
  });
  if (!pack) {
    throw new AppError(messages.PRESENTATION_DECK_PACK_NOT_FOUND, 404);
  }
  const withMedia = await templateMediaService.withMediaAttached(pack);
  return formatDeckPackDetail(withMedia);
}

module.exports = {
  pickPreviewImageUrl,
  hydrateDeckPackSchema,
  formatDeckPackSummary,
  formatDeckPackDetail,
  buildSlidePreviews,
  listActiveDeckPacks,
  getActiveDeckPack,
};
