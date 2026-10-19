const { v4: uuidv4 } = require('uuid');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const { DEFAULT_VIDEO_SETTINGS } = require('../../shared/constants/videoEditor');
const {
  assertVideoSceneTemplateSchema,
  assertVideoPackTemplateSchema,
} = require('../validations/videoTemplate.validations');
const templateMediaService = require('../templates/templateMedia.service');

const VIDEO_SCENE = 'VIDEO_SCENE';
const VIDEO_PACK = 'VIDEO_PACK';
const VIDEO_TEMPLATE_TYPES = [VIDEO_SCENE, VIDEO_PACK];

function pickPreviewImageUrl(media) {
  const rows = Array.isArray(media) ? media : [];
  const previewMedia =
    rows.find((m) => m.kind === 'preview') ||
    rows.find((m) => m.slotHint === 'preview') ||
    rows.find((m) => String(m.slotHint || '').startsWith('scene:1')) ||
    rows.find((m) => String(m.slotHint || '').startsWith('slide:1')) ||
    rows[0] ||
    null;
  return previewMedia?.url || null;
}

function formatVideoTemplateForGallery(template) {
  if (!template) return template;
  const previewImageUrl = pickPreviewImageUrl(template.media);
  const basePreview =
    template.schema?.preview && typeof template.schema.preview === 'object'
      ? { ...template.schema.preview }
      : {};
  const isPack = template.type === VIDEO_PACK;
  const sceneCount = isPack
    ? Array.isArray(template.schema?.scenes)
      ? template.schema.scenes.length
      : 0
    : 1;

  return {
    id: template.id,
    name: template.name,
    type: template.type,
    contentType: template.contentType,
    variant: template.variant,
    version: template.version,
    isActive: template.isActive,
    schema: template.schema,
    packId: isPack ? template.schema?.pack_id || null : null,
    sceneCount: isPack ? sceneCount : basePreview.sceneCount || 1,
    meta: template.schema?.meta || null,
    preview: {
      ...basePreview,
      imageUrl: previewImageUrl,
      thumbnailUrl: previewImageUrl,
      ...(isPack && basePreview.sceneCount == null ? { sceneCount } : {}),
    },
    previewImageUrl,
    thumbnailUrl: previewImageUrl,
    media: template.media || [],
    createdAt: template.createdAt,
    updatedAt: template.updatedAt,
  };
}

/**
 * Refresh element urls from TemplateMedia (presigned) using s3Key matches.
 */
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
        // Prefer url rewritten when sibling s3Key is processed; keep as fallback
        out[k] = v;
      } else {
        out[k] = hydrateValueWithMediaUrls(v, keyMap);
      }
    }
    // If we have s3Key but url was left stale, force refresh
    if (typeof out.s3Key === 'string' && keyMap.has(out.s3Key) && keyMap.get(out.s3Key).url) {
      out.url = keyMap.get(out.s3Key).url;
    }
    return out;
  }
  return value;
}

async function hydrateVideoTemplateSchema(schema, mediaRows) {
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

async function listActiveVideoTemplates({ contentType, type } = {}) {
  const where = {
    isActive: true,
    type: type && VIDEO_TEMPLATE_TYPES.includes(type) ? type : { in: VIDEO_TEMPLATE_TYPES },
  };
  if (contentType) where.contentType = contentType;

  const templates = await prisma.template.findMany({
    where,
    orderBy: [{ type: 'asc' }, { contentType: 'asc' }, { name: 'asc' }, { version: 'desc' }],
  });
  const withMedia = await templateMediaService.withMediaAttachedMany(templates);
  return withMedia.map(formatVideoTemplateForGallery);
}

/** @deprecated Prefer listActiveVideoTemplates */
async function listActiveVideoSceneTemplates(opts = {}) {
  return listActiveVideoTemplates({ ...opts, type: VIDEO_SCENE });
}

async function getActiveVideoTemplate(templateId, { types = VIDEO_TEMPLATE_TYPES } = {}) {
  const template = await prisma.template.findFirst({
    where: {
      id: templateId,
      type: { in: types },
      isActive: true,
    },
  });
  if (!template) {
    throw new AppError(messages.VIDEO_TEMPLATE_NOT_FOUND, 404);
  }
  const withMedia = await templateMediaService.withMediaAttached(template);
  return formatVideoTemplateForGallery(withMedia);
}

async function getActiveVideoSceneTemplate(templateId) {
  return getActiveVideoTemplate(templateId, { types: [VIDEO_SCENE] });
}

async function getActiveVideoPackTemplate(templateId) {
  return getActiveVideoTemplate(templateId, { types: [VIDEO_PACK] });
}

/**
 * Expand VIDEO_SCENE template schema into an editor scene.
 */
function schemaToScene(schema, { templateId, sceneId, order } = {}) {
  const validated = assertVideoSceneTemplateSchema(schema);
  const blueprint = validated.scene;
  const id = sceneId || `scene_${uuidv4().replace(/-/g, '').slice(0, 12)}`;

  const elements = (blueprint.elements || []).map((el) => ({
    ...el,
    id: el.id || `el_${uuidv4().replace(/-/g, '').slice(0, 10)}`,
  }));

  return {
    sceneId: id,
    name: blueprint.name || 'Scene',
    order: order != null ? order : blueprint.order != null ? blueprint.order : 0,
    durationInFrames: blueprint.durationInFrames,
    locked: blueprint.locked === true,
    layout: blueprint.layout || undefined,
    templateId: templateId || undefined,
    background: blueprint.background,
    elements,
    ...(blueprint.presenter ? { presenter: blueprint.presenter } : {}),
    ...(blueprint.transition ? { transition: blueprint.transition } : {}),
  };
}

function packSchemaToScenes(schema, { templateId } = {}) {
  const validated = assertVideoPackTemplateSchema(schema);
  return (validated.scenes || []).map((blueprint, idx) => {
    const id = `scene_${uuidv4().replace(/-/g, '').slice(0, 12)}`;
    const elements = (blueprint.elements || []).map((el) => ({
      ...el,
      id: el.id || `el_${uuidv4().replace(/-/g, '').slice(0, 10)}`,
    }));
    return {
      sceneId: id,
      name: blueprint.name || `Scene ${idx + 1}`,
      order: blueprint.order != null ? blueprint.order : idx,
      durationInFrames: blueprint.durationInFrames,
      locked: blueprint.locked === true,
      layout: blueprint.layout || undefined,
      templateId: templateId || undefined,
      background: blueprint.background,
      elements,
      ...(blueprint.presenter ? { presenter: blueprint.presenter } : {}),
      ...(blueprint.transition ? { transition: blueprint.transition } : {}),
    };
  });
}

async function applyTemplateToNewProjectState({
  template,
  aspectRatio,
  canvasSize,
  customWidth,
  customHeight,
  tags,
  resolveVideoSettingsFromCanvas,
  buildProjectMeta,
  normalizeProjectState,
}) {
  const media = Array.isArray(template.media) ? template.media : [];
  const hydratedSchema = await hydrateVideoTemplateSchema(template.schema, media);

  if (template.type === VIDEO_PACK) {
    let schema;
    try {
      schema = assertVideoPackTemplateSchema(hydratedSchema);
    } catch (err) {
      throw new AppError(err.message || 'Invalid VIDEO_PACK template schema', 400);
    }

    const scenes = packSchemaToScenes(schema, { templateId: template.id });
    const videoSettings = resolveVideoSettingsFromCanvas({
      aspectRatio,
      canvasSize,
      customWidth,
      customHeight,
      videoSettings: {
        ...DEFAULT_VIDEO_SETTINGS,
        ...(schema.videoSettings || {}),
      },
    });

    const meta = buildProjectMeta({
      aspectRatio,
      canvasSize,
      tags,
      existingMeta: { fromTemplateId: template.id, fromVideoPackId: template.id },
    });

    const state = { videoSettings, scenes };
    if (meta) state.meta = meta;
    return normalizeProjectState(state);
  }

  let schema;
  try {
    schema = assertVideoSceneTemplateSchema(hydratedSchema);
  } catch (err) {
    throw new AppError(err.message || 'Invalid VIDEO_SCENE template schema', 400);
  }

  const scene = schemaToScene(schema, { templateId: template.id, order: 0 });

  const videoSettings = resolveVideoSettingsFromCanvas({
    aspectRatio,
    canvasSize,
    customWidth,
    customHeight,
    videoSettings: {
      ...DEFAULT_VIDEO_SETTINGS,
      ...(schema.videoSettings || {}),
    },
  });

  const meta = buildProjectMeta({
    aspectRatio,
    canvasSize,
    tags,
    existingMeta: { fromTemplateId: template.id },
  });

  const state = {
    videoSettings,
    scenes: [scene],
  };
  if (meta) state.meta = meta;

  return normalizeProjectState(state);
}

module.exports = {
  VIDEO_SCENE,
  VIDEO_PACK,
  VIDEO_TEMPLATE_TYPES,
  listActiveVideoTemplates,
  listActiveVideoSceneTemplates,
  getActiveVideoTemplate,
  getActiveVideoSceneTemplate,
  getActiveVideoPackTemplate,
  schemaToScene,
  packSchemaToScenes,
  applyTemplateToNewProjectState,
  hydrateVideoTemplateSchema,
  formatVideoTemplateForGallery,
  pickPreviewImageUrl,
};
