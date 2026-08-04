const { v4: uuidv4 } = require('uuid');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const { DEFAULT_VIDEO_SETTINGS } = require('../../shared/constants/videoEditor');
const {
  assertVideoSceneTemplateSchema,
  assertVideoPackTemplateSchema,
} = require('../validations/videoTemplate.validations');

const VIDEO_SCENE = 'VIDEO_SCENE';
const VIDEO_PACK = 'VIDEO_PACK';
const VIDEO_TEMPLATE_TYPES = [VIDEO_SCENE, VIDEO_PACK];

async function listActiveVideoTemplates({ contentType, type } = {}) {
  const where = {
    isActive: true,
    type: type && VIDEO_TEMPLATE_TYPES.includes(type) ? type : { in: VIDEO_TEMPLATE_TYPES },
  };
  if (contentType) where.contentType = contentType;

  return prisma.template.findMany({
    where,
    orderBy: [{ type: 'asc' }, { contentType: 'asc' }, { name: 'asc' }, { version: 'desc' }],
  });
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
  return template;
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

function applyTemplateToNewProjectState({
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
  if (template.type === VIDEO_PACK) {
    let schema;
    try {
      schema = assertVideoPackTemplateSchema(template.schema);
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
    schema = assertVideoSceneTemplateSchema(template.schema);
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
};
