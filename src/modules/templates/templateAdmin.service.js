const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const { assertVideoSceneTemplateSchema } = require('../validations/videoTemplate.validations');
const {
  assertDeckLayoutTemplateSchema,
  assertDeckPackTemplateSchema,
} = require('../validations/presentation.validations');
const templateMediaService = require('./templateMedia.service');

function assertDeckLayoutSchema(schema) {
  try {
    return assertDeckLayoutTemplateSchema(schema);
  } catch (err) {
    throw new AppError(err.message || 'Invalid DECK_LAYOUT schema', 400);
  }
}

function assertDeckPackSchema(schema) {
  try {
    return assertDeckPackTemplateSchema(schema);
  } catch (err) {
    throw new AppError(err.message || 'Invalid DECK_PACK schema', 400);
  }
}

async function assertPackLayoutIdsExist(schema) {
  const layoutIds = (schema.slides || []).map((s) => s.layout_id).filter(Boolean);
  if (!layoutIds.length) return;
  const layouts = await prisma.template.findMany({
    where: {
      type: 'DECK_LAYOUT',
      isActive: true,
      OR: layoutIds.map((layoutId) => ({
        schema: { path: ['layout_id'], equals: layoutId },
      })),
    },
    select: { id: true, schema: true },
  });
  const found = new Set(layouts.map((l) => l.schema?.layout_id).filter(Boolean));
  const missing = layoutIds.filter((id) => !found.has(id));
  if (missing.length) {
    throw new AppError(
      `DECK_PACK references unknown or inactive layout_id(s): ${missing.join(', ')}`,
      400
    );
  }
}

async function listTemplates({ type, contentType, isActive } = {}) {
  const where = {};
  if (type) where.type = type;
  if (contentType !== undefined && contentType !== null && contentType !== '') {
    where.contentType = contentType;
  }
  if (isActive !== undefined && isActive !== null && isActive !== '') {
    where.isActive = isActive === true || isActive === 'true';
  }

  const templates = await prisma.template.findMany({
    where,
    orderBy: [{ type: 'asc' }, { contentType: 'asc' }, { name: 'asc' }, { version: 'desc' }],
  });
  return templateMediaService.withMediaAttachedMany(templates);
}

async function getTemplate(id) {
  const template = await prisma.template.findUnique({ where: { id } });
  if (!template) {
    throw new AppError(messages.TEMPLATE_NOT_FOUND, 404);
  }
  return templateMediaService.withMediaAttached(template);
}

async function createTemplate({
  name,
  contentType,
  variant,
  schema,
  createdBy,
  type,
  isActive = true,
  version = 1,
}) {
  if (!type || !['DECK_LAYOUT', 'VIDEO_SCENE', 'DECK_PACK'].includes(type)) {
    throw new AppError(
      'type is required and must be DECK_LAYOUT, VIDEO_SCENE, or DECK_PACK',
      400
    );
  }

  let validatedSchema = schema;
  if (type === 'VIDEO_SCENE') {
    try {
      validatedSchema = assertVideoSceneTemplateSchema(schema);
    } catch (err) {
      throw new AppError(err.message || 'Invalid VIDEO_SCENE schema', 400);
    }
  } else if (type === 'DECK_PACK') {
    validatedSchema = assertDeckPackSchema(schema);
    await assertPackLayoutIdsExist(validatedSchema);
  } else {
    validatedSchema = assertDeckLayoutSchema(schema);
  }

  const created = await prisma.template.create({
    data: {
      type,
      name,
      contentType: contentType ?? null,
      variant: variant ?? null,
      schema: validatedSchema,
      version,
      isActive,
      createdBy,
    },
  });
  return templateMediaService.withMediaAttached(created);
}

async function updateTemplate({ id, name, schema, isActive, contentType, variant }) {
  const existing = await prisma.template.findUnique({ where: { id } });
  if (!existing) throw new AppError(messages.TEMPLATE_NOT_FOUND, 404);
  const data = {};

  if (name !== undefined) data.name = name;
  if (isActive !== undefined) data.isActive = isActive;
  if (contentType !== undefined) data.contentType = contentType;
  if (variant !== undefined) data.variant = variant;
  if (schema !== undefined) {
    if (existing.type === 'VIDEO_SCENE') {
      try {
        data.schema = assertVideoSceneTemplateSchema(schema);
      } catch (err) {
        throw new AppError(err.message || 'Invalid VIDEO_SCENE schema', 400);
      }
    } else if (existing.type === 'DECK_LAYOUT') {
      data.schema = assertDeckLayoutSchema(schema);
    } else if (existing.type === 'DECK_PACK') {
      data.schema = assertDeckPackSchema(schema);
      await assertPackLayoutIdsExist(data.schema);
    } else {
      data.schema = schema;
    }
    data.version = (existing.version || 1) + 1;
  }

  const updated = await prisma.template.update({
    where: { id },
    data,
  });
  return templateMediaService.withMediaAttached(updated);
}

module.exports = {
  listTemplates,
  getTemplate,
  createTemplate,
  updateTemplate,
  assertDeckLayoutSchema,
  assertDeckPackSchema,
};
