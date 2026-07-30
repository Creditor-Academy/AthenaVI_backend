const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const { assertVideoSceneTemplateSchema } = require('../validations/videoTemplate.validations');
const { assertDeckLayoutTemplateSchema } = require('../validations/presentation.validations');

function assertDeckLayoutSchema(schema) {
  try {
    return assertDeckLayoutTemplateSchema(schema);
  } catch (err) {
    throw new AppError(err.message || 'Invalid DECK_LAYOUT schema', 400);
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

  return prisma.template.findMany({
    where,
    orderBy: [{ type: 'asc' }, { contentType: 'asc' }, { name: 'asc' }, { version: 'desc' }],
  });
}

async function getTemplate(id) {
  const template = await prisma.template.findUnique({ where: { id } });
  if (!template) {
    throw new AppError(messages.TEMPLATE_NOT_FOUND, 404);
  }
  return template;
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
  if (!type || !['DECK_LAYOUT', 'VIDEO_SCENE'].includes(type)) {
    throw new AppError('type is required and must be DECK_LAYOUT or VIDEO_SCENE', 400);
  }

  let validatedSchema = schema;
  if (type === 'VIDEO_SCENE') {
    try {
      validatedSchema = assertVideoSceneTemplateSchema(schema);
    } catch (err) {
      throw new AppError(err.message || 'Invalid VIDEO_SCENE schema', 400);
    }
  } else {
    validatedSchema = assertDeckLayoutSchema(schema);
  }

  return prisma.template.create({
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
}

async function updateTemplate({ id, name, schema, isActive, contentType, variant }) {
  const existing = await getTemplate(id);
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
    } else {
      data.schema = schema;
    }
    data.version = (existing.version || 1) + 1;
  }

  return prisma.template.update({
    where: { id },
    data,
  });
}

module.exports = {
  listTemplates,
  getTemplate,
  createTemplate,
  updateTemplate,
  assertDeckLayoutSchema,
};
