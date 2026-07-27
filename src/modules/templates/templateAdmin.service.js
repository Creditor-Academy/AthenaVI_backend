const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const { assertVideoSceneTemplateSchema } = require('../validations/videoTemplate.validations');

function assertDeckLayoutSchema(schema) {
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
    throw new AppError('DECK_LAYOUT schema must be an object', 400);
  }
  if (schema.scene && schema.videoSettings) {
    throw new AppError(
      'DECK_LAYOUT schema must not use VIDEO_SCENE shape (scene/videoSettings). Use type VIDEO_SCENE instead.',
      400
    );
  }
  return schema;
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
  type = 'DECK_LAYOUT',
  isActive = true,
  version = 1,
}) {
  let validatedSchema = schema;
  if (type === 'VIDEO_SCENE') {
    try {
      validatedSchema = assertVideoSceneTemplateSchema(schema);
    } catch (err) {
      throw new AppError(err.message || 'Invalid VIDEO_SCENE schema', 400);
    }
  } else if (type === 'DECK_LAYOUT') {
    validatedSchema = assertDeckLayoutSchema(schema);
  } else {
    throw new AppError('Invalid template type', 400);
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

async function updateTemplate({ id, name, schema, isActive }) {
  const existing = await getTemplate(id);
  const data = {};

  if (name !== undefined) data.name = name;
  if (isActive !== undefined) data.isActive = isActive;
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
