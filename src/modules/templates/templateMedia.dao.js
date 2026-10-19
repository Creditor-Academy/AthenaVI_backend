const prisma = require('../../shared/config/prismaClient');

async function listByTemplateId(templateId) {
  return prisma.templateMedia.findMany({
    where: { templateId },
    orderBy: [{ sortOrder: 'asc' }, { createdAt: 'asc' }],
  });
}

async function findById(templateId, mediaId) {
  return prisma.templateMedia.findFirst({
    where: { id: mediaId, templateId },
  });
}

async function findBySlotHint(templateId, slotHint) {
  return prisma.templateMedia.findFirst({
    where: { templateId, slotHint },
  });
}

async function createMedia(data) {
  return prisma.templateMedia.create({ data });
}

async function upsertBySlotHint(data) {
  const { templateId, slotHint, ...rest } = data;
  if (!slotHint) {
    return prisma.templateMedia.create({
      data: { templateId, slotHint: null, ...rest },
    });
  }
  return prisma.templateMedia.upsert({
    where: {
      templateId_slotHint: { templateId, slotHint },
    },
    create: { templateId, slotHint, ...rest },
    update: rest,
  });
}

async function deleteMedia(mediaId) {
  return prisma.templateMedia.delete({ where: { id: mediaId } });
}

async function maxSortOrder(templateId, kind) {
  const agg = await prisma.templateMedia.aggregate({
    where: { templateId, kind },
    _max: { sortOrder: true },
  });
  return agg._max.sortOrder ?? 0;
}

async function listMediaForTemplates(templateIds) {
  if (!templateIds?.length) return [];
  return prisma.templateMedia.findMany({
    where: { templateId: { in: templateIds } },
    orderBy: [{ sortOrder: 'asc' }, { createdAt: 'asc' }],
  });
}

module.exports = {
  listByTemplateId,
  findById,
  findBySlotHint,
  createMedia,
  upsertBySlotHint,
  deleteMedia,
  maxSortOrder,
  listMediaForTemplates,
};
