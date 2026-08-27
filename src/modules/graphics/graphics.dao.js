const prisma = require('../../shared/config/prismaClient');

function create(data) {
  return prisma.graphicAsset.create({ data });
}

function findById(id) {
  return prisma.graphicAsset.findUnique({ where: { id } });
}

function update(id, data) {
  return prisma.graphicAsset.update({ where: { id }, data });
}

function remove(id) {
  return prisma.graphicAsset.delete({ where: { id } });
}

function listPublished() {
  return prisma.graphicAsset.findMany({
    where: { status: 'published' },
    orderBy: { updatedAt: 'desc' },
  });
}

function list({
  q,
  category,
  type,
  style,
  mood,
  colorMode,
  status,
  skip = 0,
  take = 60,
} = {}) {
  const where = {};
  if (status) where.status = status;
  if (category) where.category = category;
  if (type) where.type = type;
  if (style) where.style = style;
  if (colorMode) where.colorMode = colorMode;
  if (mood) where.moods = { has: mood };

  if (q && String(q).trim()) {
    const term = String(q).trim();
    where.OR = [
      { name: { contains: term, mode: 'insensitive' } },
      { description: { contains: term, mode: 'insensitive' } },
      { tags: { has: term } },
      { category: { contains: term, mode: 'insensitive' } },
    ];
  }

  return prisma.graphicAsset.findMany({
    where,
    orderBy: { updatedAt: 'desc' },
    skip,
    take,
  });
}

function count(filters = {}) {
  const { skip, take, ...rest } = filters;
  return prisma.graphicAsset.count({
    where: listWhere(rest),
  });
}

function listWhere({ q, category, type, style, mood, colorMode, status } = {}) {
  const where = {};
  if (status) where.status = status;
  if (category) where.category = category;
  if (type) where.type = type;
  if (style) where.style = style;
  if (colorMode) where.colorMode = colorMode;
  if (mood) where.moods = { has: mood };
  if (q && String(q).trim()) {
    const term = String(q).trim();
    where.OR = [
      { name: { contains: term, mode: 'insensitive' } },
      { description: { contains: term, mode: 'insensitive' } },
      { tags: { has: term } },
      { category: { contains: term, mode: 'insensitive' } },
    ];
  }
  return where;
}

function findByExternalTag(tag) {
  return prisma.graphicAsset.findFirst({
    where: { tags: { has: String(tag) } },
  });
}

module.exports = {
  create,
  findById,
  findByExternalTag,
  update,
  remove,
  list,
  count,
  listPublished,
};
