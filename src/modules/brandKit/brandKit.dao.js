const prisma = require('../../shared/config/prismaClient');

async function listByWorkspace(workspaceId) {
  return prisma.workspaceBrandKit.findMany({
    where: { workspaceId },
    include: {
      media: {
        orderBy: [{ kind: 'asc' }, { sortOrder: 'asc' }, { createdAt: 'asc' }],
      },
      _count: { select: { media: true } },
    },
    orderBy: [{ isDefault: 'desc' }, { name: 'asc' }, { createdAt: 'desc' }],
  });
}

async function findById(brandKitId) {
  return prisma.workspaceBrandKit.findUnique({
    where: { id: brandKitId },
    include: {
      media: {
        orderBy: [{ kind: 'asc' }, { sortOrder: 'asc' }, { createdAt: 'asc' }],
      },
    },
  });
}

async function findInWorkspace(workspaceId, brandKitId) {
  return prisma.workspaceBrandKit.findFirst({
    where: { id: brandKitId, workspaceId },
    include: {
      media: {
        orderBy: [{ kind: 'asc' }, { sortOrder: 'asc' }, { createdAt: 'asc' }],
      },
    },
  });
}

async function findDefaultByWorkspace(workspaceId) {
  return prisma.workspaceBrandKit.findFirst({
    where: { workspaceId, isDefault: true },
    include: {
      media: {
        orderBy: [{ kind: 'asc' }, { sortOrder: 'asc' }, { createdAt: 'asc' }],
      },
    },
  });
}

async function findMediaByKindRole(brandKitId, kind, role) {
  const roles = kind === 'logo' ? logoRoleCandidates(role) : [String(role || '').toLowerCase()];
  return prisma.brandKitMedia.findFirst({
    where: { brandKitId, kind, role: { in: roles } },
  });
}

async function findAllMediaByKindRole(brandKitId, kind, role) {
  const roles = kind === 'logo' ? logoRoleCandidates(role) : [String(role || '').toLowerCase()];
  return prisma.brandKitMedia.findMany({
    where: { brandKitId, kind, role: { in: roles } },
  });
}

function logoRoleCandidates(role) {
  const r = String(role || '').toLowerCase();
  if (r === 'light' || r === 'light-mode') return ['light', 'light-mode'];
  if (r === 'dark' || r === 'dark-mode') return ['dark', 'dark-mode'];
  return [r];
}

async function createKit({ workspaceId, name, data, isDefault, createdBy }) {
  return prisma.$transaction(async (tx) => {
    if (isDefault) {
      await tx.workspaceBrandKit.updateMany({
        where: { workspaceId, isDefault: true },
        data: { isDefault: false },
      });
    }
    return tx.workspaceBrandKit.create({
      data: {
        workspaceId,
        name,
        data,
        isDefault: Boolean(isDefault),
        createdBy,
      },
      include: { media: true },
    });
  });
}

async function updateKit({ workspaceId, brandKitId, name, data, isDefault }) {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.workspaceBrandKit.findFirst({
      where: { id: brandKitId, workspaceId },
    });
    if (!existing) return null;

    if (isDefault === true) {
      await tx.workspaceBrandKit.updateMany({
        where: { workspaceId, isDefault: true, NOT: { id: brandKitId } },
        data: { isDefault: false },
      });
    }

    const patch = {};
    if (name !== undefined) patch.name = name;
    if (data !== undefined) patch.data = data;
    if (isDefault !== undefined) patch.isDefault = Boolean(isDefault);

    return tx.workspaceBrandKit.update({
      where: { id: brandKitId },
      data: patch,
      include: {
        media: {
          orderBy: [{ kind: 'asc' }, { sortOrder: 'asc' }, { createdAt: 'asc' }],
        },
      },
    });
  });
}

async function setDefault(workspaceId, brandKitId) {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.workspaceBrandKit.findFirst({
      where: { id: brandKitId, workspaceId },
    });
    if (!existing) return null;

    await tx.workspaceBrandKit.updateMany({
      where: { workspaceId, isDefault: true, NOT: { id: brandKitId } },
      data: { isDefault: false },
    });

    return tx.workspaceBrandKit.update({
      where: { id: brandKitId },
      data: { isDefault: true },
      include: {
        media: {
          orderBy: [{ kind: 'asc' }, { sortOrder: 'asc' }, { createdAt: 'asc' }],
        },
      },
    });
  });
}

async function deleteKit(workspaceId, brandKitId) {
  const existing = await prisma.workspaceBrandKit.findFirst({
    where: { id: brandKitId, workspaceId },
    include: { media: true },
  });
  if (!existing) return null;

  await prisma.workspaceBrandKit.delete({ where: { id: brandKitId } });
  return existing;
}

async function createMedia(data) {
  return prisma.brandKitMedia.create({ data });
}

async function findMedia(brandKitId, mediaId) {
  return prisma.brandKitMedia.findFirst({
    where: { id: mediaId, brandKitId },
  });
}

async function deleteMedia(mediaId) {
  return prisma.brandKitMedia.delete({ where: { id: mediaId } });
}

async function maxSortOrder(brandKitId, kind) {
  const agg = await prisma.brandKitMedia.aggregate({
    where: { brandKitId, kind },
    _max: { sortOrder: true },
  });
  return agg._max.sortOrder ?? -1;
}

module.exports = {
  listByWorkspace,
  findById,
  findInWorkspace,
  findDefaultByWorkspace,
  findMediaByKindRole,
  findAllMediaByKindRole,
  logoRoleCandidates,
  createKit,
  updateKit,
  setDefault,
  deleteKit,
  createMedia,
  findMedia,
  deleteMedia,
  maxSortOrder,
};
