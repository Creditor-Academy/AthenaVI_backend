const prisma = require('../../shared/config/prismaClient');

/* =========================
   VIDEO (video editor)
========================= */

const createVideo = async (data) => {
  return await prisma.video.create({
    data,
  });
};

const findVideoById = async (videoId) => {
  return await prisma.video.findUnique({
    where: { id: videoId },
    include: {
      workspace: { select: { id: true, name: true } },
    },
  });
};

const findVideosByWorkspaceId = async (workspaceId, options = {}) => {
  const { includeScenes = false } = options;
  return await prisma.video.findMany({
    where: { workspaceId },
    include: includeScenes
      ? { scenes: { orderBy: { order: 'asc' } } }
      : undefined,
    orderBy: { updatedAt: 'desc' },
  });
};

const updateVideo = async (videoId, data) => {
  return await prisma.video.update({
    where: { id: videoId },
    data,
  });
};

const deleteVideo = async (videoId) => {
  return await prisma.video.delete({
    where: { id: videoId },
  });
};

/* =========================
   SCENE
========================= */

const createScene = async (data) => {
  return await prisma.scene.create({
    data,
  });
};

const findSceneById = async (sceneId) => {
  return await prisma.scene.findUnique({
    where: { id: sceneId },
    include: {
      video: { select: { id: true, workspaceId: true } },
    },
  });
};

const findScenesByVideoId = async (videoId) => {
  return await prisma.scene.findMany({
    where: { videoId },
    orderBy: [{ order: 'asc' }, { startTime: 'asc' }],
  });
};

const updateScene = async (sceneId, data) => {
  return await prisma.scene.update({
    where: { id: sceneId },
    data,
  });
};

const deleteScene = async (sceneId) => {
  return await prisma.scene.delete({
    where: { id: sceneId },
  });
};

module.exports = {
  createVideo,
  findVideoById,
  findVideosByWorkspaceId,
  updateVideo,
  deleteVideo,
  createScene,
  findSceneById,
  findScenesByVideoId,
  updateScene,
  deleteScene,
};
