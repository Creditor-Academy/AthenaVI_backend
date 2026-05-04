const prisma = require('../../shared/config/prismaClient');

const findHeygenResponseByRequestHash = async (requestHash) => {
  return prisma.heygenResponse.findUnique({
    where: { requestHash },
  });
};

const saveHeygenResponse = async ({
  workspaceId,
  projectId,
  sceneId,
  videoId,
  videoUrl = '',
  s3Key = null,
  requestHash,
  status = 'processing',
  rawResponse = null,
}) => {
  if (!workspaceId || !projectId || !videoId || !requestHash) {
    throw new Error('workspaceId, projectId, videoId, and requestHash are required');
  }

  return prisma.heygenResponse.create({
    data: {
      workspaceId,
      projectId,
      sceneId: sceneId ?? '',
      videoId,
      videoUrl,
      s3Key,
      requestHash,
      status,
      rawResponse,
    },
  });
};

const listHeygenResponsesByProject = async (workspaceId, projectId) => {
  return prisma.heygenResponse.findMany({
    where: { workspaceId, projectId },
    orderBy: { createdAt: 'desc' },
  });
};

const findHeygenResponseByIdForProject = async (id, workspaceId, projectId) => {
  return prisma.heygenResponse.findFirst({
    where: { id, workspaceId, projectId },
  });
};

const updateHeygenResponse = async (id, data) => {
  return prisma.heygenResponse.update({
    where: { id },
    data,
  });
};

module.exports = {
  findHeygenResponseByRequestHash,
  saveHeygenResponse,
  listHeygenResponsesByProject,
  findHeygenResponseByIdForProject,
  updateHeygenResponse,
};
