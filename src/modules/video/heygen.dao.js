const prisma = require('../../shared/config/prismaClient');

const findHeygenResponseByRequestHash = async (requestHash) => {
  return prisma.heygenResponse.findUnique({
    where: { requestHash },
  });
};

const saveHeygenResponse = async ({
  workspaceId,
  projectId,
  videoId,
  videoUrl,
  requestHash,
  status = 'processing',
}) => {
  if (!workspaceId || !projectId || !videoId || !requestHash) {
    throw new Error('workspaceId, projectId, videoId, and requestHash are required');
  }

  return prisma.heygenResponse.create({
    data: {
      workspaceId,
      projectId,
      videoId,
      videoUrl,
      requestHash,
      status,
    },
  });
};

module.exports = {
  findHeygenResponseByRequestHash,
  saveHeygenResponse,
};
