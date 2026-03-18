const prisma = require('../../shared/config/prismaClient');

const createRenderJob = async (data) => {
  return await prisma.renderJob.create({
    data,
  });
};

const findRenderJobById = async (jobId) => {
  return await prisma.renderJob.findUnique({
    where: { id: jobId },
  });
};

const updateRenderJob = async (jobId, data) => {
  return await prisma.renderJob.update({
    where: { id: jobId },
    data,
  });
};

module.exports = {
  createRenderJob,
  findRenderJobById,
  updateRenderJob,
};
