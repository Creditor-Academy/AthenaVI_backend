const prisma = require('../../shared/config/prismaClient');

const findSpeechGenerationByRequestHash = async (requestHash) => {
  return prisma.speechGeneration.findUnique({
    where: { requestHash },
  });
};

const saveSpeechGeneration = async ({
  workspaceId,
  folderId,
  projectId,
  sceneId,
  voiceId,
  script,
  inputType = 'text',
  speed = 1,
  locale = null,
  language = null,
  requestHash,
  status = 'processing',
  rawResponse = null,
  triggeredByUserId = null,
  billingContext = null,
}) => {
  if (!workspaceId || !projectId || !voiceId || !script || !requestHash) {
    throw new Error('workspaceId, projectId, voiceId, script, and requestHash are required');
  }

  return prisma.speechGeneration.create({
    data: {
      workspaceId,
      folderId,
      projectId,
      sceneId: sceneId ?? '',
      voiceId,
      script,
      inputType,
      speed,
      locale,
      language,
      requestHash,
      status,
      rawResponse,
      triggeredByUserId,
      billingContext,
    },
  });
};

const listSpeechGenerationsByProject = async (workspaceId, projectId) => {
  return prisma.speechGeneration.findMany({
    where: { workspaceId, projectId },
    orderBy: { createdAt: 'desc' },
  });
};

const findSpeechGenerationByIdForProject = async (id, workspaceId, projectId) => {
  return prisma.speechGeneration.findFirst({
    where: { id, workspaceId, projectId },
  });
};

const updateSpeechGeneration = async (id, data) => {
  return prisma.speechGeneration.update({
    where: { id },
    data,
  });
};

module.exports = {
  findSpeechGenerationByRequestHash,
  saveSpeechGeneration,
  listSpeechGenerationsByProject,
  findSpeechGenerationByIdForProject,
  updateSpeechGeneration,
};
