const { Prisma } = require('@prisma/client');
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

/**
 * Re-arm a failed, never-billed row for a new attempt (same id, same unique requestHash, so the S3
 * key built from the id is simply overwritten). The `where` re-checks the failure state so two
 * concurrent retries cannot both claim the row. Returns the row, or null if someone else got it.
 */
const claimFailedSpeechGeneration = async (
  id,
  { folderId, voiceId, script, inputType, speed, locale, language, triggeredByUserId, billingContext }
) => {
  const { count } = await prisma.speechGeneration.updateMany({
    where: { id, status: 'failed', billingStatus: { not: 'charged' } },
    data: {
      folderId,
      voiceId,
      script,
      inputType,
      speed,
      locale,
      language,
      heygenAudioUrl: null,
      audioUrl: '',
      s3Key: null,
      fileSizeBytes: null,
      durationSec: null,
      wordTimestamps: Prisma.DbNull,
      rawResponse: Prisma.DbNull,
      status: 'processing',
      triggeredByUserId,
      billingContext: billingContext ?? Prisma.DbNull,
      billingStatus: 'pending',
      creditsCharged: null,
      billedDurationSec: null,
    },
  });
  if (count === 0) return null;
  return prisma.speechGeneration.findUnique({ where: { id } });
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
  claimFailedSpeechGeneration,
  listSpeechGenerationsByProject,
  findSpeechGenerationByIdForProject,
  updateSpeechGeneration,
};
