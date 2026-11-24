const { Prisma } = require('@prisma/client');
const prisma = require('../../shared/config/prismaClient');

const findHeygenResponseByRequestHash = async (requestHash) => {
  return prisma.heygenResponse.findUnique({
    where: { requestHash },
  });
};

const saveHeygenResponse = async ({
  workspaceId,
  folderId,
  projectId,
  sceneId,
  videoId,
  videoUrl = '',
  s3Key = null,
  requestHash,
  status = 'processing',
  rawResponse = null,
  triggeredByUserId = null,
  billingContext = null,
}) => {
  if (!workspaceId || !projectId || !videoId || !requestHash) {
    throw new Error('workspaceId, projectId, videoId, and requestHash are required');
  }

  return prisma.heygenResponse.create({
    data: {
      workspaceId,
      folderId,
      projectId,
      sceneId: sceneId ?? '',
      videoId,
      videoUrl,
      s3Key,
      requestHash,
      status,
      rawResponse,
      triggeredByUserId,
      billingContext,
    },
  });
};

/**
 * Re-arm a failed, never-billed row for a new HeyGen job (same id, same unique requestHash).
 * The `where` re-checks the failure state so two concurrent retries cannot both claim the row;
 * `count` is 0 when someone else already did, and `row` is then whatever the row is now.
 */
const reuseFailedHeygenResponse = async (
  id,
  {
    folderId,
    sceneId,
    videoId,
    status = 'processing',
    rawResponse = null,
    triggeredByUserId = null,
    billingContext = null,
  }
) => {
  if (!id || !videoId) {
    throw new Error('id and videoId are required');
  }

  const { count } = await prisma.heygenResponse.updateMany({
    where: { id, status: 'failed', s3Key: null, billingStatus: { not: 'charged' } },
    data: {
      folderId,
      sceneId: sceneId ?? '',
      videoId,
      videoUrl: '',
      s3Key: null,
      fileSizeBytes: null,
      status,
      rawResponse: rawResponse ?? Prisma.DbNull,
      triggeredByUserId,
      billingContext: billingContext ?? Prisma.DbNull,
      billingStatus: 'pending',
      creditsCharged: null,
      billedDurationSec: null,
    },
  });
  const row = await prisma.heygenResponse.findUnique({ where: { id } });
  return { count, row };
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
  reuseFailedHeygenResponse,
  listHeygenResponsesByProject,
  findHeygenResponseByIdForProject,
  updateHeygenResponse,
};
