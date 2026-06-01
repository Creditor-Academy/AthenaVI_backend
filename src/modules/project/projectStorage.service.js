const prisma = require('../../shared/config/prismaClient');
const { collectAssetIds } = require('../../shared/utils/projectAssetIds');
const projectDao = require('./project.dao');

function computeJsonSizeBytes(data) {
  if (data == null) {
    return 0;
  }
  try {
    return Buffer.byteLength(JSON.stringify(data), 'utf8');
  } catch {
    return 0;
  }
}

function sumFileSizeBytes(rows) {
  return (rows || []).reduce((sum, row) => sum + (row.fileSizeBytes || 0), 0);
}

async function sumReferencedAssetBytes(workspaceId, projectData) {
  const assetIds = collectAssetIds(projectData);
  if (!assetIds.length) {
    return 0;
  }

  const assets = await projectDao.findAssetsByIds(workspaceId, assetIds);
  return assets.reduce((sum, asset) => sum + (asset.size || 0), 0);
}

async function computeProjectStorageBytes(project) {
  const jsonBytes = computeJsonSizeBytes(project.data);
  const assetBytes = await sumReferencedAssetBytes(project.workspaceId, project.data);
  const heygenBytes = sumFileSizeBytes(project.heygenResponses);
  const renderBytes = sumFileSizeBytes(project.projectRenders);
  const cacheBytes = sumFileSizeBytes(project.sceneRenderCaches);

  return jsonBytes + assetBytes + heygenBytes + renderBytes + cacheBytes;
}

async function recalculateProjectStorage(projectId) {
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    include: {
      heygenResponses: {
        select: { fileSizeBytes: true, s3Key: true },
      },
      projectRenders: {
        select: { fileSizeBytes: true, s3Key: true },
      },
      sceneRenderCaches: {
        select: { fileSizeBytes: true, s3Key: true },
      },
    },
  });

  if (!project) {
    return 0;
  }

  const storageBytes = await computeProjectStorageBytes(project);

  await prisma.project.update({
    where: { id: projectId },
    data: { storageBytes },
  });

  return storageBytes;
}

module.exports = {
  computeJsonSizeBytes,
  computeProjectStorageBytes,
  recalculateProjectStorage,
};
