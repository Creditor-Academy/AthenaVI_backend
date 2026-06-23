const messages = require('../../shared/utils/messages');
const assetDao = require('./asset.dao');
const { uploadFile, deleteFile } = require('../s3/s3.service');
const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const { collectAssetIds } = require('../../shared/utils/projectAssetIds');
const storageAccounting = require('../storage/storageAccounting.service');
const inboxService = require('../inbox/inbox.service');

function getWorkspaceMemberRole(workspace, userId) {
  if (!workspace || !Array.isArray(workspace.members)) {
    return null;
  }
  const member = workspace.members.find((item) => item.userId === userId);
  return member ? member.role : null;
}

function assertCanManageAsset({ workspace, userId, asset }) {
  if (workspace.type === 'PRIVATE') {
    return;
  }

  if (asset.uploadedBy === userId) {
    return;
  }

  const role = getWorkspaceMemberRole(workspace, userId);
  if (role === 'OWNER' || role === 'ADMIN') {
    return;
  }

  throw new AppError(messages.ASSET_FORBIDDEN, 403);
}

async function assertAssetNotReferenced(workspaceId, assetId) {
  const projects = await assetDao.listProjectDataByWorkspace(workspaceId);
  let usedInProjectCount = 0;

  for (const project of projects) {
    const ids = collectAssetIds(project.data);
    if (ids.includes(assetId)) {
      usedInProjectCount += 1;
    }
  }

  if (usedInProjectCount > 0) {
    throw new AppError(messages.ASSET_IN_USE, 409, [
      {
        field: 'assetId',
        message: `Asset is used in ${usedInProjectCount} project(s)`,
      },
    ]);
  }
}

const persistWorkspaceAsset = async ({
  userId,
  workspace,
  buffer,
  contentType,
  originalName,
  name,
  source = 'upload',
  stockProvider = null,
  stockExternalId = null,
  stockMetadata = null,
}) => {
  let uploadedKey = null;
  try {
    const owner = await assetDao.findUserById(workspace.ownerId);

    if (!owner) {
      throw new AppError(messages.WORKSPACE_OWNER_NOT_FOUND, 404);
    }

    const size = buffer.length;
    await storageAccounting.recalculateUserStorageUsed(workspace.ownerId);
    try {
      await storageAccounting.assertOwnerCanFitAdditionalBytes(workspace.id, size);
    } catch (storageError) {
      if (storageError.message === messages.STORAGE_LIMIT_EXCEEDED) {
        inboxService
          .notifyStorageUploadBlocked({
            ownerId: workspace.ownerId,
            uploaderId: userId,
            workspaceId: workspace.id,
            workspaceName: workspace.name,
          })
          .catch((error) => console.error('Storage upload blocked notification failed:', error));
      }
      throw storageError;
    }

    const { key, url } = await uploadFile(
      buffer,
      'workspace',
      workspace.id,
      'assets',
      originalName,
      contentType
    );
    uploadedKey = key;

    const finalName = name || originalName;

    const result = await prisma.$transaction(async (tx) => {
      const asset = await assetDao.createAsset(tx, {
        workspaceId: workspace.id,
        uploadedBy: userId,
        size,
        url,
        key,
        type: contentType,
        name: finalName,
        source,
        stockProvider,
        stockExternalId,
        stockMetadata,
      });

      return asset;
    });
    await storageAccounting.recalculateUserStorageUsed(workspace.ownerId);
    return result;
  } catch (error) {
    if (uploadedKey) {
      await deleteFile(uploadedKey);
    }
    throw error;
  }
};

const uploadAsset = async ({ userId, workspace, file, name }) => {
  const buffer = file.buffer;
  if (!buffer) {
    throw new AppError(messages.INVALID_FILE_TYPE, 400);
  }

  return persistWorkspaceAsset({
    userId,
    workspace,
    buffer,
    contentType: file.mimetype,
    originalName: file.originalname,
    name: name || file.originalname,
    source: 'upload',
  });
};

const getAssets = async (userId, workspace, query) => {
  const isPrivate = workspace.type === 'PRIVATE';
  const source = query.source === 'upload' || query.source === 'stock' ? query.source : undefined;

  return assetDao.findAssets({
    workspaceId: workspace.id,
    userId,
    isPrivate,
    source,
    take: query.take,
    skip: query.skip,
  });
};

const renameAsset = async ({ assetId, workspace, userId, name }) => {
  const workspaceId = workspace.id;
  const asset = await assetDao.findAssetById(assetId, workspaceId);

  if (!asset) {
    throw new AppError(messages.ASSET_NOT_FOUND, 404);
  }

  assertCanManageAsset({ workspace, userId, asset });
  return assetDao.updateAssetName(assetId, name.trim());
};

const deleteAsset = async ({ assetId, workspace, userId }) => {
  const asset = await assetDao.findAssetById(assetId, workspace.id);

  if (!asset) {
    throw new AppError(messages.ASSET_NOT_FOUND, 404);
  }

  assertCanManageAsset({ workspace, userId, asset });
  await assertAssetNotReferenced(workspace.id, assetId);

  if (asset.key) {
    await deleteFile(asset.key);
  }

  const deleted = await prisma.$transaction(async (tx) => {
    return assetDao.deleteAssetById(tx, assetId);
  });
  await storageAccounting.recalculateUserStorageUsed(workspace.ownerId);
  return deleted;
};

module.exports = {
  persistWorkspaceAsset,
  uploadAsset,
  getAssets,
  renameAsset,
  deleteAsset,
};
