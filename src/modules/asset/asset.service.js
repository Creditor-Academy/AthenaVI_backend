const messages = require('../../shared/utils/messages');
const assetDao = require('./asset.dao');
const { uploadFile, deleteFile } = require('../s3/s3.service');
const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');

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
    if (owner.storageUsed + size > owner.storageLimit) {
      throw new AppError(messages.STORAGE_LIMIT_EXCEEDED, 400);
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

      await assetDao.incrementUserStorage(tx, owner.id, size);

      return asset;
    });
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

const renameAsset = async ({ assetId, workspaceId, name }) => {
  const asset = await assetDao.findAssetById(assetId, workspaceId);

  if (!asset) {
    throw new AppError(messages.ASSET_NOT_FOUND, 404);
  }

  return assetDao.updateAssetName(assetId, name.trim());
};

const deleteAsset = async ({ assetId, workspace }) => {
  const asset = await assetDao.findAssetById(assetId, workspace.id);

  if (!asset) {
    throw new AppError(messages.ASSET_NOT_FOUND, 404);
  }

  if (asset.key) {
    await deleteFile(asset.key);
  }

  return prisma.$transaction(async (tx) => {
    await assetDao.decrementUserStorage(tx, workspace.ownerId, asset.size);
    return assetDao.deleteAssetById(tx, assetId);
  });
};

module.exports = {
  persistWorkspaceAsset,
  uploadAsset,
  getAssets,
  renameAsset,
  deleteAsset,
};
