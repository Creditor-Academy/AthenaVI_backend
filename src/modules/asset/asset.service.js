const messages = require('../../shared/utils/messages');
const assetDao = require('./asset.dao');
const { uploadFile, deleteFile } = require('../s3/s3.service');
const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');

const uploadAsset = async ({ userId, workspace, file, name }) => {
  let uploadedKey = null;
  try {
    // Get owner
    const owner = await assetDao.findUserById(workspace.ownerId);

    if (!owner) {
      throw new Error(messages.WORKSPACE_OWNER_NOT_FOUND);
    }

    // Storage check
    if (owner.storageUsed + file.size > owner.storageLimit) {
      throw new Error(messages.STORAGE_LIMIT_EXCEEDED);
    }

    // Upload to S3 first
    const { key, url } = await uploadFile(
      file.stream,
      'workspace',
      workspace.id,
      'assets',
      file.originalname,
      file.mimetype
    );
    uploadedKey = key;

    const finalName = name || file.originalname;

    // DB Transaction
    const result = await prisma.$transaction(async (tx) => {
      const asset = await assetDao.createAsset(tx, {
        workspaceId: workspace.id,
        uploadedBy: userId,
        size: file.size,
        url,
        key,
        type: file.mimetype,
        name: finalName,
      });

      await assetDao.incrementUserStorage(tx, owner.id, file.size);

      return asset;
    });
    return result;
  } catch (error) {
    // Rollback S3 if DB fails
    if (uploadedKey) {
      await deleteFile(uploadedKey);
    }
    throw error;
  }
};

const getAssets = async (userId, workspace, query) => {
  const isPrivate = workspace.type === "PRIVATE";

  return await assetDao.findAssets({
    workspaceId: workspace.id,
    userId,
    isPrivate,
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
  uploadAsset,
  getAssets,
  renameAsset,
  deleteAsset,
};
