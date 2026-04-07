const messages = require('../../shared/utils/messages');
const  assetDao = require('./asset.dao');
const { uploadFile, deleteFile } = require('../s3/s3.service');
const prisma = require('../../shared/config/prismaClient');

const uploadAsset = async ({ userId, workspace, file }) => {
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
    const { key, url } = await uploadFile(file.stream,"workspace", workspace.id, "assets",file.originalname, file.mimetype);
    uploadedKey = key;

    // DB Transaction
    const result = await prisma.$transaction(async (tx) => {
      const asset = await assetDao.createAsset(tx, {
        workspaceId: workspace.id,
        uploadedBy: userId,
        size: file.size,
        url,
        type: file.mimetype,
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

module.exports = {
  uploadAsset,
};
