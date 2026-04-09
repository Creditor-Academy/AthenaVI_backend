const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { checkWorkspaceAccess } = require('../../middlewares/workspaceAccess');
const { uploadAssetS3 } = require('../../middlewares/upload.middleware');
const validate = require('../../middlewares/validate.middleware');
const { uploadAssetSchema, getAssetsSchema, renameAssetSchema, deleteAssetSchema } = require('./asset.validation');
const assetController = require('./asset.controller');
const router = express.Router();

router.post(
  "/:workspaceId/upload",
  authMiddleware,
  checkWorkspaceAccess,
  uploadAssetS3.single("file"),
  validate(uploadAssetSchema),
  assetController.uploadAsset
);

router.get(
  "/:workspaceId",
  authMiddleware,
  checkWorkspaceAccess,
  validate(getAssetsSchema),
  assetController.getAssets
);

router.patch(
  "/:workspaceId/:assetId/rename",
  authMiddleware,
  checkWorkspaceAccess,
  validate(renameAssetSchema),
  assetController.renameAsset
);

router.delete(
  "/:workspaceId/:assetId",
  authMiddleware,
  checkWorkspaceAccess,
  validate(deleteAssetSchema),
  assetController.deleteAsset
);

module.exports = router;