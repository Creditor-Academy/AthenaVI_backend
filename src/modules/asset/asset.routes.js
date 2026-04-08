const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { checkWorkspaceAccess } = require('../../middlewares/workspaceAccess');
const { uploadAssetS3 } = require('../../middlewares/upload.middleware');
const assetController = require('./asset.controller');
const router = express.Router();

router.post(
  "/:workspaceId/upload",
  authMiddleware,
  checkWorkspaceAccess,
  uploadAssetS3.single("file"),
  assetController.uploadAsset
);

router.get(
  "/:workspaceId",
  authMiddleware,
  checkWorkspaceAccess,
  assetController.getAssets
);

module.exports = router;