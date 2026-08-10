const express = require('express');
const router = express.Router({ mergeParams: true });
const validate = require('../../middlewares/validate.middleware');
const { uploadAssetS3 } = require('../../middlewares/upload.middleware');
const { requireWorkspaceRole } = require('../../middlewares/requireWorkspaceRole');
const brandKitController = require('./brandKit.controller');
const brandKitValidations = require('./brandKit.validations');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];
const ownerOrAdmin = ['OWNER', 'ADMIN'];

router.get(
  '/',
  requireWorkspaceRole(anyMember),
  validate(brandKitValidations.listBrandKitsSchema),
  brandKitController.listBrandKits
);

router.post(
  '/',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.createBrandKitSchema),
  brandKitController.createBrandKit
);

router.get(
  '/:brandKitId',
  requireWorkspaceRole(anyMember),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.getBrandKit
);

router.patch(
  '/:brandKitId',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.updateBrandKitSchema),
  brandKitController.updateBrandKit
);

router.delete(
  '/:brandKitId',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.deleteBrandKit
);

router.post(
  '/:brandKitId/set-default',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.setDefaultBrandKit
);

router.post(
  '/:brandKitId/media',
  requireWorkspaceRole(ownerOrAdmin),
  uploadAssetS3.single('file'),
  validate(brandKitValidations.uploadBrandKitMediaSchema),
  brandKitController.uploadMedia
);

router.delete(
  '/:brandKitId/media/:mediaId',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.deleteBrandKitMediaSchema),
  brandKitController.deleteMedia
);

router.get(
  '/:brandKitId/media/:mediaId/stream',
  requireWorkspaceRole(anyMember),
  brandKitController.streamMedia
);

module.exports = router;
