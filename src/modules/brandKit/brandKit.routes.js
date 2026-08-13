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

router.post(
  '/suggest/colors',
  requireWorkspaceRole(ownerOrAdmin),
  uploadAssetS3.single('file'),
  validate(brandKitValidations.suggestColorsSchema),
  brandKitController.suggestColors
);

router.post(
  '/suggest/fonts',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.suggestFontsSchema),
  brandKitController.suggestFonts
);

router.post(
  '/suggest/voice',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.suggestVoiceSchema),
  brandKitController.suggestVoice
);

router.post(
  '/suggest/image-style',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.suggestImageStyleSchema),
  brandKitController.suggestImageStyle
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

router.get(
  '/:brandKitId/health',
  requireWorkspaceRole(anyMember),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.getBrandKitHealth
);

router.post(
  '/:brandKitId/suggest/logo-variants',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.suggestLogoVariantsSchema),
  brandKitController.suggestLogoVariants
);

router.get(
  '/:brandKitId/mockups/catalog',
  requireWorkspaceRole(anyMember),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.listMockupCatalog
);

router.get(
  '/:brandKitId/mockups',
  requireWorkspaceRole(anyMember),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.listMockups
);

router.post(
  '/:brandKitId/mockups/generate',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.generateMockupSchema),
  brandKitController.generateMockup
);

router.post(
  '/:brandKitId/guidelines/generate',
  requireWorkspaceRole(ownerOrAdmin),
  validate(brandKitValidations.generateGuidelineSchema),
  brandKitController.generateGuideline
);

router.get(
  '/:brandKitId/guidelines/pdf',
  requireWorkspaceRole(anyMember),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.downloadGuidelinePdf
);

router.get(
  '/:brandKitId/guidelines',
  requireWorkspaceRole(anyMember),
  validate(brandKitValidations.brandKitByIdSchema),
  brandKitController.getGuideline
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
