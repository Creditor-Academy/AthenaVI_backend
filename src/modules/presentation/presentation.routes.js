const express = require('express');
const multer = require('multer');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const validate = require('../../middlewares/validate.middleware');
const { uploadAssetS3 } = require('../../middlewares/upload.middleware');
const presentationValidations = require('../validations/presentation.validations');
const presentationController = require('./presentation.controller');
const presentationShareRoutes = require('../presentationShare/presentationShare.routes');
const presentationCommentRoutes = require('../presentationComment/presentationComment.routes');

const router = express.Router({ mergeParams: true });

const uploadOutlineDocument = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 20 * 1024 * 1024,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    const allowed = [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword',
    ];
    const name = String(file.originalname || '').toLowerCase();
    const okMime = allowed.includes(file.mimetype);
    const okExt = name.endsWith('.pdf') || name.endsWith('.docx') || name.endsWith('.doc');
    if (!okMime && !okExt) {
      return cb(new AppError(messages.PRESENTATION_DOCUMENT_UNPARSEABLE, 400));
    }
    return cb(null, true);
  },
}).single('file');

/**
 * Deck cover captured by the frontend from the live preview. Intentionally not `uploadAssetS3`:
 * that allows 50MB and video/audio, neither of which belongs in a thumbnail.
 */
const uploadCoverImage = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new AppError(messages.INVALID_IMAGE_TYPE, 400));
    }
    return cb(null, true);
  },
}).single('file');

router.post(
  '/',
  validate(presentationValidations.createPresentationSchema),
  presentationController.createPresentation
);

router.get(
  '/',
  validate(presentationValidations.listPresentationsSchema),
  presentationController.listPresentations
);

router.get(
  '/:presentationId',
  validate(presentationValidations.presentationByIdSchema),
  presentationController.getPresentation
);

router.get(
  '/:presentationId/preview',
  validate(presentationValidations.presentationPreviewSchema),
  presentationController.getPresentationPreview
);

router.put(
  '/:presentationId/thumbnail',
  validate(presentationValidations.updatePresentationThumbnailSchema),
  presentationController.updateThumbnail
);

router.put(
  '/:presentationId/thumbnail/image',
  uploadCoverImage,
  validate(presentationValidations.uploadPresentationCoverSchema),
  presentationController.uploadPresentationCover
);

router.use('/:presentationId/share', presentationShareRoutes);
router.use('/:presentationId/comments', presentationCommentRoutes);

router.get(
  '/:presentationId/status',
  validate(presentationValidations.presentationByIdSchema),
  presentationController.getStatus
);

router.get(
  '/:presentationId/credit-estimate',
  validate(presentationValidations.creditEstimateSchema),
  presentationController.creditEstimate
);

router.post(
  '/:presentationId/outline',
  (req, res, next) => {
    uploadOutlineDocument(req, res, (err) => {
      if (err) return next(err);
      return next();
    });
  },
  validate(presentationValidations.generateOutlineSchema),
  presentationController.generateOutline
);

router.patch(
  '/:presentationId/outline',
  validate(presentationValidations.patchOutlineSchema),
  presentationController.updateOutline
);

router.post(
  '/:presentationId/theme',
  validate(presentationValidations.setThemeSchema),
  presentationController.setTheme
);

router.post(
  '/:presentationId/apply-brand-kit',
  validate(presentationValidations.applyBrandKitSchema),
  presentationController.applyBrandKit
);

router.post(
  '/:presentationId/generate',
  validate(presentationValidations.generateDeckSchema),
  presentationController.startGenerate
);

router.patch(
  '/:presentationId/slides/reorder',
  validate(presentationValidations.reorderSlidesSchema),
  presentationController.reorderSlides
);

router.post(
  '/:presentationId/slides',
  validate(presentationValidations.addSlideSchema),
  presentationController.addSlide
);

router.get(
  '/:presentationId/slides/:slideId',
  validate(presentationValidations.slideByIdSchema),
  presentationController.getSlide
);

router.delete(
  '/:presentationId/slides/:slideId',
  validate(presentationValidations.slideByIdSchema),
  presentationController.deleteSlide
);

router.post(
  '/:presentationId/slides/:slideId/duplicate',
  validate(presentationValidations.slideByIdSchema),
  presentationController.duplicateSlide
);

router.post(
  '/:presentationId/slides/:slideId/apply-layout',
  validate(presentationValidations.applyLayoutSchema),
  presentationController.applyLayout
);

router.put(
  '/:presentationId/slides/:slideId/canvas',
  validate(presentationValidations.putCanvasSchema),
  presentationController.putCanvas
);

router.patch(
  '/:presentationId/slides/:slideId/elements/reorder',
  validate(presentationValidations.reorderElementsSchema),
  presentationController.reorderElements
);

router.patch(
  '/:presentationId/slides/:slideId/elements/batch',
  validate(presentationValidations.patchElementsBatchSchema),
  presentationController.patchElementsBatch
);

router.post(
  '/:presentationId/slides/:slideId/elements/group',
  validate(presentationValidations.groupElementsSchema),
  presentationController.groupElements
);

router.post(
  '/:presentationId/slides/:slideId/elements/ungroup',
  validate(presentationValidations.ungroupElementsSchema),
  presentationController.ungroupElements
);

router.post(
  '/:presentationId/slides/:slideId/elements/align',
  validate(presentationValidations.alignElementsSchema),
  presentationController.alignElements
);

router.post(
  '/:presentationId/slides/:slideId/elements',
  validate(presentationValidations.addElementSchema),
  presentationController.addElement
);

router.patch(
  '/:presentationId/slides/:slideId/elements/:elementId',
  validate(presentationValidations.patchElementSchema),
  presentationController.patchElement
);

router.delete(
  '/:presentationId/slides/:slideId/elements/:elementId',
  validate(presentationValidations.elementByIdSchema),
  presentationController.deleteElement
);

router.patch(
  '/:presentationId/slides/:slideId',
  validate(presentationValidations.patchSlideSchema),
  presentationController.patchSlide
);

router.post(
  '/:presentationId/slides/:slideId/regenerate',
  validate(presentationValidations.regenerateSlideSchema),
  presentationController.regenerateSlide
);

router.post(
  '/:presentationId/slides/:slideId/media',
  uploadAssetS3.single('file'),
  validate(presentationValidations.uploadSlideMediaSchema),
  presentationController.uploadSlideMedia
);

router.post(
  '/:presentationId/slides/:slideId/attach-asset',
  validate(presentationValidations.attachSlideAssetSchema),
  presentationController.attachSlideAsset
);

router.post(
  '/:presentationId/slides/:slideId/insert-stock',
  validate(presentationValidations.insertSlideStockSchema),
  presentationController.insertSlideStock
);

router.post(
  '/:presentationId/export',
  validate(presentationValidations.exportDeckSchema),
  presentationController.queueExport
);

router.get(
  '/:presentationId/export/:exportId',
  validate(presentationValidations.exportByIdSchema),
  presentationController.getExport
);

module.exports = router;
