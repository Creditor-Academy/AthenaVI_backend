const express = require('express');
const multer = require('multer');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const validate = require('../../middlewares/validate.middleware');
const presentationValidations = require('../validations/presentation.validations');
const presentationController = require('./presentation.controller');

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

router.post(
  '/',
  validate(presentationValidations.createPresentationSchema),
  presentationController.createPresentation
);

router.get(
  '/:presentationId',
  validate(presentationValidations.presentationByIdSchema),
  presentationController.getPresentation
);

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
  '/:presentationId/generate',
  validate(presentationValidations.generateDeckSchema),
  presentationController.startGenerate
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
