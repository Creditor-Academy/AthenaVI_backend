const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { checkWorkspaceAccess } = require('../../middlewares/workspaceAccess');
const validate = require('../../middlewares/validate.middleware');
const imageGenValidations = require('../validations/imageGen.validations');
const imageGenController = require('./imageGen.controller');

const router = express.Router();

router.get('/models', authMiddleware, imageGenController.listModels);
router.get('/formats', authMiddleware, imageGenController.listFormats);
router.get('/styles', authMiddleware, imageGenController.listStyles);

router.get(
  '/workspaces/:workspaceId/estimate',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.estimateSchema),
  imageGenController.estimate
);

router.post(
  '/workspaces/:workspaceId/generate',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.generateSchema),
  imageGenController.generate
);

router.get(
  '/workspaces/:workspaceId/generations',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.listGenerationsSchema),
  imageGenController.listGenerations
);

router.get(
  '/workspaces/:workspaceId/generations/:generationId',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.getGenerationSchema),
  imageGenController.getGeneration
);

router.post(
  '/workspaces/:workspaceId/generations/:generationId/regenerate',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.regenerateSchema),
  imageGenController.regenerate
);

router.post(
  '/workspaces/:workspaceId/generations/:generationId/tweak',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.tweakSchema),
  imageGenController.tweak
);

router.get(
  '/workspaces/:workspaceId/generations/:generationId/download',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.downloadSchema),
  imageGenController.download
);

module.exports = router;
