const express = require('express');
const multer = require('multer');
const path = require('path');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { checkWorkspaceAccess } = require('../../middlewares/workspaceAccess');
const validate = require('../../middlewares/validate.middleware');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const imageGenValidations = require('../validations/imageGen.validations');
const imageGenController = require('./imageGen.controller');
const contextController = require('./imageGen.context.controller');

const router = express.Router();

const MAX_FILE_BYTES =
  Number(process.env.IMAGE_GEN_CONTEXT_MAX_FILE_BYTES) > 0
    ? Number(process.env.IMAGE_GEN_CONTEXT_MAX_FILE_BYTES)
    : 20 * 1024 * 1024;

const MAX_FILES =
  Number(process.env.IMAGE_GEN_CONTEXT_MAX_FILES) > 0
    ? Number(process.env.IMAGE_GEN_CONTEXT_MAX_FILES)
    : 5;

const ALLOWED_EXTS = new Set([
  '.pdf',
  '.docx',
  '.doc',
  '.md',
  '.markdown',
  '.txt',
  '.png',
  '.jpg',
  '.jpeg',
  '.webp',
]);

const ALLOWED_MIMES = new Set([
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/msword',
  'text/markdown',
  'text/x-markdown',
  'text/plain',
  'image/png',
  'image/jpeg',
  'image/jpg',
  'image/webp',
]);

const uploadContextFiles = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_FILE_BYTES,
    files: MAX_FILES,
  },
  fileFilter: (req, file, cb) => {
    const name = String(file.originalname || '').toLowerCase();
    const ext = path.extname(name);
    const mime = String(file.mimetype || '').toLowerCase();
    if (!ALLOWED_MIMES.has(mime) && !ALLOWED_EXTS.has(ext)) {
      return cb(new AppError(messages.IMAGE_GEN_CONTEXT_UNSUPPORTED_TYPE, 400));
    }
    return cb(null, true);
  },
}).array('files', MAX_FILES);

/**
 * Parse multipart `payload` JSON string into req.body before Joi.
 */
function parseContextPayload(req, res, next) {
  try {
    let payload = {};
    if (req.body?.payload != null) {
      if (typeof req.body.payload === 'string') {
        const raw = req.body.payload.trim();
        payload = raw ? JSON.parse(raw) : {};
      } else if (typeof req.body.payload === 'object') {
        payload = req.body.payload;
      }
    } else if (req.body && typeof req.body === 'object') {
      // Allow flat form fields for convenience
      payload = {
        inlineText: req.body.inlineText,
        assetIds: req.body.assetIds,
      };
    }

    if (typeof payload.assetIds === 'string') {
      try {
        payload.assetIds = JSON.parse(payload.assetIds);
      } catch {
        payload.assetIds = payload.assetIds
          ? String(payload.assetIds)
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          : [];
      }
    }

    req.body = {
      inlineText: payload.inlineText,
      assetIds: Array.isArray(payload.assetIds) ? payload.assetIds : [],
    };
    return next();
  } catch (err) {
    return next(new AppError('Invalid context payload JSON', 400));
  }
}

router.get('/models', authMiddleware, imageGenController.listModels);
router.get('/formats', authMiddleware, imageGenController.listFormats);
router.get('/styles', authMiddleware, imageGenController.listStyles);
router.get('/archetypes', authMiddleware, imageGenController.listArchetypes);

router.get(
  '/workspaces/:workspaceId/estimate',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.estimateSchema),
  imageGenController.estimate
);

router.post(
  '/workspaces/:workspaceId/context',
  authMiddleware,
  checkWorkspaceAccess,
  (req, res, next) => {
    uploadContextFiles(req, res, (err) => {
      if (err) return next(err);
      return next();
    });
  },
  parseContextPayload,
  validate(imageGenValidations.createContextSchema),
  contextController.createContext
);

router.get(
  '/workspaces/:workspaceId/context/:contextId',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.getContextSchema),
  contextController.getContext
);

router.delete(
  '/workspaces/:workspaceId/context/:contextId',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.deleteContextSchema),
  contextController.deleteContext
);

router.post(
  '/workspaces/:workspaceId/generate',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.generateSchema),
  imageGenController.generate
);

router.get(
  '/workspaces/:workspaceId/threads',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.listThreadsSchema),
  imageGenController.listThreads
);

router.get(
  '/workspaces/:workspaceId/threads/:threadId',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.getThreadSchema),
  imageGenController.getThread
);

router.post(
  '/workspaces/:workspaceId/threads/:threadId/messages',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.sendThreadMessageSchema),
  imageGenController.sendThreadMessage
);

router.patch(
  '/workspaces/:workspaceId/threads/:threadId',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.renameThreadSchema),
  imageGenController.renameThread
);

router.post(
  '/workspaces/:workspaceId/threads/:threadId/move-folder',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.moveThreadSchema),
  imageGenController.moveThread
);

router.delete(
  '/workspaces/:workspaceId/threads/:threadId',
  authMiddleware,
  checkWorkspaceAccess,
  validate(imageGenValidations.deleteThreadSchema),
  imageGenController.deleteThread
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
