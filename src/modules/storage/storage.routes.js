const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const storageController = require('./storage.controller');
const storageValidations = require('../validations/storage.validations');

const router = express.Router();

router.get(
  '/',
  authMiddleware,
  validate(storageValidations.storageSummarySchema),
  storageController.getMyStorage
);
router.get(
  '/history',
  authMiddleware,
  validate(storageValidations.storageHistoryQuerySchema),
  storageController.getMyStorageHistory
);
router.get(
  '/requests',
  authMiddleware,
  validate(storageValidations.storageUpgradeRequestsQuerySchema),
  storageController.getMyStorageUpgradeRequests
);
router.post(
  '/request',
  authMiddleware,
  validate(storageValidations.storageUpgradeRequestBodySchema),
  storageController.requestStorageUpgrade
);

module.exports = router;
