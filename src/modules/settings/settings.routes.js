const express = require('express');
const router = express.Router();
const settingsController = require('./settings.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const settingsValidation = require('../validations/settings.validations');

router.get('/appearance', authMiddleware, settingsController.getAppearance);

router.patch(
  '/appearance',
  authMiddleware,
  validate(settingsValidation.updateAppearanceValidation),
  settingsController.updateAppearance
);

module.exports = router;
