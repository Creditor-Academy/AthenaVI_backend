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

router.get('/notifications', authMiddleware, settingsController.getNotifications);

router.patch(
  '/notifications',
  authMiddleware,
  validate(settingsValidation.updateNotificationsValidation),
  settingsController.updateNotifications
);

router.get('/security', authMiddleware, settingsController.getSecurity);

router.patch(
  '/security',
  authMiddleware,
  validate(settingsValidation.updateSecurityValidation),
  settingsController.updateSecurity
);

router.patch(
  '/security/password',
  authMiddleware,
  validate(settingsValidation.changePasswordValidation),
  settingsController.changePassword
);

router.post(
  '/security/delete-account',
  authMiddleware,
  validate(settingsValidation.deleteAccountValidation),
  settingsController.deleteAccount
);

module.exports = router;
