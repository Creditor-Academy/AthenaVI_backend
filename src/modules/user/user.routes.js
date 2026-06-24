const express = require('express');
const router = express.Router();
const userController = require('./user.controller');
const settingsRoutes = require('../settings/settings.routes');
const inboxRoutes = require('../inbox/inbox.routes');
const storageRoutes = require('../storage/storage.routes');
const renderController = require('../render/render.controller');
const renderValidations = require('../render/render.validation');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const userValidation = require('../validations/user.validation');
const {uploadProfile} = require('../../middlewares/upload.middleware');

// protected route to get user profile
router.get('/profile', authMiddleware, userController.getUserProfile);
router.get('/capabilities', authMiddleware, userController.getUserCapabilities);

router.patch(
  '/profile',
  authMiddleware,
  validate(userValidation.updateUserProfileValidation),
  userController.updateUserProfile
);

// upload routes

router.post(
  '/upload/profile-image',
  authMiddleware,
  uploadProfile.single('profileImage'),
  userController.uploadProfileImage
);

router.delete(
  '/profile-image',
  authMiddleware,
  userController.deleteProfileImage
);

router.get(
  '/videos',
  authMiddleware,
  validate(renderValidations.ownerVideosSchema),
  renderController.listOwnerVideos
);

router.use('/settings', settingsRoutes);
router.use('/inbox', inboxRoutes);
router.use('/storage', storageRoutes);

module.exports = router;
