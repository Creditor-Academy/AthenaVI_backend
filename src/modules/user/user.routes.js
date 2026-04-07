const express = require('express');
const router = express.Router();
const userController = require('./user.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const userValidation = require('../validations/user.validation');
const {uploadProfile} = require('../../middlewares/upload.middleware');

// GET /api/user - Get all users (public route for now)
router.get('/getall', authMiddleware, userController.getAllUsers);

// protected route to get user profile
router.get('/profile', authMiddleware, userController.getUserProfile);

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

module.exports = router;
