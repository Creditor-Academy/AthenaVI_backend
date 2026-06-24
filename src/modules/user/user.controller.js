const asyncHandler = require('../../shared/utils/asyncHandler');
const AppError = require('../../shared/utils/AppError');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const userService = require('./user.service');

const getUserProfile = asyncHandler(async (req, res) => {
  const userId = req.user.id;

  const profileData = await userService.getUserProfile(userId);

  return successResponse(
    req,
    res,
    {
      profile: profileData,
    },
    200,
    messages.USER_PROFILE_FETCHED_SUCCESSFULLY
  );
});

const getUserCapabilities = asyncHandler(async (req, res) => {
  const capabilities = await userService.getUserCapabilities(req.user.id);
  return successResponse(req, res, capabilities, 200, messages.USER_PROFILE_FETCHED_SUCCESSFULLY);
});

const updateUserProfile = asyncHandler(async (req, res) => {
  // Implementation for updating user profile

  const userId = req.user.id;
  console.log(userId);
  console.log(req.body);

  const updatedProfile = await userService.updateUserProfile(userId, req.body);

  return successResponse(
    req,
    res,
    {
      profile: updatedProfile,
    },
    200,
    messages.USER_PROFILE_FETCHED_SUCCESSFULLY
  );
});

const uploadProfileImage = asyncHandler(async (req, res) => {
  if (!req.file) {
    throw new AppError(messages.PROFILE_IMAGE_REQUIRED, 400);
  }

  const userId = req.user.id;

  const result = await userService.uploadProfileImageService(userId, req.file);
  return successResponse(
    req,
    res,
    {
      profile: result,
    },
    200,
    messages.PROFILE_IMAGE_UPLOADED_SUCCESSFULLY
  );
});

const deleteProfileImage = asyncHandler(async (req, res) => {
  const userId = req.user.id;

  const deleteUserProfile = await userService.deleteProfileImageService(userId);
  return successResponse(
    req,
    res,
    {
      profile: deleteUserProfile,
    },
    200,
    messages.PROFILE_IMAGE_DELETED_SUCCESSFULLY
  );
});

module.exports = {
  getUserProfile,
  getUserCapabilities,
  updateUserProfile,
  uploadProfileImage,
  deleteProfileImage,
};
