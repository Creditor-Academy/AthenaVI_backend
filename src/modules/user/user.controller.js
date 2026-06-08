const userDao = require('./user.dao');
const asyncHandler = require('../../shared/utils/asyncHandler');
const AppError = require('../../shared/utils/AppError');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const userService = require('./user.service');

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await userDao.getAllUsers();

  if (!users) {
    throw new AppError('This is a test error', 500);
  }

  return successResponse(
    req,
    res,
    {
      users,
      count: users.length,
    },
    200,
    messages.USERS_FETCHED_SUCCESSFULLY
  );
});

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
  getAllUsers,
  getUserProfile,
  getUserCapabilities,
  updateUserProfile,
  uploadProfileImage,
  deleteProfileImage,
};
