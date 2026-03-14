const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { uploadFile, deleteFile } = require('../s3/s3.service');
const userDao = require('./user.dao');

const getUserProfile = async (userId) => {
  // Implementation for fetching user profile

  const user = await userDao.getUserById(userId);

  if (!user) {
    throw new AppError('User not found', 404);
  }

  return user;
};

const updateUserProfile = async (userId, data) => {
  const allowedFields = ['name', 'phoneNumber'];

  const updateData = {};

  allowedFields.forEach((field) => {
    if (data[field] !== undefined) {
      updateData[field] = data[field];
    }
  });

  if (Object.keys(updateData).length === 0) {
    throw new AppError(messages.NO_VALID_FIELDS_PROVIDED, 204);
  }

  const updatedUser = await userDao.updateUserById(userId, updateData);

  return updatedUser;
};

const uploadProfileImageService = async (userId, file) => {
  const result = await uploadFile(
    file.buffer,
    userId,
    'profile-images',
    file.originalname,
    file.mimetype
  );

  const updatedUser = await userDao.updateUserProfileImageById(
    userId,
    result.url
  );

  return updatedUser;
};

const deleteProfileImageService = async (userId) => {
  const user = await userDao.getUserById(userId);

  if (!user || !user.profileImage) {
    throw new AppError(messages.PROFILE_IMAGE_NOT_FOUND, 404);
  }

  const imageUrl = user.profileImage;

  // extract S3 key from URL
  const key = imageUrl.split('.amazonaws.com/')[1];

  await deleteFile(key);

  const updatedUser =  await userDao.updateUserProfileImageById(userId, null);
  return updatedUser;
};

module.exports = {
  getUserProfile,
  updateUserProfile,
  uploadProfileImageService,
  deleteProfileImageService
};
