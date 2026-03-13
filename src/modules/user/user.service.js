const AppError = require("../../shared/utils/AppError");
const messages = require("../../shared/utils/messages");
const userDao = require("./user.dao");


const getUserProfile = async (userId) => {
  // Implementation for fetching user profile

  const user = await userDao.getUserById(userId);

  if(!user){
    throw new AppError("User not found", 404);
  }

    return user;
};


const updateUserProfile = async (userId, data) => {
 const allowedFields = ["name", "phoneNumber"];

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

}

module.exports = {
  getUserProfile,
  updateUserProfile
};