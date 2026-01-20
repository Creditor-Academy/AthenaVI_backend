const userDao = require("./user.dao");
const asyncHandler = require("../../shared/utils/asyncHandler");
const AppError = require("../../shared/utils/AppError");
const { successResponse } = require("../../shared/utils/apiResponse");
const messages = require("../../shared/utils/messages");

const getAllUsers = asyncHandler(async (req, res) => {

  const users = await userDao.getAllUsers();

  if(!users){
     throw new AppError("This is a test error", 500);
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

module.exports = {
  getAllUsers,
};
