const asyncHandler = require("../../shared/utils/asyncHandler");
const { successResponse } = require("../../shared/utils/apiResponse");
const creditService = require("./credit.service");

// GET /api/credits
const getCredits = asyncHandler(async (req, res) => {
  const availableCredits = await creditService.getAvailableCredits(req.user.id);

  return successResponse(req,res,{
    availableCredits,
  },200,"Credits fetched successfully");
});

// GET /api/credits/history
const getCreditHistory = asyncHandler(async (req, res) => {
  const history = await creditService.getCreditHistory(req.user.id);

  return successResponse(res, "Credit history fetched successfully", history);
});

module.exports= {getCredits,getCreditHistory}