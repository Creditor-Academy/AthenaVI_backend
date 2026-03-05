const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const creditService = require('./credit.service');
const messages = require('../../shared/utils/messages');

// GET /api/credits
const getCredits = asyncHandler(async (req, res) => {
  const availableCredits = await creditService.getAvailableCredits(req.user.id);

  return successResponse(
    req,
    res,
    {
      availableCredits,
    },
    200,
    messages.CREDITS_FETCHED
  );
});

// GET /api/credits/history
const getCreditHistory = asyncHandler(async (req, res) => {
  const history = await creditService.getCreditHistory(req.user.id);

  return successResponse(
    req,
    res,
    {history},
    200,
    messages.CREDIT_HISTORY_FETCHED
  );
});

module.exports = { getCredits, getCreditHistory };
