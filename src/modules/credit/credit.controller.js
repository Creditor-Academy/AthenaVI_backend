const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const creditService = require('./credit.service');
const messages = require('../../shared/utils/messages');

// GET /api/credits
const getCredits = asyncHandler(async (req, res) => {
  const workspaceId = req.workspace.id;

  const credits = await creditService.getAvailableCredits(workspaceId);

  return successResponse(
    req,
    res,
    {
      workspaceId,
      credits,
    },
    200,
    messages.CREDITS_FETCHED
  );
});

const getWorkspaceCreditHistory = asyncHandler(async (req, res) => {
  const workspaceId = req.workspace.id;

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;

  const history = await creditService.getWorkspaceCreditHistory({
    workspaceId,
    page,
    limit
  }
  );

  return successResponse(
    req,
    res,
    { history },
    200,
    messages.CREDIT_HISTORY_FETCHED
  );
});

const getUserCreditHistory = asyncHandler(async (req, res) => {
  const workspaceId = req.workspace.id;
  const userId = req.user.id;
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;

  const history = await creditService.getUserCreditHistory({
    workspaceId,
    userId,
    page,
    limit
  }
  );

  return successResponse(
    req,
    res,
    { history },
    200,
    messages.CREDIT_HISTORY_FETCHED
  );
});

module.exports = {
  getCredits,
  getWorkspaceCreditHistory,
  getUserCreditHistory,
};
