const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const creditService = require('./credit.service');
const messages = require('../../shared/utils/messages');

const getPersonalCredits = asyncHandler(async (req, res) => {
  const data = await creditService.getPersonalCreditsView(req.user.id);
  return successResponse(req, res, data, 200, messages.CREDITS_FETCHED);
});

const getPersonalHistory = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const history = await creditService.getPersonalCreditHistory({
    userId: req.user.id,
    page,
    limit,
  });
  return successResponse(req, res, { history }, 200, messages.CREDIT_HISTORY_FETCHED);
});

const getPersonalEstimate = asyncHandler(async (req, res) => {
  const estimate = creditService.buildPersonalEstimate(req.query);
  return successResponse(
    req,
    res,
    { estimatedCredits: estimate.athenaCredits, breakdown: estimate.breakdown },
    200,
    messages.CREDITS_ESTIMATE_FETCHED
  );
});

const getCredits = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const data = await creditService.getWorkspaceCreditsView(workspaceId, req.user.id);
  return successResponse(
    req,
    res,
    {
      workspaceId,
      ...data,
    },
    200,
    messages.CREDITS_FETCHED
  );
});

const getWorkspaceCreditHistory = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;

  const history = await creditService.getWorkspaceCreditHistory({
    workspaceId,
    page,
    limit,
  });

  return successResponse(req, res, { history }, 200, messages.CREDIT_HISTORY_FETCHED);
});

const getUserCreditHistory = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const userId = req.user.id;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;

  const history = await creditService.getUserCreditHistory({
    workspaceId,
    userId,
    page,
    limit,
  });

  return successResponse(req, res, { history }, 200, messages.CREDIT_HISTORY_FETCHED);
});

const allocateCredits = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const { amount } = req.body;
  await creditService.allocateToWorkspace({
    ownerUserId: req.user.id,
    workspaceId,
    amount,
  });
  const balances = await creditService.getWorkspaceCreditsView(workspaceId, req.user.id);
  return successResponse(req, res, balances, 200, messages.CREDITS_ALLOCATED);
});

const deallocateCredits = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const { amount } = req.body;
  await creditService.deallocateFromWorkspace({
    ownerUserId: req.user.id,
    workspaceId,
    amount,
  });
  const balances = await creditService.getWorkspaceCreditsView(workspaceId, req.user.id);
  return successResponse(req, res, balances, 200, messages.CREDITS_DEALLOCATED);
});

const getUsageByMember = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const data = await creditService.getUsageByMember(workspaceId);
  return successResponse(req, res, data, 200, messages.CREDITS_USAGE_BY_MEMBER_FETCHED);
});

const getWorkspaceEstimate = asyncHandler(async (req, res) => {
  const estimate = creditService.buildWorkspaceEstimate(req.query);
  return successResponse(
    req,
    res,
    { estimatedCredits: estimate.athenaCredits, breakdown: estimate.breakdown },
    200,
    messages.CREDITS_ESTIMATE_FETCHED
  );
});

module.exports = {
  getPersonalCredits,
  getPersonalHistory,
  getPersonalEstimate,
  getCredits,
  getWorkspaceCreditHistory,
  getUserCreditHistory,
  allocateCredits,
  deallocateCredits,
  getUsageByMember,
  getWorkspaceEstimate,
};
