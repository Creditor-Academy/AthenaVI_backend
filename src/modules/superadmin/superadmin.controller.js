const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const superadminService = require('./superadmin.service');
const superadminAlertsService = require('./superadminAlerts.service');

const grantUserCredits = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { amount, reason } = req.body;
  const result = await superadminService.grantUserCredits({
    targetUserId: userId,
    amount,
    reason,
    grantedByUserId: req.user.id,
  });
  return successResponse(
    req,
    res,
    {
      user: { id: result.user.id, personalCredits: result.user.credits },
      transaction: result.transaction,
    },
    200,
    messages.CREDITS_GRANTED
  );
});

const revokeUserCredits = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { amount, reason } = req.body;
  const result = await superadminService.revokeUserCredits({
    targetUserId: userId,
    amount,
    reason,
    revokedByUserId: req.user.id,
  });
  return successResponse(
    req,
    res,
    {
      user: { id: result.user.id, personalCredits: result.user.credits },
      transaction: result.transaction,
    },
    200,
    messages.CREDITS_REVOKED
  );
});

const getUserCredits = asyncHandler(async (req, res) => {
  const summary = await superadminService.getUserCreditsSummary(req.params.userId);
  return successResponse(req, res, summary, 200, messages.CREDITS_FETCHED);
});

const getUserCreditHistory = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const history = await superadminService.getUserCreditHistory(
    req.params.userId,
    page,
    limit,
    req.query.type
  );
  return successResponse(req, res, { history }, 200, messages.CREDIT_HISTORY_FETCHED);
});

const listUsers = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const result = await superadminService.listUsers({
    page,
    limit,
    search: req.query.search,
  });
  return successResponse(req, res, result, 200, messages.CREDITS_FETCHED);
});

const updateUserPlatformAccess = asyncHandler(async (req, res) => {
  const result = await superadminService.updateUserPlatformAccess({
    targetUserId: req.params.userId,
    isPlatformSuperadmin: req.body.isPlatformSuperadmin,
    actorUserId: req.user.id,
  });
  return successResponse(req, res, result, 200, messages.PLATFORM_ACCESS_UPDATED);
});

const getWorkspaceCredits = asyncHandler(async (req, res) => {
  const summary = await superadminService.getWorkspaceCreditsSummary(req.params.workspaceId);
  return successResponse(req, res, summary, 200, messages.CREDITS_FETCHED);
});

const grantWorkspaceCredits = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const { amount, reason } = req.body;
  const result = await superadminService.grantWorkspaceCredits({
    workspaceId,
    amount,
    reason,
    grantedByUserId: req.user.id,
  });
  return successResponse(
    req,
    res,
    {
      workspace: {
        id: result.workspace.id,
        workspaceCredits: result.workspace.credits,
      },
      transaction: result.transaction,
    },
    200,
    messages.CREDITS_GRANTED
  );
});

const revokeWorkspaceCredits = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const { amount, reason } = req.body;
  const result = await superadminService.revokeWorkspaceCredits({
    workspaceId,
    amount,
    reason,
    revokedByUserId: req.user.id,
  });
  return successResponse(
    req,
    res,
    {
      workspace: {
        id: result.workspace.id,
        workspaceCredits: result.workspace.credits,
      },
      transaction: result.transaction,
    },
    200,
    messages.CREDITS_REVOKED
  );
});

const listWorkspaces = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const result = await superadminService.listWorkspaces({
    page,
    limit,
    search: req.query.search,
  });
  return successResponse(req, res, result, 200, messages.WORKSPACES_FETCHED);
});

const getWorkspaceCreditHistory = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const history = await superadminService.getWorkspaceCreditHistory(
    req.params.workspaceId,
    page,
    limit,
    req.query.type
  );
  return successResponse(req, res, { history }, 200, messages.CREDIT_HISTORY_FETCHED);
});

const getWorkspaceUsageByMember = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const result = await superadminService.getWorkspaceUsageByMember(
    req.params.workspaceId,
    page,
    limit
  );
  return successResponse(req, res, result, 200, messages.CREDITS_USAGE_BY_MEMBER_FETCHED);
});

const getUsageReport = asyncHandler(async (req, res) => {
  const report = await superadminService.getUsageReport({
    from: req.query.from,
    to: req.query.to,
    workspaceId: req.query.workspaceId,
    userId: req.query.userId,
    topLimit: req.query.topLimit ? parseInt(req.query.topLimit, 10) : 10,
  });
  return successResponse(req, res, { report }, 200, messages.CREDITS_FETCHED);
});

const getPlatformActionsReport = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const result = await superadminService.getPlatformActionsReport({
    page,
    limit,
    from: req.query.from,
    to: req.query.to,
    type: req.query.type,
    scope: req.query.scope,
  });
  return successResponse(req, res, result, 200, messages.PLATFORM_ACTIONS_REPORT_FETCHED);
});

const getHeygenAccount = asyncHandler(async (req, res) => {
  const account = await superadminService.getHeygenAccountBilling();
  return successResponse(req, res, { account }, 200, messages.HEYGEN_ACCOUNT_FETCHED);
});

const getUserStorage = asyncHandler(async (req, res) => {
  const summary = await superadminService.getUserStorageSummary(req.params.userId);
  return successResponse(req, res, summary, 200, messages.STORAGE_FETCHED);
});

const getUserStorageHistory = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const history = await superadminService.getUserStorageHistory(
    req.params.userId,
    page,
    limit,
    req.query.type
  );
  return successResponse(req, res, { history }, 200, messages.STORAGE_HISTORY_FETCHED);
});

const getStorageTiers = asyncHandler(async (req, res) => {
  const tiers = await superadminService.getStorageTiers();
  return successResponse(req, res, { tiers }, 200, messages.STORAGE_TIERS_FETCHED);
});

const grantUserStorage = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { tierId, additionalBytes, reason } = req.body;
  const result = await superadminService.grantUserStorage({
    targetUserId: userId,
    tierId,
    additionalBytes,
    reason,
    grantedByUserId: req.user.id,
  });
  return successResponse(
    req,
    res,
    {
      user: {
        id: result.user.id,
        storageLimit: result.user.storageLimit,
        storageUsed: result.user.storageUsed,
      },
      transaction: result.transaction,
    },
    200,
    messages.STORAGE_GRANTED
  );
});

const revokeUserStorage = asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { amountBytes, reason } = req.body;
  const result = await superadminService.revokeUserStorage({
    targetUserId: userId,
    amountBytes,
    reason,
    revokedByUserId: req.user.id,
  });
  return successResponse(
    req,
    res,
    {
      user: {
        id: result.user.id,
        storageLimit: result.user.storageLimit,
        storageUsed: result.user.storageUsed,
      },
      transaction: result.transaction,
    },
    200,
    messages.STORAGE_REVOKED
  );
});

const listStorageUpgradeRequests = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const result = await superadminService.listStorageUpgradeRequests(
    page,
    limit,
    req.query.status
  );
  return successResponse(req, res, result, 200, messages.STORAGE_UPGRADE_REQUESTS_FETCHED);
});

const rejectStorageUpgradeRequest = asyncHandler(async (req, res) => {
  const result = await superadminService.rejectStorageUpgradeRequest({
    requestId: req.params.requestId,
    reviewedByUserId: req.user.id,
    reviewNote: req.body.reviewNote,
  });
  return successResponse(req, res, result, 200, messages.STORAGE_UPGRADE_REQUEST_REJECTED);
});

const getAlertsSummary = asyncHandler(async (req, res) => {
  const summary = await superadminAlertsService.getAlertsSummary(req.user.id);
  return successResponse(req, res, summary, 200, messages.SUPERADMIN_ALERTS_FETCHED);
});

module.exports = {
  grantUserCredits,
  revokeUserCredits,
  getUserCredits,
  getUserCreditHistory,
  listUsers,
  updateUserPlatformAccess,
  getWorkspaceCredits,
  grantWorkspaceCredits,
  revokeWorkspaceCredits,
  listWorkspaces,
  getWorkspaceCreditHistory,
  getWorkspaceUsageByMember,
  getUsageReport,
  getPlatformActionsReport,
  getHeygenAccount,
  getUserStorage,
  getUserStorageHistory,
  getStorageTiers,
  grantUserStorage,
  revokeUserStorage,
  listStorageUpgradeRequests,
  rejectStorageUpgradeRequest,
  getAlertsSummary,
};
