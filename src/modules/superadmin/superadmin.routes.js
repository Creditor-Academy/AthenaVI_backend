const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { requirePlatformSuperadmin } = require('../../middlewares/requirePlatformSuperadmin');
const superadminController = require('./superadmin.controller');
const superadminValidation = require('../validations/superadmin.validations');

const router = express.Router();

router.use(authMiddleware, requirePlatformSuperadmin);

router.get(
  '/users',
  validate(superadminValidation.listUsersQuerySchema),
  superadminController.listUsers
);

router.patch(
  '/users/:userId/platform-access',
  validate(superadminValidation.platformAccessBodySchema),
  superadminController.updateUserPlatformAccess
);

router.get(
  '/users/:userId/credits',
  validate(superadminValidation.userIdParamsSchema),
  superadminController.getUserCredits
);

router.get(
  '/users/:userId/credits/history',
  validate(superadminValidation.historyQuerySchema),
  superadminController.getUserCreditHistory
);

router.get(
  '/users/:userId/storage',
  validate(superadminValidation.userIdParamsSchema),
  superadminController.getUserStorage
);

router.get(
  '/users/:userId/storage/history',
  validate(superadminValidation.storageHistoryQuerySchema),
  superadminController.getUserStorageHistory
);

router.post(
  '/users/:userId/storage/grant',
  validate(superadminValidation.grantStorageBodySchema),
  superadminController.grantUserStorage
);

router.post(
  '/users/:userId/storage/revoke',
  validate(superadminValidation.revokeStorageBodySchema),
  superadminController.revokeUserStorage
);

router.post(
  '/users/:userId/credits/grant',
  validate(superadminValidation.grantRevokeBodySchema),
  superadminController.grantUserCredits
);

router.post(
  '/users/:userId/credits/revoke',
  validate(superadminValidation.grantRevokeBodySchema),
  superadminController.revokeUserCredits
);

router.get('/storage/tiers', superadminController.getStorageTiers);

router.get(
  '/storage/requests',
  validate(superadminValidation.storageRequestsQuerySchema),
  superadminController.listStorageUpgradeRequests
);

router.post(
  '/storage/requests/:requestId/reject',
  validate(superadminValidation.rejectStorageRequestBodySchema),
  superadminController.rejectStorageUpgradeRequest
);

router.get(
  '/workspaces',
  validate(superadminValidation.listWorkspacesQuerySchema),
  superadminController.listWorkspaces
);

router.get(
  '/workspaces/:workspaceId/credits',
  validate(superadminValidation.workspaceIdParamsSchema),
  superadminController.getWorkspaceCredits
);

router.get(
  '/workspaces/:workspaceId/credits/history',
  validate(superadminValidation.workspaceHistoryQuerySchema),
  superadminController.getWorkspaceCreditHistory
);

router.get(
  '/workspaces/:workspaceId/credits/usage-by-member',
  validate(superadminValidation.workspacePaginationQuerySchema),
  superadminController.getWorkspaceUsageByMember
);

router.post(
  '/workspaces/:workspaceId/credits/grant',
  validate(superadminValidation.grantRevokeWorkspaceBodySchema),
  superadminController.grantWorkspaceCredits
);

router.post(
  '/workspaces/:workspaceId/credits/revoke',
  validate(superadminValidation.grantRevokeWorkspaceBodySchema),
  superadminController.revokeWorkspaceCredits
);

router.get(
  '/reports/credits/usage',
  validate(superadminValidation.usageReportQuerySchema),
  superadminController.getUsageReport
);

router.get(
  '/reports/credits/platform-actions',
  validate(superadminValidation.platformActionsQuerySchema),
  superadminController.getPlatformActionsReport
);

router.get('/heygen/account', superadminController.getHeygenAccount);

router.get('/alerts/summary', superadminController.getAlertsSummary);

module.exports = router;
