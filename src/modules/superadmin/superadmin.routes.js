const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { requirePlatformSuperadmin } = require('../../middlewares/requirePlatformSuperadmin');
const { uploadAssetS3 } = require('../../middlewares/upload.middleware');
const superadminController = require('./superadmin.controller');
const templateAdminController = require('../templates/templateAdmin.controller');
const superadminValidation = require('../validations/superadmin.validations');
const videoTemplateValidation = require('../validations/videoTemplate.validations');

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

router.get(
  '/early-access/requests',
  validate(superadminValidation.earlyAccessRequestsQuerySchema),
  superadminController.listEarlyAccessRequests
);

router.get(
  '/early-access/requests/:requestId',
  validate(superadminValidation.earlyAccessRequestIdParamsSchema),
  superadminController.getEarlyAccessRequest
);

router.post(
  '/early-access/requests/:requestId/approve',
  validate(superadminValidation.earlyAccessRequestIdParamsSchema),
  superadminController.approveEarlyAccessRequest
);

router.post(
  '/early-access/requests/:requestId/reject',
  validate(superadminValidation.earlyAccessRequestIdParamsSchema),
  superadminController.rejectEarlyAccessRequest
);

router.patch(
  '/early-access/requests/:requestId/status',
  validate(superadminValidation.earlyAccessUpdateStatusBodySchema),
  superadminController.updateEarlyAccessRequestStatus
);

router.get('/alerts/summary', superadminController.getAlertsSummary);

router.get(
  '/broadcasts/product-email',
  validate(superadminValidation.productEmailBroadcastHistoryQuerySchema),
  superadminController.listProductEmailBroadcasts
);

router.get(
  '/broadcasts/product-email/:broadcastId',
  validate(superadminValidation.broadcastIdParamsSchema),
  superadminController.getProductEmailBroadcast
);

router.get(
  '/broadcasts/product-email/:broadcastId/recipients',
  validate(superadminValidation.productEmailBroadcastRecipientsQuerySchema),
  superadminController.listProductEmailBroadcastRecipients
);

router.post(
  '/broadcasts/product-email',
  validate(superadminValidation.productEmailBroadcastBodySchema),
  superadminController.sendProductEmailBroadcast
);

router.get(
  '/templates',
  validate(videoTemplateValidation.listTemplatesAdminSchema),
  templateAdminController.listTemplates
);

router.post(
  '/templates',
  validate(videoTemplateValidation.createTemplateAdminBodySchema),
  templateAdminController.createTemplate
);

router.get(
  '/templates/:templateId',
  validate(videoTemplateValidation.templateIdAdminParamsSchema),
  templateAdminController.getTemplate
);

router.patch(
  '/templates/:templateId',
  validate(videoTemplateValidation.updateTemplateAdminSchema),
  templateAdminController.updateTemplate
);

router.get(
  '/templates/:templateId/media',
  validate(videoTemplateValidation.templateIdAdminParamsSchema),
  templateAdminController.listTemplateMedia
);

router.post(
  '/templates/:templateId/media',
  uploadAssetS3.single('file'),
  validate(videoTemplateValidation.uploadTemplateMediaAdminSchema),
  templateAdminController.uploadTemplateMedia
);

router.delete(
  '/templates/:templateId/media/:mediaId',
  validate(videoTemplateValidation.templateMediaIdAdminParamsSchema),
  templateAdminController.deleteTemplateMedia
);

module.exports = router;
