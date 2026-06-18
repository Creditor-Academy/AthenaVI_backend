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

router.get(
  '/workspaces/:workspaceId/credits',
  validate(superadminValidation.workspaceIdParamsSchema),
  superadminController.getWorkspaceCredits
);

router.post(
  '/workspaces/:workspaceId/credits/grant',
  validate(superadminValidation.grantRevokeWorkspaceBodySchema),
  superadminController.grantWorkspaceCredits
);

router.get(
  '/reports/credits/usage',
  validate(superadminValidation.usageReportQuerySchema),
  superadminController.getUsageReport
);

router.get('/heygen/account', superadminController.getHeygenAccount);

module.exports = router;
