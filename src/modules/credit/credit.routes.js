const express = require('express');
const router = express.Router();
const creditController = require('./credit.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { requireWorkspaceRole } = require('../../middlewares/requireWorkspaceRole');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];
const ownerOrAdmin = ['OWNER', 'ADMIN'];
const ownerOnly = ['OWNER'];

router.get(
  '/:id', //:id = workspaceId
  authMiddleware,
  requireWorkspaceRole(ownerOrAdmin),
  creditController.getCredits
);

router.get(
  "/:id/history", //:id = workspaceId
  authMiddleware, 
  requireWorkspaceRole(ownerOrAdmin),
  creditController.getWorkspaceCreditHistory
);

router.get(
  "/:id/my-history", //:id = workspaceId
  authMiddleware,
  requireWorkspaceRole(anyMember),
  creditController.getUserCreditHistory
);


module.exports = router;
