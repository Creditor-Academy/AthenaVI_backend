const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../../middlewares/auth.middlware');
const {
  requireWorkspaceRole,
} = require('../../middlewares/requireWorkspaceRole');
const {
  createTeamWorkspace,
  getUserWorkspaces,
  getWorkspaceById,
  deleteWorkspace,
  getWorkspaceMembers,
  inviteMember,
  acceptInvitation,
  removeMember,
  changeMemberRole,
  cancelInvitation,
  getWorkspaceInvitations,
} = require('./workspace.controller');
const workspaceValidations = require('../validations/workspace.validations');
const validate = require('../../middlewares/validate.middleware');
const videoRoutes = require('../video/video.routes');
const renderController = require('../render/render.controller');
const renderValidations = require('../validations/render.validations');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];
const ownerOrAdmin = ['OWNER', 'ADMIN'];
const ownerOnly = ['OWNER'];

// workspace routes
router.post(
  '/',
  authMiddleware,
  validate(workspaceValidations.createWorkspaceSchema),
  createTeamWorkspace
);

router.get('/', authMiddleware, getUserWorkspaces);

router.use(
  '/:id/videos',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(anyMember),
  videoRoutes
);

router.get(
  '/:id/render/:jobId',
  authMiddleware,
  validate(renderValidations.getRenderJobSchema),
  requireWorkspaceRole(anyMember),
  renderController.getRenderJob
);

router.get(
  '/:id',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(anyMember),
  getWorkspaceById
);
router.delete(
  '/:id',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(ownerOnly),
  deleteWorkspace
);

//invitation routes
router.get(
  '/:id/invitations',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(ownerOrAdmin),
  getWorkspaceInvitations
);

router.post(
  '/:id/invite',
  authMiddleware,
  validate(workspaceValidations.inviteMemberSchema),
  requireWorkspaceRole(ownerOrAdmin),
  inviteMember
);

router.delete(
  '/:id/invitations/:invitationId',
  authMiddleware,
  validate(workspaceValidations.cancelInvitationSchema),
  requireWorkspaceRole(ownerOrAdmin),
  cancelInvitation
);

router.post(
  '/invitations/accept',
  authMiddleware,
  validate(workspaceValidations.acceptInvitationSchema),
  acceptInvitation
);

//member management routes
router.get(
  '/:id/members',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(ownerOrAdmin),
  getWorkspaceMembers
);
router.patch(
  '/:id/members/:memberId/role',
  authMiddleware,
  validate(workspaceValidations.changeMemberRoleSchema),
  requireWorkspaceRole(ownerOnly),
  changeMemberRole
);
router.delete(
  '/:id/members/:memberId',
  authMiddleware,
  validate(workspaceValidations.removeMemberSchema),
  requireWorkspaceRole(ownerOrAdmin),
  removeMember
);

module.exports = router;
