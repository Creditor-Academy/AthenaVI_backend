const express = require('express');
const router = express.Router({ mergeParams: true });
const { authMiddleware } = require('../../middlewares/auth.middlware');
const {
  requireWorkspaceRole,
} = require('../../middlewares/requireWorkspaceRole');
const {
  createTeamWorkspace,
  getUserWorkspaces,
  getWorkspaceById,
  deleteWorkspace,
  renameWorkspace,
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
const folderRoutes = require('../folder/folder.routes');
const projectRoutes = require('../project/project.routes');
const heygenVideoRoutes = require('../video/heygenVideo.routes');
const renderRoutes = require('../render/render.routes');
const speechRoutes = require('../speech/speech.routes');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];
const ownerOrAdmin = ['OWNER', 'ADMIN'];
const ownerOnly = ['OWNER'];

// nested routes
router.use(
  '/:workspaceId/folders',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  folderRoutes
);
router.use(
  '/:workspaceId/projects/:projectId/heygen',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  heygenVideoRoutes
);
router.use(
  '/:workspaceId/projects/:projectId/renders',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  renderRoutes
);
router.use(
  '/:workspaceId/projects/:projectId/speech',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  speechRoutes
);
router.use(
  '/:workspaceId/projects',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  projectRoutes
);

// workspace routes
router.post(
  '/',
  authMiddleware,
  validate(workspaceValidations.createWorkspaceSchema),
  createTeamWorkspace
);

router.get('/', authMiddleware, getUserWorkspaces);
router.get(
  '/:workspaceId',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(anyMember),
  getWorkspaceById
);
router.patch(
  '/:workspaceId',
  authMiddleware,
  validate(workspaceValidations.renameWorkspaceSchema),
  requireWorkspaceRole(ownerOnly),
  renameWorkspace
);
router.delete(
  '/:workspaceId',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(ownerOnly),
  deleteWorkspace
);

//invitation routes
router.get(
  '/:workspaceId/invitations',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(ownerOrAdmin),
  getWorkspaceInvitations
);

router.post(
  '/:workspaceId/invite',
  authMiddleware,
  validate(workspaceValidations.inviteMemberSchema),
  requireWorkspaceRole(ownerOrAdmin),
  inviteMember
);

router.delete(
  '/:workspaceId/invitations/:invitationId',
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
  '/:workspaceId/members',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(ownerOrAdmin),
  getWorkspaceMembers
);
router.patch(
  '/:workspaceId/members/:memberId/role',
  authMiddleware,
  validate(workspaceValidations.changeMemberRoleSchema),
  requireWorkspaceRole(ownerOnly),
  changeMemberRole
);
router.delete(
  '/:workspaceId/members/:memberId',
  authMiddleware,
  validate(workspaceValidations.removeMemberSchema),
  requireWorkspaceRole(ownerOrAdmin),
  removeMember
);

module.exports = router;
