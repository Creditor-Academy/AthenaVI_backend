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
  getWorkspaceStorage,
  deleteWorkspace,
  renameWorkspace,
  getWorkspaceMembers,
  inviteMember,
  acceptInvitation,
  getInvitationPreview,
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
const renderController = require('../render/render.controller');
const renderValidations = require('../render/render.validation');
const speechRoutes = require('../speech/speech.routes');
const commentRoutes = require('../comment/comment.routes');
const heygenShareRoutes = require('../heygen/heygenShare.routes');
const presentationRoutes = require('../presentation/presentation.routes');
const presentationController = require('../presentation/presentation.controller');
const presentationValidations = require('../validations/presentation.validations');
const brandKitRoutes = require('../brandKit/brandKit.routes');
const videoTemplateController = require('../project/videoTemplate.controller');
const videoTemplateValidations = require('../validations/videoTemplate.validations');
const workspaceLibraryController = require('./workspaceLibrary.controller');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];
const ownerOrAdmin = ['OWNER', 'ADMIN'];
const ownerOnly = ['OWNER'];

// nested routes
router.get(
  '/:workspaceId/library',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(workspaceValidations.listWorkspaceLibrarySchema),
  workspaceLibraryController.getLibrary
);
router.get(
  '/:workspaceId/presentation-templates',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(presentationValidations.listWorkspacePresentationTemplatesSchema),
  presentationController.listPresentationTemplates
);
router.get(
  '/:workspaceId/presentation-themes',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(presentationValidations.listWorkspacePresentationThemesSchema),
  presentationController.listPresentationThemes
);
router.get(
  '/:workspaceId/presentation-elements',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(presentationValidations.listWorkspacePresentationElementsSchema),
  presentationController.listPresentationElements
);
router.use(
  '/:workspaceId/presentations',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  presentationRoutes
);
router.use('/:workspaceId/brand-kits', authMiddleware, brandKitRoutes);
router.get(
  '/:workspaceId/presentation-deck-packs',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(presentationValidations.listWorkspacePresentationDeckPacksSchema),
  presentationController.listPresentationDeckPacks
);
router.get(
  '/:workspaceId/video-templates',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(videoTemplateValidations.listWorkspaceVideoTemplatesSchema),
  videoTemplateController.listVideoTemplates
);
router.get(
  '/:workspaceId/video-templates/:templateId',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(videoTemplateValidations.workspaceVideoTemplateByIdSchema),
  videoTemplateController.getVideoTemplate
);
router.use(
  '/:workspaceId/heygen',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  heygenShareRoutes
);
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
router.get(
  '/:workspaceId/videos',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(renderValidations.workspaceVideosSchema),
  renderController.listWorkspaceVideos
);
router.use(
  '/:workspaceId/projects/:projectId/speech',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  speechRoutes
);
router.use(
  '/:workspaceId/projects/:projectId/comments',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  commentRoutes
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
router.get(
  '/:workspaceId/storage',
  authMiddleware,
  validate(workspaceValidations.workspaceByIdSchema),
  requireWorkspaceRole(anyMember),
  getWorkspaceStorage
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

router.get(
  '/invitations/:token',
  validate(workspaceValidations.getInvitationByTokenSchema),
  getInvitationPreview
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
