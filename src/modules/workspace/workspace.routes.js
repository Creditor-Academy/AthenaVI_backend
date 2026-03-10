const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { requireWorkspaceRole } = require('../../middlewares/requireWorkspaceRole');
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
} = require('./workspace.controller');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];
const ownerOrAdmin = ['OWNER', 'ADMIN'];
const ownerOnly = ['OWNER'];


// workspace routes
router.post('/', authMiddleware, createTeamWorkspace);
router.get('/', authMiddleware, getUserWorkspaces);
router.get('/:id', authMiddleware, requireWorkspaceRole(anyMember), getWorkspaceById);
router.delete('/:id', authMiddleware, requireWorkspaceRole(ownerOnly), deleteWorkspace);


//invitation routes
router.post('/:id/invite', authMiddleware, requireWorkspaceRole(ownerOrAdmin), inviteMember);
router.post('/invitations/accept', authMiddleware, acceptInvitation);


//member management routes
router.get('/:id/members', authMiddleware, requireWorkspaceRole(ownerOrAdmin), getWorkspaceMembers);
router.patch('/:id/members/:memberId/role', authMiddleware, requireWorkspaceRole(ownerOnly), changeMemberRole);
router.delete('/:id/members/:memberId', authMiddleware, requireWorkspaceRole(ownerOrAdmin), removeMember);



module.exports = router;
