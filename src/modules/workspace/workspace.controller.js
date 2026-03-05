const asyncHandler = require('../../shared/utils/asyncHandler');
const AppError = require('../../shared/utils/AppError');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const workspaceService = require('./workspace.service');

const createTeamWorkspace = asyncHandler(async (req, res) => {
  const { name } = req.body;
  const userId = req.user.id;
  const workspace = await workspaceService.createTeamWorkspace(userId, name);
  return successResponse(
    req,
    res,
    { workspace },
    201,
    messages.WORKSPACE_CREATED
  );
});

const getUserWorkspaces = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaces = await workspaceService.getUserWorkspaces(userId);
  return successResponse(
    req,
    res,
    { workspaces, count: workspaces.length },
    200,
    null
  );
});

const getWorkspaceById = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const workspace = await workspaceService.getWorkspaceById(userId, workspaceId);
  return successResponse(req, res, { workspace }, 200, null);
});

const deleteWorkspace = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  await workspaceService.deleteWorkspace(userId, workspaceId);
  return successResponse(
    req,
    res,
    null,
    200,
    messages.WORKSPACE_DELETED
  );
});

const getWorkspaceMembers = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspaceId = req.params.id;
  const members = await workspaceService.getWorkspaceMembers(workspaceId, userId);
  return successResponse(req, res, { members }, 200, null);
});

const inviteMember = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const inviterId = req.user.id;
  const { email, role } = req.body;
  if (!email || !role) {
    throw new AppError(messages.ALL_FIELDS_REQUIRED, 400);
  }
  const result = await workspaceService.inviteMember(
    workspaceId,
    inviterId,
    email,
    role
  );
  return successResponse(
    req,
    res,
    { token: result.token, expiresAt: result.expiresAt },
    201,
    messages.WORKSPACE_INVITE_SENT
  );
});

const acceptInvitation = asyncHandler(async (req, res) => {
  const { token } = req.body;
  const userId = req.user.id;
  if (!token) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }
  const workspace = await workspaceService.acceptInvitation(token, userId);
  return successResponse(
    req,
    res,
    { workspace },
    200,
    messages.WORKSPACE_INVITATION_ACCEPTED
  );
});

const removeMember = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const memberId = req.params.memberId;
  const requesterId = req.user.id;
  await workspaceService.removeMember(workspaceId, requesterId, memberId);
  return successResponse(
    req,
    res,
    null,
    200,
    messages.WORKSPACE_MEMBER_REMOVED
  );
});

const changeMemberRole = asyncHandler(async (req, res) => {
  const workspaceId = req.params.id;
  const memberId = req.params.memberId;
  const requesterId = req.user.id;
  const { role: newRole } = req.body;
  if (!newRole) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }
  const member = await workspaceService.changeMemberRole(
    workspaceId,
    requesterId,
    memberId,
    newRole
  );
  return successResponse(
    req,
    res,
    { member },
    200,
    messages.WORKSPACE_ROLE_UPDATED
  );
});

module.exports = {
  createTeamWorkspace,
  getUserWorkspaces,
  getWorkspaceById,
  deleteWorkspace,
  getWorkspaceMembers,
  inviteMember,
  acceptInvitation,
  removeMember,
  changeMemberRole,
};
