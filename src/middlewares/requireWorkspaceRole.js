const asyncHandler = require('../shared/utils/asyncHandler');
const AppError = require('../shared/utils/AppError');
const messages = require('../shared/utils/messages');
const workspaceDao = require('../modules/workspace/workspace.dao');

/**
 * Middleware factory: require current user to be a member of the workspace with one of the allowed roles.
 * Expects workspace id in req.params.id (e.g. /workspaces/:id/...).
 * Sets req.workspaceMembership and req.workspace for use in controllers.
 * @param {string[]} allowedRoles - e.g. ['OWNER'], ['OWNER', 'ADMIN']
 */
function requireWorkspaceRole(allowedRoles) {
  return asyncHandler(async (req, res, next) => {
    const workspaceId = req.params.id;
    if (!workspaceId) {
      throw new AppError(messages.INVALID_REQUEST, 400);
    }

    const userId = req.user?.id;
    if (!userId) {
      throw new AppError(messages.UNAUTHORIZED, 401);
    }

    const membership = await workspaceDao.findWorkspaceMember(workspaceId, userId);
    if (!membership) {
      throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
    }

    if (!allowedRoles.includes(membership.role)) {
      throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
    }

    req.workspaceMembership = membership;
    req.workspace = membership.workspace;
    next();
  });
}

module.exports = { requireWorkspaceRole };
