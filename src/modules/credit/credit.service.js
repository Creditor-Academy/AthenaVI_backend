const messages = require('../../shared/utils/messages');
const creditDao = require('./credit.dao');

// Business meaning of "available credits"
const getAvailableCredits = async (workspaceId) => {
  const workspace = await creditDao.getWorkspaceCredits(workspaceId);

  if (!workspace) {
    throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  }
  return workspace.credits;
};

const getWorkspaceCreditHistory = async ({ workspaceId, page, limit }) => {
  return creditDao.getWorkspaceCreditHistory(workspaceId, page, limit);
};

const getUserCreditHistory = async ({ workspaceId, userId, page, limit }) => {
  return creditDao.getUserCreditHistory(workspaceId, userId, page, limit);
};

module.exports = {
  getAvailableCredits,
  getUserCreditHistory,
  getWorkspaceCreditHistory,
};
