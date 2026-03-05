const messages = require('../../shared/utils/messages');
const creditDao = require('./credit.dao');

// Business meaning of "available credits"
const getAvailableCredits = async (userId) => {
  const member = await creditDao.findWorkspaceMember(userId);

  if (!member) {
    throw new Error(messages.WORKSPACE_NOT_FOUND);
  }

  return {
    workspaceId: member.workspaceId,
    credits: member.workspace.credits,
  };
};

const getCreditHistory = async (userId) => {
  const member = await creditDao.findWorkspaceMember(userId);

  if (!member) {
    throw new Error(messages.WORKSPACE_NOT_FOUND);
  }

  const history = await creditDao.getCreditTransactions(member.workspaceId);

  return {
    workspaceId: member.workspaceId,
    history,
  };
};

module.exports = {
  getAvailableCredits,
  getCreditHistory,
};
