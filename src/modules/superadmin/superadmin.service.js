const prisma = require('../../shared/config/prismaClient');
const creditLedger = require('../credit/creditLedger.service');
const creditDao = require('../credit/credit.dao');
const { enrichCreditHistoryResult } = require('../credit/creditHistory.enrich');
const heygenV3Service = require('../heygen/heygenV3.service');

async function grantUserCredits({ targetUserId, amount, reason, grantedByUserId }) {
  return creditLedger.platformGrant({
    targetUserId,
    amountAc: amount,
    grantedByUserId,
    reason,
  });
}

async function revokeUserCredits({ targetUserId, amount, reason, revokedByUserId }) {
  return creditLedger.platformRevoke({
    targetUserId,
    amountAc: amount,
    revokedByUserId,
    reason,
  });
}

async function getUserCreditsSummary(userId) {
  const user = await creditLedger.getUserOrThrow(userId);
  return {
    userId: user.id,
    email: user.email,
    name: user.name,
    personalCredits: user.credits,
  };
}

async function getUserCreditHistory(userId, page, limit, type) {
  const result = await creditDao.getAllUserCreditHistory(userId, page, limit, type || undefined);
  return enrichCreditHistoryResult(result);
}

async function listUsers({ page, limit, search }) {
  return creditDao.listUsersWithCredits({ page, limit, search });
}

async function getWorkspaceCreditsSummary(workspaceId) {
  const workspace = await creditLedger.getWorkspaceOrThrow(workspaceId);
  const owner = await creditDao.getUserCredits(workspace.ownerId);
  const members = await prisma.workspaceMember.count({ where: { workspaceId } });

  return {
    workspaceId: workspace.id,
    name: workspace.name,
    type: workspace.type,
    workspaceCredits: workspace.credits,
    owner: owner
      ? { id: owner.id, email: owner.email, name: owner.name, personalCredits: owner.credits }
      : null,
    memberCount: members,
  };
}

async function grantWorkspaceCredits({ workspaceId, amount, reason, grantedByUserId }) {
  return creditLedger.platformGrantWorkspace({
    workspaceId,
    amountAc: amount,
    grantedByUserId,
    reason,
  });
}

async function getUsageReport(filters) {
  return creditDao.aggregateUsageReport(filters);
}

async function getHeygenAccountBilling() {
  return heygenV3Service.getAccountBillingInfo();
}

module.exports = {
  grantUserCredits,
  revokeUserCredits,
  getUserCreditsSummary,
  getUserCreditHistory,
  listUsers,
  getWorkspaceCreditsSummary,
  grantWorkspaceCredits,
  getUsageReport,
  getHeygenAccountBilling,
};
