const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const creditLedger = require('../credit/creditLedger.service');
const creditDao = require('../credit/credit.dao');
const { enrichCreditHistoryResult } = require('../credit/creditHistory.enrich');
const heygenV3Service = require('../heygen/heygenV3.service');
const storageService = require('../storage/storage.service');
const storageDao = require('../storage/storage.dao');
const superadminDao = require('./superadmin.dao');
const { STORAGE_TIERS } = require('../../shared/config/storagePricing');

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
  const members = await creditDao.prisma.workspaceMember.count({ where: { workspaceId } });

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

async function revokeWorkspaceCredits({ workspaceId, amount, reason, revokedByUserId }) {
  return creditLedger.platformRevokeWorkspace({
    workspaceId,
    amountAc: amount,
    revokedByUserId,
    reason,
  });
}

async function listWorkspaces({ page, limit, search }) {
  return superadminDao.listWorkspacesWithCredits({ page, limit, search });
}

async function getWorkspaceCreditHistory(workspaceId, page, limit, type) {
  const result = await creditDao.getWorkspaceCreditHistory(workspaceId, page, limit, {
    types: type ? [type] : undefined,
  });
  return enrichCreditHistoryResult(result);
}

async function getWorkspaceUsageByMember(workspaceId, page, limit) {
  const workspace = await creditLedger.getWorkspaceOrThrow(workspaceId);
  if (workspace.type !== 'TEAM') {
    throw new AppError(messages.CREDITS_USAGE_BY_MEMBER_TEAM_ONLY, 400);
  }
  return creditDao.usageByMemberInWorkspace(workspaceId, page, limit);
}

async function getUsageReport(filters) {
  return creditDao.aggregateUsageReport(filters);
}

async function getPlatformActionsReport(filters) {
  return creditDao.listPlatformCreditActions(filters);
}

async function getHeygenAccountBilling() {
  return heygenV3Service.getAccountBillingInfo();
}

async function getUserStorageSummary(userId) {
  return storageService.getUserStorageSummary(userId);
}

async function getUserStorageHistory(userId, page, limit, type) {
  return storageService.getUserStorageHistory(userId, page, limit, type);
}

async function getStorageTiers() {
  return STORAGE_TIERS.map((tier) => ({
    id: tier.id,
    label: tier.label,
    limitBytes: tier.limitBytes,
  }));
}

async function grantUserStorage({ targetUserId, tierId, additionalBytes, reason, grantedByUserId }) {
  return storageService.grantUserStorage({
    targetUserId,
    tierId,
    additionalBytes,
    reason,
    grantedByUserId,
  });
}

async function revokeUserStorage({ targetUserId, amountBytes, reason, revokedByUserId }) {
  return storageService.revokeUserStorage({
    targetUserId,
    amountBytes,
    reason,
    revokedByUserId,
  });
}

async function listStorageUpgradeRequests(page, limit, status) {
  return storageService.listStorageUpgradeRequestsForAdmin(page, limit, status);
}

async function rejectStorageUpgradeRequest({ requestId, reviewedByUserId, reviewNote }) {
  return storageService.rejectStorageUpgradeRequest({
    requestId,
    reviewedByUserId,
    reviewNote,
  });
}

async function updateUserPlatformAccess({
  targetUserId,
  isPlatformSuperadmin,
  actorUserId,
}) {
  if (targetUserId === actorUserId && isPlatformSuperadmin === false) {
    throw new AppError(messages.CANNOT_DEMOTE_SELF_SUPERADMIN, 400);
  }

  await creditLedger.getUserOrThrow(targetUserId);

  const remainingCount = await superadminDao.countAccessibleSuperadminsAfterChange(
    targetUserId,
    isPlatformSuperadmin
  );
  if (remainingCount === 0) {
    throw new AppError(messages.CANNOT_REMOVE_LAST_SUPERADMIN, 400);
  }

  const user = await superadminDao.updateUserPlatformAccess(targetUserId, isPlatformSuperadmin);
  return {
    userId: user.id,
    email: user.email,
    name: user.name,
    isPlatformSuperadmin: user.isPlatformSuperadmin,
  };
}

module.exports = {
  grantUserCredits,
  revokeUserCredits,
  getUserCreditsSummary,
  getUserCreditHistory,
  listUsers,
  getWorkspaceCreditsSummary,
  grantWorkspaceCredits,
  revokeWorkspaceCredits,
  listWorkspaces,
  getWorkspaceCreditHistory,
  getWorkspaceUsageByMember,
  getUsageReport,
  getPlatformActionsReport,
  getHeygenAccountBilling,
  getUserStorageSummary,
  getUserStorageHistory,
  getStorageTiers,
  grantUserStorage,
  revokeUserStorage,
  listStorageUpgradeRequests,
  rejectStorageUpgradeRequest,
  updateUserPlatformAccess,
};
