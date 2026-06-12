const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const creditDao = require('./credit.dao');
const creditLedger = require('./creditLedger.service');
const { enrichCreditHistoryResult } = require('./creditHistory.enrich');
const {
  FEATURE,
  SCOPE,
  calculateUsageCredits,
  estimateDurationFromScript,
  estimateDurationFromText,
  estimateDurationFromFrames,
} = require('../../shared/config/creditPricing');

const getWorkspaceCreditsView = async (workspaceId, userId) => {
  const balances = await creditLedger.getBalances({ userId, workspaceId });
  return balances;
};

const getPersonalCreditsView = async (userId) => {
  const user = await creditLedger.getUserOrThrow(userId);
  return { personalCredits: user.credits };
};

const getWorkspaceCreditHistory = async ({ workspaceId, page, limit }) => {
  const result = await creditDao.getWorkspaceCreditHistory(workspaceId, page, limit, {
    scope: SCOPE.WORKSPACE,
  });
  return enrichCreditHistoryResult(result);
};

const getUserCreditHistory = async ({ workspaceId, userId, page, limit }) => {
  const result = await creditDao.getUserCreditHistory(workspaceId, userId, page, limit);
  return enrichCreditHistoryResult(result);
};

const getPersonalCreditHistory = async ({ userId, page, limit }) => {
  const result = await creditDao.getUserScopedCreditHistory(userId, page, limit);
  return enrichCreditHistoryResult(result);
};

const allocateToWorkspace = async ({ ownerUserId, workspaceId, amount }) => {
  return creditLedger.allocateToWorkspace({ ownerUserId, workspaceId, amountAc: amount });
};

const deallocateFromWorkspace = async ({ ownerUserId, workspaceId, amount }) => {
  return creditLedger.deallocateFromWorkspace({ ownerUserId, workspaceId, amountAc: amount });
};

const getUsageByMember = async (workspaceId, page, limit) => {
  const workspace = await creditLedger.getWorkspaceOrThrow(workspaceId);
  if (workspace.type !== 'TEAM') {
    throw new AppError(messages.CREDITS_USAGE_BY_MEMBER_TEAM_ONLY, 400);
  }
  return creditDao.usageByMemberInWorkspace(workspaceId, page, limit);
};

function buildWorkspaceEstimate(query) {
  const feature = query.feature;
  if (feature === FEATURE.HEYGEN_VIDEO) {
    const durationSeconds = estimateDurationFromScript(query.script);
    return calculateUsageCredits({
      feature,
      durationSeconds,
      avatarEngine: query.avatarEngine,
    });
  }
  if (feature === FEATURE.REMOTION_EXPORT) {
    const durationSeconds = query.durationInFrames
      ? estimateDurationFromFrames(query.durationInFrames, query.fps)
      : 60;
    return calculateUsageCredits({ feature, durationSeconds });
  }
  throw new AppError(messages.INVALID_CREDIT_AMOUNT, 400);
}

function buildPersonalEstimate(query) {
  const feature = query.feature;
  if (feature === FEATURE.VOICE_PREVIEW) {
    const durationSeconds = estimateDurationFromText(query.text);
    return calculateUsageCredits({ feature, durationSeconds });
  }
  return calculateUsageCredits({ feature, durationSeconds: 0 });
}

module.exports = {
  getWorkspaceCreditsView,
  getPersonalCreditsView,
  getWorkspaceCreditHistory,
  getUserCreditHistory,
  getPersonalCreditHistory,
  allocateToWorkspace,
  deallocateFromWorkspace,
  getUsageByMember,
  buildWorkspaceEstimate,
  buildPersonalEstimate,
};
