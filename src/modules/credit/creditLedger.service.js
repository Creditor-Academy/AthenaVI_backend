const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const creditDao = require('./credit.dao');
const { SCOPE } = require('../../shared/config/creditPricing');
const inboxService = require('../inbox/inbox.service');

async function notifyCreditsLowAfterCharge({ scope, workspaceId, userId }) {
  try {
    if (scope === SCOPE.USER) {
      const user = await getUserOrThrow(userId);
      await inboxService.maybeNotifyCreditsLow({
        userId,
        pool: 'user',
        balance: user.credits,
      });
      return;
    }

    const target = await resolveBillingTarget(workspaceId);
    if (target.pool === 'user') {
      const user = await getUserOrThrow(target.ownerId);
      await inboxService.maybeNotifyCreditsLow({
        userId: target.ownerId,
        pool: 'user',
        balance: user.credits,
      });
      return;
    }

    const workspace = await getWorkspaceOrThrow(workspaceId);
    await inboxService.maybeNotifyCreditsLow({
      workspaceId,
      pool: 'workspace',
      balance: workspace.credits,
    });
  } catch (error) {
    console.error('Failed to evaluate low-credit notification:', error);
  }
}

async function getWorkspaceOrThrow(workspaceId) {
  const workspace = await creditDao.getWorkspaceCredits(workspaceId);
  if (!workspace) {
    throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  }
  return workspace;
}

async function getUserOrThrow(userId) {
  const user = await creditDao.getUserCredits(userId);
  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }
  return user;
}

/**
 * @returns {{ pool: 'user'|'workspace', workspaceId: string|null, workspaceType?: string }}
 */
async function resolveBillingTarget(workspaceId) {
  const workspace = await getWorkspaceOrThrow(workspaceId);
  if (workspace.type === 'PRIVATE') {
    return { pool: 'user', workspaceId, workspaceType: 'PRIVATE', ownerId: workspace.ownerId };
  }
  return { pool: 'workspace', workspaceId, workspaceType: 'TEAM', ownerId: workspace.ownerId };
}

async function getBalanceForPool(pool, { userId, workspaceId }) {
  if (pool === 'user') {
    const user = await getUserOrThrow(userId);
    return user.credits;
  }
  const workspace = await getWorkspaceOrThrow(workspaceId);
  return workspace.credits;
}

async function getBalances({ userId, workspaceId }) {
  const user = await getUserOrThrow(userId);
  const result = {
    personalCredits: user.credits,
    workspaceCredits: null,
    workspaceType: null,
    workspaceId: workspaceId || null,
  };
  if (workspaceId) {
    const workspace = await getWorkspaceOrThrow(workspaceId);
    result.workspaceCredits = workspace.credits;
    result.workspaceType = workspace.type;
  }
  return result;
}

async function assertCanAfford({ scope, workspaceId, userId, estimatedAc }) {
  const need = Math.max(0, Math.floor(Number(estimatedAc) || 0));
  if (need === 0) return;

  let balance;
  if (scope === SCOPE.USER) {
    balance = await getBalanceForPool('user', { userId });
  } else {
    const target = await resolveBillingTarget(workspaceId);
    if (target.pool === 'user') {
      balance = await getBalanceForPool('user', { userId: target.ownerId });
    } else {
      balance = await getBalanceForPool('workspace', { workspaceId });
    }
  }

  if (balance < need) {
    throw new AppError(messages.INSUFFICIENT_CREDITS, 402);
  }
}

async function applyDeltaInTx(tx, { pool, userId, workspaceId, delta }) {
  if (pool === 'user') {
    const updated = await creditDao.incrementUserCredits(tx, userId, delta);
    if (updated.credits < 0) {
      throw new AppError(messages.INSUFFICIENT_CREDITS, 402);
    }
    return updated;
  }
  const updated = await creditDao.incrementWorkspaceCredits(tx, workspaceId, delta);
  if (updated.credits < 0) {
    throw new AppError(messages.INSUFFICIENT_CREDITS, 402);
  }
  return updated;
}

async function recordLedgerEntry(tx, entry) {
  return creditDao.createCreditTransaction(tx, entry);
}

async function chargeUsage({
  scope,
  workspaceId,
  userId,
  amountAc,
  idempotencyKey,
  metadata,
  reference,
}) {
  const charge = Math.max(0, Math.floor(Number(amountAc) || 0));
  if (charge === 0) return { skipped: true, reason: 'zero_amount' };

  const existing = await creditDao.findTransactionByIdempotencyKey(idempotencyKey);
  if (existing) {
    return { skipped: true, reason: 'idempotent', transaction: existing };
  }

  let pool = 'user';
  let billUserId = userId;
  let billWorkspaceId = scope === SCOPE.WORKSPACE ? workspaceId : null;

  if (scope === SCOPE.WORKSPACE) {
    const target = await resolveBillingTarget(workspaceId);
    pool = target.pool;
    if (pool === 'user') {
      billUserId = target.ownerId;
    }
  }

  const result = await prisma.$transaction(async (tx) => {
    await applyDeltaInTx(tx, {
      pool,
      userId: billUserId,
      workspaceId: pool === 'workspace' ? workspaceId : undefined,
      delta: -charge,
    });

    const transaction = await recordLedgerEntry(tx, {
      userId,
      workspaceId: billWorkspaceId,
      amount: -charge,
      type: 'usage',
      scope,
      reference: reference || null,
      idempotencyKey,
      metadata: metadata || undefined,
    });

    return { skipped: false, transaction, charged: charge };
  });

  await notifyCreditsLowAfterCharge({ scope, workspaceId, userId });
  return result;
}

async function platformGrant({ targetUserId, amountAc, grantedByUserId, reason }) {
  const amount = Math.floor(Number(amountAc) || 0);
  if (amount <= 0) {
    throw new AppError(messages.INVALID_CREDIT_AMOUNT, 400);
  }
  await getUserOrThrow(targetUserId);

  const result = await prisma.$transaction(async (tx) => {
    const user = await applyDeltaInTx(tx, {
      pool: 'user',
      userId: targetUserId,
      delta: amount,
    });
    const transaction = await recordLedgerEntry(tx, {
      userId: targetUserId,
      workspaceId: null,
      amount,
      type: 'platform_grant',
      scope: SCOPE.USER,
      reference: reason || null,
      metadata: { grantedByUserId, reason: reason || null },
    });
    return { user, transaction };
  });

  inboxService
    .notifyCreditsPlatformGrant({ userId: targetUserId, amount, reason })
    .catch((error) => console.error('Credits grant notification failed:', error));
  inboxService
    .maybeNotifyCreditsLow({
      userId: targetUserId,
      pool: 'user',
      balance: result.user.credits,
    })
    .catch((error) => console.error('Credits low notification failed:', error));

  return result;
}

async function platformRevoke({ targetUserId, amountAc, revokedByUserId, reason }) {
  const amount = Math.floor(Number(amountAc) || 0);
  if (amount <= 0) {
    throw new AppError(messages.INVALID_CREDIT_AMOUNT, 400);
  }
  const user = await getUserOrThrow(targetUserId);
  if (user.credits < amount) {
    throw new AppError(messages.INSUFFICIENT_CREDITS, 402);
  }

  const result = await prisma.$transaction(async (tx) => {
    const updated = await applyDeltaInTx(tx, {
      pool: 'user',
      userId: targetUserId,
      delta: -amount,
    });
    const transaction = await recordLedgerEntry(tx, {
      userId: targetUserId,
      workspaceId: null,
      amount: -amount,
      type: 'platform_revoke',
      scope: SCOPE.USER,
      reference: reason || null,
      metadata: { revokedByUserId, reason: reason || null },
    });
    return { user: updated, transaction };
  });

  inboxService
    .notifyCreditsPlatformRevoke({ userId: targetUserId, amount, reason })
    .catch((error) => console.error('Credits revoke notification failed:', error));
  inboxService
    .maybeNotifyCreditsLow({
      userId: targetUserId,
      pool: 'user',
      balance: result.user.credits,
    })
    .catch((error) => console.error('Credits low notification failed:', error));

  return result;
}

async function platformGrantWorkspace({ workspaceId, amountAc, grantedByUserId, reason }) {
  const amount = Math.floor(Number(amountAc) || 0);
  if (amount <= 0) {
    throw new AppError(messages.INVALID_CREDIT_AMOUNT, 400);
  }
  const workspaceMeta = await getWorkspaceOrThrow(workspaceId);

  const result = await prisma.$transaction(async (tx) => {
    const workspace = await applyDeltaInTx(tx, {
      pool: 'workspace',
      workspaceId,
      userId: null,
      delta: amount,
    });
    const transaction = await recordLedgerEntry(tx, {
      userId: grantedByUserId,
      workspaceId,
      amount,
      type: 'platform_grant',
      scope: SCOPE.WORKSPACE,
      reference: reason || null,
      metadata: { grantedByUserId, reason: reason || null, target: 'workspace' },
    });
    return { workspace, transaction };
  });

  inboxService
    .notifyCreditsWorkspaceGrant({
      workspaceId,
      workspaceName: workspaceMeta.name,
      ownerId: workspaceMeta.ownerId,
      amount,
      reason,
    })
    .catch((error) => console.error('Workspace credits grant notification failed:', error));
  inboxService
    .maybeNotifyCreditsLow({
      workspaceId,
      pool: 'workspace',
      balance: result.workspace.credits,
    })
    .catch((error) => console.error('Credits low notification failed:', error));

  return result;
}

async function allocateToWorkspace({ ownerUserId, workspaceId, amountAc }) {
  const amount = Math.floor(Number(amountAc) || 0);
  if (amount <= 0) {
    throw new AppError(messages.INVALID_CREDIT_AMOUNT, 400);
  }

  const workspace = await getWorkspaceOrThrow(workspaceId);
  if (workspace.type !== 'TEAM') {
    throw new AppError(messages.CREDITS_ALLOCATE_TEAM_ONLY, 400);
  }
  if (workspace.ownerId !== ownerUserId) {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }

  const owner = await getUserOrThrow(ownerUserId);
  if (owner.credits < amount) {
    throw new AppError(messages.INSUFFICIENT_CREDITS, 402);
  }

  const result = await prisma.$transaction(async (tx) => {
    await applyDeltaInTx(tx, { pool: 'user', userId: ownerUserId, delta: -amount });
    await applyDeltaInTx(tx, { pool: 'workspace', workspaceId, userId: ownerUserId, delta: amount });

    const outTx = await recordLedgerEntry(tx, {
      userId: ownerUserId,
      workspaceId: null,
      amount: -amount,
      type: 'allocation',
      scope: SCOPE.USER,
      reference: workspaceId,
      metadata: { direction: 'out', workspaceId },
    });
    const inTx = await recordLedgerEntry(tx, {
      userId: ownerUserId,
      workspaceId,
      amount,
      type: 'allocation',
      scope: SCOPE.WORKSPACE,
      reference: workspaceId,
      metadata: { direction: 'in', workspaceId },
    });

    return { outTx, inTx };
  });

  const updatedWorkspace = await getWorkspaceOrThrow(workspaceId);
  inboxService
    .notifyCreditsAllocated({
      ownerId: ownerUserId,
      workspaceId,
      workspaceName: workspace.name,
      amount,
      direction: 'in',
    })
    .catch((error) => console.error('Credits allocation notification failed:', error));
  inboxService
    .maybeNotifyCreditsLow({
      userId: ownerUserId,
      pool: 'user',
      balance: (await getUserOrThrow(ownerUserId)).credits,
    })
    .catch((error) => console.error('Credits low notification failed:', error));
  inboxService
    .maybeNotifyCreditsLow({
      workspaceId,
      pool: 'workspace',
      balance: updatedWorkspace.credits,
    })
    .catch((error) => console.error('Credits low notification failed:', error));

  return result;
}

async function deallocateFromWorkspace({ ownerUserId, workspaceId, amountAc }) {
  const amount = Math.floor(Number(amountAc) || 0);
  if (amount <= 0) {
    throw new AppError(messages.INVALID_CREDIT_AMOUNT, 400);
  }

  const workspace = await getWorkspaceOrThrow(workspaceId);
  if (workspace.type !== 'TEAM') {
    throw new AppError(messages.CREDITS_ALLOCATE_TEAM_ONLY, 400);
  }
  if (workspace.ownerId !== ownerUserId) {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }
  if (workspace.credits < amount) {
    throw new AppError(messages.INSUFFICIENT_CREDITS, 402);
  }

  const result = await prisma.$transaction(async (tx) => {
    await applyDeltaInTx(tx, { pool: 'workspace', workspaceId, userId: ownerUserId, delta: -amount });
    await applyDeltaInTx(tx, { pool: 'user', userId: ownerUserId, delta: amount });

    const outTx = await recordLedgerEntry(tx, {
      userId: ownerUserId,
      workspaceId,
      amount: -amount,
      type: 'deallocation',
      scope: SCOPE.WORKSPACE,
      reference: workspaceId,
      metadata: { direction: 'out', workspaceId },
    });
    const inTx = await recordLedgerEntry(tx, {
      userId: ownerUserId,
      workspaceId: null,
      amount,
      type: 'deallocation',
      scope: SCOPE.USER,
      reference: workspaceId,
      metadata: { direction: 'in', workspaceId },
    });

    return { outTx, inTx };
  });

  const updatedWorkspace = await getWorkspaceOrThrow(workspaceId);
  inboxService
    .notifyCreditsAllocated({
      ownerId: ownerUserId,
      workspaceId,
      workspaceName: workspace.name,
      amount,
      direction: 'out',
    })
    .catch((error) => console.error('Credits deallocation notification failed:', error));
  inboxService
    .maybeNotifyCreditsLow({
      workspaceId,
      pool: 'workspace',
      balance: updatedWorkspace.credits,
    })
    .catch((error) => console.error('Credits low notification failed:', error));

  return result;
}

async function platformRevokeWorkspace({ workspaceId, amountAc, revokedByUserId, reason }) {
  const amount = Math.floor(Number(amountAc) || 0);
  if (amount <= 0) {
    throw new AppError(messages.INVALID_CREDIT_AMOUNT, 400);
  }
  const workspaceMeta = await getWorkspaceOrThrow(workspaceId);
  if (workspaceMeta.credits < amount) {
    throw new AppError(messages.INSUFFICIENT_CREDITS, 402);
  }

  const result = await prisma.$transaction(async (tx) => {
    const workspace = await applyDeltaInTx(tx, {
      pool: 'workspace',
      workspaceId,
      userId: null,
      delta: -amount,
    });
    const transaction = await recordLedgerEntry(tx, {
      userId: revokedByUserId,
      workspaceId,
      amount: -amount,
      type: 'platform_revoke',
      scope: SCOPE.WORKSPACE,
      reference: reason || null,
      metadata: { revokedByUserId, reason: reason || null, target: 'workspace' },
    });
    return { workspace, transaction };
  });

  inboxService
    .notifyCreditsWorkspaceRevoke({
      workspaceId,
      workspaceName: workspaceMeta.name,
      ownerId: workspaceMeta.ownerId,
      amount,
      reason,
    })
    .catch((error) => console.error('Workspace credits revoke notification failed:', error));
  inboxService
    .maybeNotifyCreditsLow({
      workspaceId,
      pool: 'workspace',
      balance: result.workspace.credits,
    })
    .catch((error) => console.error('Credits low notification failed:', error));

  return result;
}

module.exports = {
  resolveBillingTarget,
  getBalances,
  assertCanAfford,
  chargeUsage,
  platformGrant,
  platformRevoke,
  platformGrantWorkspace,
  platformRevokeWorkspace,
  allocateToWorkspace,
  deallocateFromWorkspace,
  getUserOrThrow,
  getWorkspaceOrThrow,
};
