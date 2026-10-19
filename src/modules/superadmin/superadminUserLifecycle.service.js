const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const { normalizeEmail } = require('../../shared/utils/normalizeEmail');
const { toJsonNumber } = require('../../shared/utils/byteSize');
const { hasPlatformSuperadminAccess } = require('../../shared/services/platformSuperadmin.service');
const superadminDao = require('./superadmin.dao');

const MAX_PAUSE_REASON_LENGTH = 500;

const FOREIGN_KEY_VIOLATION = 'P2003';

function serializeUser(user) {
  return {
    ...user,
    storageLimit: toJsonNumber(user.storageLimit),
    storageUsed: toJsonNumber(user.storageUsed),
  };
}

function normalizeReason(reason) {
  const trimmed = String(reason ?? '').trim();
  return trimmed ? trimmed.slice(0, MAX_PAUSE_REASON_LENGTH) : null;
}

const defaultDeps = {
  superadminDao,
  // Lazy so this module does not pull the auth/S3 stacks in at import time (keeps tests light).
  revokeAllSessions: (userId) => require('../auth/services/auth.service').logoutAllDevices(userId),
  permanentlyDeleteUser: (userId) =>
    require('../settings/accountDeletion.service').permanentlyDeleteUser(userId),
  logger,
};

/**
 * Admin lifecycle actions on a user: pause / resume service and permanent delete.
 *
 * Guardrails shared by pause and delete: no acting on yourself and no acting on a platform
 * superadmin (demote first) so an admin can never lock the platform out of its own console.
 */
function createUserLifecycleService(overrides = {}) {
  const deps = { ...defaultDeps, ...overrides };

  async function loadTarget({ targetUserId, actorId }) {
    if (targetUserId === actorId) {
      throw new AppError(messages.USER_ADMIN_ACTION_SELF, 400);
    }
    const target = await deps.superadminDao.findUserLifecycleState(targetUserId);
    if (!target) {
      throw new AppError(messages.USER_NOT_FOUND, 404);
    }
    if (hasPlatformSuperadminAccess(target)) {
      throw new AppError(messages.USER_ADMIN_ACTION_SUPERADMIN, 400);
    }
    return target;
  }

  async function summaryOf(userId, fallback) {
    const summary = await deps.superadminDao.findUserSummaryById(userId);
    return summary ? serializeUser(summary) : fallback;
  }

  /**
   * Idempotent. Always revokes sessions (even when already paused) so a retry after a partial
   * failure still ends every live session.
   */
  async function pauseUser({ targetUserId, actorId, reason }) {
    const target = await loadTarget({ targetUserId, actorId });
    const alreadyPaused = Boolean(target.pausedAt);

    let user;
    if (!alreadyPaused) {
      const updated = await deps.superadminDao.setUserPaused(targetUserId, {
        pausedAt: new Date(),
        pauseReason: normalizeReason(reason),
      });
      user = serializeUser(updated);
    }

    await deps.revokeAllSessions(targetUserId);

    deps.logger.info('Admin paused user service', {
      targetUserId,
      actorId,
      alreadyPaused,
    });

    return {
      user: user || (await summaryOf(targetUserId, { id: targetUserId })),
      changed: !alreadyPaused,
    };
  }

  async function resumeUser({ targetUserId, actorId }) {
    const target = await loadTarget({ targetUserId, actorId });
    if (!target.pausedAt) {
      return { user: await summaryOf(targetUserId, { id: targetUserId }), changed: false };
    }

    const updated = await deps.superadminDao.setUserPaused(targetUserId, {
      pausedAt: null,
      pauseReason: null,
    });

    deps.logger.info('Admin resumed user service', { targetUserId, actorId });
    return { user: serializeUser(updated), changed: true };
  }

  /**
   * Permanent and irreversible. Requires the target's email as a typed confirmation and refuses
   * when the user owns team workspaces other people still use (the owner FK cascades).
   */
  async function deleteUser({ targetUserId, actorId, confirmEmail }) {
    const target = await loadTarget({ targetUserId, actorId });

    if (normalizeEmail(confirmEmail) !== normalizeEmail(target.email)) {
      throw new AppError(messages.USER_DELETE_CONFIRMATION_MISMATCH, 400);
    }

    const shared = await deps.superadminDao.findOwnedSharedTeamWorkspaces(targetUserId);
    if (shared.length > 0) {
      const names = shared.map((w) => w.name).join(', ');
      throw new AppError(`${messages.USER_DELETE_OWNS_TEAM_WORKSPACES}: ${names}`, 409);
    }

    // Kill sessions first so the user cannot keep working while data is being removed.
    await deps.revokeAllSessions(targetUserId);

    let deleted;
    try {
      deleted = await deps.permanentlyDeleteUser(targetUserId);
    } catch (err) {
      if (err?.code === FOREIGN_KEY_VIOLATION) {
        deps.logger.error('Admin user delete blocked by a foreign key', {
          targetUserId,
          actorId,
          error: err.message,
        });
        throw new AppError(
          'This user is still referenced by other records and cannot be deleted',
          409
        );
      }
      throw err;
    }
    if (!deleted) {
      throw new AppError(messages.USER_NOT_FOUND, 404);
    }

    deps.logger.info('Admin deleted user', { targetUserId, actorId });
    return { deletedUserId: targetUserId };
  }

  return { pauseUser, resumeUser, deleteUser };
}

const defaultService = () => createUserLifecycleService();

module.exports = {
  createUserLifecycleService,
  pauseUser: (input) => defaultService().pauseUser(input),
  resumeUser: (input) => defaultService().resumeUser(input),
  deleteUser: (input) => defaultService().deleteUser(input),
  MAX_PAUSE_REASON_LENGTH,
};
