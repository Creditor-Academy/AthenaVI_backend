const bcrypt = require('bcrypt');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const authDao = require('../auth/auth.dao');
const authService = require('../auth/services/auth.service');
const securityDao = require('./security.dao');
const settingsDao = require('./settings.dao');
const {
  ACCOUNT_DELETION_CONFIRMATION,
  ACCOUNT_DELETION_GRACE_DAYS,
  DEFAULT_LOGIN_ALERTS,
  getDeletionGraceMs,
} = require('./security.constants');

const buildAccountDeletionStatus = (user) => {
  if (!user?.deletionScheduledAt) {
    return { pending: false };
  }

  const now = Date.now();
  const scheduledAt = user.deletionScheduledAt.getTime();
  const msRemaining = Math.max(scheduledAt - now, 0);

  return {
    pending: true,
    requestedAt: user.deletionRequestedAt,
    permanentDeletionAt: user.deletionScheduledAt,
    recoverableUntil: user.deletionScheduledAt,
    daysRemaining: Math.ceil(msRemaining / (24 * 60 * 60 * 1000)),
    gracePeriodDays: ACCOUNT_DELETION_GRACE_DAYS,
  };
};

const getSecuritySettings = async (userId) => {
  const user = await securityDao.findSecurityByUserId(userId);

  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }

  const settings = await settingsDao.findByUserId(userId);

  return {
    hasPassword: Boolean(user.password),
    canChangePassword: Boolean(user.password),
    loginAlerts: settings?.loginAlerts ?? DEFAULT_LOGIN_ALERTS,
    accountDeletion: buildAccountDeletionStatus(user),
  };
};

const updateSecuritySettings = async (userId, payload) => {
  const user = await securityDao.findSecurityByUserId(userId);

  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }

  const updateData = {};

  if (payload.loginAlerts !== undefined) {
    updateData.loginAlerts = payload.loginAlerts;
  }

  if (Object.keys(updateData).length === 0) {
    throw new AppError(messages.NO_VALID_FIELDS_PROVIDED, 400);
  }

  const settings = await settingsDao.upsertSettings(userId, updateData);

  return {
    hasPassword: Boolean(user.password),
    canChangePassword: Boolean(user.password),
    loginAlerts: settings.loginAlerts,
    accountDeletion: buildAccountDeletionStatus(user),
  };
};

const changePassword = async (userId, { currentPassword, newPassword }) => {
  const user = await securityDao.findSecurityByUserId(userId);

  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }

  if (!user.password) {
    throw new AppError(messages.PASSWORD_CHANGE_NOT_AVAILABLE, 400);
  }

  const isMatch = await bcrypt.compare(currentPassword, user.password);
  if (!isMatch) {
    throw new AppError(messages.CURRENT_PASSWORD_INCORRECT, 400);
  }

  const hashedPassword = await bcrypt.hash(
    newPassword,
    Number(process.env.SALT_ROUNDS)
  );

  await authDao.updatePasswordAndInvalidateResetTokens({
    userId,
    hashedPassword,
  });

  return { passwordChanged: true };
};

const requestAccountDeletion = async (userId, { confirmation }) => {
  if (confirmation !== ACCOUNT_DELETION_CONFIRMATION) {
    throw new AppError(messages.ACCOUNT_DELETION_CONFIRMATION_INVALID, 400);
  }

  const user = await securityDao.findSecurityByUserId(userId);

  if (!user) {
    throw new AppError(messages.USER_NOT_FOUND, 404);
  }

  if (user.deletionScheduledAt && user.deletionScheduledAt > new Date()) {
    throw new AppError(messages.ACCOUNT_DELETION_ALREADY_PENDING, 409);
  }

  const requestedAt = new Date();
  const scheduledAt = new Date(requestedAt.getTime() + getDeletionGraceMs());

  const updated = await securityDao.scheduleAccountDeletion(userId, {
    requestedAt,
    scheduledAt,
  });

  await authService.logoutAllDevices(userId);

  return {
    accountDeletion: buildAccountDeletionStatus(updated),
  };
};

const recoverAccountIfPending = async (user) => {
  if (!user?.deletionScheduledAt) {
    return user;
  }

  if (user.deletionScheduledAt <= new Date()) {
    throw new AppError(messages.ACCOUNT_PERMANENTLY_DELETED, 401);
  }

  await securityDao.clearAccountDeletion(user.id);
  return { ...user, deletionRequestedAt: null, deletionScheduledAt: null };
};

module.exports = {
  getSecuritySettings,
  updateSecuritySettings,
  changePassword,
  requestAccountDeletion,
  recoverAccountIfPending,
  buildAccountDeletionStatus,
};
