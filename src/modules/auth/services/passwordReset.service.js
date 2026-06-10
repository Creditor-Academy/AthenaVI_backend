const authdao = require('../auth.dao');
const refreshTokenDao = require('../../sessions/refreshToken.dao');
const sessionService = require('../../sessions/session.service');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { getSaltRounds } = require('../../../shared/utils/bcryptConfig');

const RESET_TOKEN_EXPIRY_MINUTES = 15;

const generateResetToken = async (user) => {
  const rawToken = crypto.randomBytes(32).toString('hex');

  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

  const expiresAt = new Date(
    Date.now() + RESET_TOKEN_EXPIRY_MINUTES * 60 * 1000
  );

  await authdao.createPasswordResetToken({
    userId: user.id,
    tokenHash,
    expiresAt,
  });

  return rawToken;
};

const resetPassword = async ({ token, newPassword }) => {
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const record = await authdao.findValidPasswordResetTokenByHash(tokenHash);

  if (!record) {
    throw new AppError(messages.PASSWORD_RESET_TOKEN_INVALID, 400);
  }

  const hashedPassword = await bcrypt.hash(newPassword, getSaltRounds());

  await authdao.updatePasswordAndInvalidateResetTokens({userId: record.userId, hashedPassword})
  
  // Invalidate all sessions
  const tokens = await refreshTokenDao.findByUserId(record.userId);

  await refreshTokenDao.revokeAllByUserId(record.userId);

  await Promise.all(
    tokens.map((t) =>
      sessionService.deleteSession({ sessionId: t.sessionId })
    )
  );

  return true;
};

module.exports = {
  RESET_TOKEN_EXPIRY_MINUTES,
  generateResetToken,
  resetPassword,
};
