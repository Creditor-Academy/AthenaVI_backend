const authdao = require('../auth.dao');
const refreshTokenDao= require('../../sessions/refreshToken.dao');
const sessionService = require('../../sessions/session.service');
const crypto = require('crypto');
const bcrypt = require('bcrypt')

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
    throw new Error('Invalid or expired token');
  }

  const hashedPassword = await bcrypt.hash(
    newPassword,
    Number(process.env.SALT_ROUNDS)
  );

  await authdao.updatePasswordAndInvalidateResetTokens({userId: record.userId, hashedPassword})
  
  // Invalidate all sessions
  const tokens = await refreshTokenDao.findByUserId(record.userId);

  await refreshTokenDao.revokeAllByUserId(record.userId);

  await Promise.all(tokens.map((token) => sessionService.deleteSession(token.sessionId)));

  return true;
};

module.exports = {
  generateResetToken,
  resetPassword,
};
