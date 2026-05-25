const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const { sendEmail } = require('../../../shared/notification/email.service');
const authDao = require('../auth.dao');
const refreshTokenDao = require('../../sessions/refreshToken.dao');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const otpService = require('../services/otp.service');
const sessionService = require('../../sessions/session.service');
const { signAccessToken } = require('../../../shared/utils/jwt');
const passwordResetService = require('../services/passwordReset.service');
const logger = require('../../../shared/utils/logger');
const otpTemplate = require('../../../shared/templates/otp.template');
const resetPasswordTemplate = require('../../../shared/templates/passwordReset.template');
const googleOAuth = require('../services/googleOAuth.service');
const workspaceService = require('../../workspace/workspace.service');
const inboxService = require('../../inbox/inbox.service');

async function _issueSessionAndTokens({ userId, userAgent, ip }) {
  const sessionId = await sessionService.createSession({ userId, userAgent, ip });
  const accessToken = signAccessToken({ sub: userId, sessionId });

  const refreshTokenId = crypto.randomUUID();
  const refreshTokenSecret = crypto.randomBytes(40).toString('hex');
  const rawRefreshToken = `${refreshTokenId}.${refreshTokenSecret}`;
  const hashedRefreshToken = await bcrypt.hash(
    refreshTokenSecret,
    Number(process.env.SALT_ROUNDS)
  );

  await refreshTokenDao.create({
    id: refreshTokenId,
    token: hashedRefreshToken,
    sessionId,
    userId,
  });

  return { accessToken, rawRefreshToken };
}

async function sendOtp(email) {
  await otpService.acquireOtpLock(email);
  await otpService.checkResendLimit(email);

  const otp = crypto.randomInt(100000, 999999).toString();
  await otpService.storeOtp(email, otp);
  await sendEmail({
    to: email,
    subject: 'OTP Verification',
    html: otpTemplate(otp),
  });
}

async function registerUser({ name, email, password, otp, userAgent, ip }) {
  await otpService.verifyOtp({ email, otp });

  const existingUser = await authDao.findUserByEmail(email);
  if (existingUser) {
    throw new AppError(messages.USER_EMAIL_EXISTS, 409);
  }

  const hashedPassword = await bcrypt.hash(
    password,
    Number(process.env.SALT_ROUNDS)
  );
  const user = await authDao.createUser({ name, email, password: hashedPassword });
  await workspaceService.createPrivateWorkspaceForUser(user.id);
  await inboxService.syncPendingWorkspaceInvitations(user.id, user.email);

  const { accessToken, rawRefreshToken } = await _issueSessionAndTokens({
    userId: user.id,
    userAgent,
    ip,
  });

  return { accessToken, rawRefreshToken, user: { name: user.name, email: user.email } };
}

async function loginUser({ email, password, userAgent, ip }) {
  const user = await authDao.findUserByEmail(email);
  if (!user) {
    throw new AppError(messages.INVALID_CREDENTIALS, 401);
  }

  if (!user.password) {
    throw new AppError(messages.INVALID_CREDENTIALS, 401);
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new AppError(messages.INVALID_CREDENTIALS, 401);
  }

  const accountRecovered = Boolean(
    user.deletionScheduledAt && user.deletionScheduledAt > new Date()
  );

  const securityService = require('../../settings/security.service');
  await securityService.recoverAccountIfPending(user);

  const { accessToken, rawRefreshToken } = await _issueSessionAndTokens({
    userId: user.id,
    userAgent,
    ip,
  });

  return {
    accessToken,
    rawRefreshToken,
    user: { name: user.name, email: user.email },
    accountRecovered,
  };
}

async function rotateRefreshToken(incomingRawToken) {
  if (!incomingRawToken) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  const parts = incomingRawToken.split('.');
  if (parts.length !== 2) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  const [tokenId, secret] = parts;
  const savedToken = await refreshTokenDao.findById(tokenId);

  if (!savedToken) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  if (savedToken.isRevoked || savedToken.expiresAt < new Date()) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  const isValid = await bcrypt.compare(secret, savedToken.hashedToken);
  if (!isValid) {
    await refreshTokenDao.revokeBySession(savedToken.sessionId);
    await sessionService.deleteSession({ sessionId: savedToken.sessionId });
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  const sessionExists = await sessionService.findSession({
    sessionId: savedToken.sessionId,
  });
  if (!sessionExists) {
    throw new AppError(messages.SESSION_EXPIRED, 401);
  }

  await refreshTokenDao.revoke(savedToken.id);

  const newTokenId = crypto.randomUUID();
  const newSecret = crypto.randomBytes(40).toString('hex');
  const newRawRefreshToken = `${newTokenId}.${newSecret}`;
  const hashedRefreshToken = await bcrypt.hash(
    newSecret,
    Number(process.env.SALT_ROUNDS)
  );

  await refreshTokenDao.create({
    id: newTokenId,
    token: hashedRefreshToken,
    userId: savedToken.userId,
    sessionId: savedToken.sessionId,
  });

  const accessToken = signAccessToken({
    sub: savedToken.userId,
    sessionId: savedToken.sessionId,
  });

  return { accessToken, newRawRefreshToken };
}

async function logoutUser(rawToken) {
  if (!rawToken) {
    throw new AppError(messages.REFRESH_TOKEN_MISSING, 400);
  }

  const [refreshTokenId] = rawToken.split('.');
  const storedToken = await refreshTokenDao.findById(refreshTokenId);

  if (!storedToken) {
    throw new AppError(messages.NOT_FOUND, 404);
  }

  await sessionService.deleteSession({ sessionId: storedToken.sessionId });
  await refreshTokenDao.revoke(refreshTokenId);
}

async function logoutAllDevices(userId) {
  const tokens = await refreshTokenDao.findByUserId(userId);
  await refreshTokenDao.revokeAllByUserId(userId);
  await Promise.all(
    tokens.map((token) =>
      sessionService.deleteSession({ sessionId: token.sessionId })
    )
  );
}

async function sendPasswordResetEmail(email) {
  const user = await authDao.findUserByEmail(email);

  // Always silently succeed to prevent email enumeration
  if (!user) return;

  const resetToken = await passwordResetService.generateResetToken(user);
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

  try {
    await sendEmail({
      to: user.email,
      subject: 'Password Reset',
      html: resetPasswordTemplate(
        resetUrl,
        passwordResetService.RESET_TOKEN_EXPIRY_MINUTES
      ),
    });
  } catch (err) {
    logger.error('Password reset email failed', {
      email: user.email,
      error: err.message,
    });
  }
}

async function resetPassword({ token, newPassword }) {
  await passwordResetService.resetPassword({ token, newPassword });
}

async function handleGoogleOAuthCallback({ code, state, userAgent, ip }) {
  const stateValid = await googleOAuth.consumeState(state);
  if (!stateValid) {
    throw new AppError('invalid_state', 400);
  }

  let tokens;
  try {
    tokens = await googleOAuth.exchangeCodeForTokens(code);
  } catch {
    throw new AppError('token_exchange_failed', 400);
  }

  const { id_token: idToken, access_token, refresh_token, expires_in } = tokens;
  if (!idToken) {
    throw new AppError('no_id_token', 400);
  }

  let payload;
  try {
    payload = await googleOAuth.verifyIdToken(idToken);
  } catch {
    throw new AppError('invalid_id_token', 400);
  }

  const { sub: providerAccountId, email, email_verified, name, picture } = payload;
  if (!email) {
    throw new AppError('no_email', 400);
  }

  let user;
  const existingAccount = await authDao.findAccountByProvider('google', providerAccountId);

  if (existingAccount) {
    user = existingAccount.user;
  } else {
    const existingUser = await authDao.findUserByEmail(email);
    if (existingUser) {
      user = existingUser;
    } else {
      user = await authDao.createUser({
        name: name || null,
        email,
        password: null,
        profileImage: picture || null,
        emailVerified: Boolean(email_verified),
      });
      await workspaceService.createPrivateWorkspaceForUser(user.id);
      await inboxService.syncPendingWorkspaceInvitations(user.id, user.email);
    }
    await authDao.upsertGoogleAccount({
      userId: user.id,
      providerAccountId,
      accessToken: access_token,
      refreshToken: refresh_token,
      expiresAt: expires_in ? Math.floor(Date.now() / 1000) + expires_in : null,
      idToken,
    });
  }

  const securityService = require('../../settings/security.service');
  const accountRecovered = Boolean(
    user.deletionScheduledAt && user.deletionScheduledAt > new Date()
  );
  await securityService.recoverAccountIfPending(user);

  const { accessToken, rawRefreshToken } = await _issueSessionAndTokens({
    userId: user.id,
    userAgent,
    ip,
  });

  return {
    accessToken,
    rawRefreshToken,
    user: { name: user.name, email: user.email },
    accountRecovered,
  };
}

module.exports = {
  sendOtp,
  registerUser,
  loginUser,
  rotateRefreshToken,
  logoutUser,
  logoutAllDevices,
  sendPasswordResetEmail,
  resetPassword,
  handleGoogleOAuthCallback,
};
