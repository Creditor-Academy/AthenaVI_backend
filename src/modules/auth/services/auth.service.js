const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const { sendEmail } = require('../../../shared/notification/email.service');
const authDao = require('../auth.dao');
const refreshTokenDao = require('../../sessions/refreshToken.dao');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const otpService = require('../services/otp.service');
const authRateLimitService = require('../services/authRateLimit.service');
const sessionService = require('../../sessions/session.service');
const { signAccessToken } = require('../../../shared/utils/jwt');
const passwordResetService = require('../services/passwordReset.service');
const logger = require('../../../shared/utils/logger');
const otpTemplate = require('../../../shared/templates/otp.template');
const resetPasswordTemplate = require('../../../shared/templates/passwordReset.template');
const googleOAuth = require('../services/googleOAuth.service');
const inboxService = require('../../inbox/inbox.service');
const { normalizeEmail } = require('../../../shared/utils/normalizeEmail');
const { isPrismaUniqueConstraintError } = require('../../../shared/utils/prismaErrors');
const { getSaltRounds } = require('../../../shared/utils/bcryptConfig');
const {
  hasPlatformSuperadminAccess,
} = require('../../../shared/services/platformSuperadmin.service');

async function _issueSessionAndTokens({ userId, userAgent, ip }) {
  const sessionId = await sessionService.createSession({ userId, userAgent, ip });
  const accessToken = signAccessToken({ sub: userId, sessionId });

  const refreshTokenId = crypto.randomUUID();
  const refreshTokenSecret = crypto.randomBytes(40).toString('hex');
  const rawRefreshToken = `${refreshTokenId}.${refreshTokenSecret}`;
  const hashedRefreshToken = await bcrypt.hash(refreshTokenSecret, getSaltRounds());

  await refreshTokenDao.create({
    id: refreshTokenId,
    token: hashedRefreshToken,
    sessionId,
    userId,
  });

  return { accessToken, rawRefreshToken };
}

async function _failLogin({ email, ip }) {
  await authRateLimitService.recordLoginFailure({ email, ip });
  throw new AppError(messages.INVALID_CREDENTIALS, 401);
}

async function sendOtp(email) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    throw new AppError(messages.EMAIL_REQUIRED, 400);
  }

  const existingUser = await authDao.findUserByEmail(normalizedEmail);
  if (existingUser) {
    return;
  }

  await otpService.acquireOtpLock(normalizedEmail);

  try {
    await otpService.checkResendLimit(normalizedEmail);

    const otp = crypto.randomInt(100000, 999999).toString();
    await otpService.storeOtp(normalizedEmail, otp);
    await sendEmail({
      to: normalizedEmail,
      subject: 'OTP Verification',
      html: otpTemplate(otp),
    });
  } finally {
    await otpService.releaseOtpLock(normalizedEmail);
  }
}

async function registerUser({ name, email, password, otp, userAgent, ip }) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    throw new AppError(messages.EMAIL_REQUIRED, 400);
  }

  const existingUser = await authDao.findUserByEmail(normalizedEmail);
  if (existingUser) {
    throw new AppError(messages.USER_EMAIL_EXISTS, 409);
  }

  await otpService.verifyOtp({ email: normalizedEmail, otp });

  const hashedPassword = await bcrypt.hash(password, getSaltRounds());

  let user;
  try {
    user = await authDao.createUserWithPrivateWorkspace({
      name,
      email: normalizedEmail,
      password: hashedPassword,
      emailVerified: true,
    });
  } catch (err) {
    if (isPrismaUniqueConstraintError(err)) {
      throw new AppError(messages.USER_EMAIL_EXISTS, 409);
    }
    throw err;
  }

  try {
    await inboxService.syncPendingWorkspaceInvitations(user.id, user.email);
  } catch (err) {
    logger.error('Failed to sync pending workspace invitations after register', {
      userId: user.id,
      email: user.email,
      error: err.message,
    });
  }

  const { accessToken, rawRefreshToken } = await _issueSessionAndTokens({
    userId: user.id,
    userAgent,
    ip,
  });

  return { accessToken, rawRefreshToken, user: { name: user.name, email: user.email } };
}

async function loginUser({ email, password, userAgent, ip }) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    await _failLogin({ email: email || '', ip });
  }

  await authRateLimitService.assertLoginAllowed({ email: normalizedEmail, ip });

  const user = await authDao.findUserByEmail(normalizedEmail);
  if (!user) {
    await _failLogin({ email: normalizedEmail, ip });
  }

  if (!user.password) {
    await _failLogin({ email: normalizedEmail, ip });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    await _failLogin({ email: normalizedEmail, ip });
  }

  await authRateLimitService.clearLoginAttempts({ email: normalizedEmail, ip });

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

async function loginSuperadminUser({ email, password, userAgent, ip }) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    await _failLogin({ email: email || '', ip });
  }

  await authRateLimitService.assertLoginAllowed({ email: normalizedEmail, ip });

  const user = await authDao.findUserByEmail(normalizedEmail);
  if (!user) {
    await _failLogin({ email: normalizedEmail, ip });
  }

  if (!user.password) {
    await _failLogin({ email: normalizedEmail, ip });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    await _failLogin({ email: normalizedEmail, ip });
  }

  if (!hasPlatformSuperadminAccess(user)) {
    throw new AppError(messages.PLATFORM_SUPERADMIN_REQUIRED, 403);
  }

  await authRateLimitService.clearLoginAttempts({ email: normalizedEmail, ip });

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
    isPlatformSuperadmin: true,
    portal: 'superadmin',
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
  const hashedRefreshToken = await bcrypt.hash(newSecret, getSaltRounds());

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
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) {
    return;
  }

  const user = await authDao.findUserByEmail(normalizedEmail);

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
  const portal = await googleOAuth.consumeState(state);
  if (!portal) {
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

  const normalizedEmail = normalizeEmail(email);

  let user;
  const existingAccount = await authDao.findAccountByProvider('google', providerAccountId);

  if (existingAccount) {
    user = existingAccount.user;
  } else {
    const existingUser = await authDao.findUserByEmail(normalizedEmail);
    if (existingUser) {
      user = existingUser;
    } else {
      let isNewUser = true;
      try {
        user = await authDao.createUserWithPrivateWorkspace({
          name: name || null,
          email: normalizedEmail,
          password: null,
          profileImage: picture || null,
          emailVerified: Boolean(email_verified),
        });
      } catch (err) {
        if (isPrismaUniqueConstraintError(err)) {
          isNewUser = false;
          user = await authDao.findUserByEmail(normalizedEmail);
          if (!user) {
            throw err;
          }
        } else {
          throw err;
        }
      }

      if (isNewUser) {
        try {
          await inboxService.syncPendingWorkspaceInvitations(user.id, user.email);
        } catch (err) {
          logger.error('Failed to sync pending workspace invitations after Google signup', {
            userId: user.id,
            email: user.email,
            error: err.message,
          });
        }
      }
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

  if (portal === 'superadmin' && !hasPlatformSuperadminAccess(user)) {
    throw new AppError(messages.PLATFORM_SUPERADMIN_REQUIRED, 403);
  }

  const { accessToken, rawRefreshToken } = await _issueSessionAndTokens({
    userId: user.id,
    userAgent,
    ip,
  });

  const result = {
    accessToken,
    rawRefreshToken,
    user: { name: user.name, email: user.email },
    accountRecovered,
    portal,
  };

  if (portal === 'superadmin') {
    result.isPlatformSuperadmin = true;
  }

  return result;
}

module.exports = {
  sendOtp,
  registerUser,
  loginUser,
  loginSuperadminUser,
  rotateRefreshToken,
  logoutUser,
  logoutAllDevices,
  sendPasswordResetEmail,
  resetPassword,
  handleGoogleOAuthCallback,
};
