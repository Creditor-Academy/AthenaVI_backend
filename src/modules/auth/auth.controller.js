const { successResponse } = require('../../shared/utils/apiResponse');
const AppError = require('../../shared/utils/AppError');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const { sendEmail } = require('../notification/email.service');
const authDao = require('./auth.dao');
const refreshTokenDao = require('../sessions/refreshToken.dao');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const otpService = require('./otp.service');
const {
  createSession,
  deleteSession,
  findSession,
} = require('../sessions/session.service');
const { signAccessToken } = require('../../shared/utils/jwt');
const { redisClient } = require('../../shared/config/redis');

const createAndSendOtp = asyncHandler(async (req, res) => {
  const { email } = req.body;
  console.log(email);

  if (!email) {
    throw new AppError(messages.EMAIL_REQUIRED, 400);
  }

  await otpService.acquireOtpLock(email);
  await otpService.checkResendLimit(email);

  const otp = crypto.randomInt(100000, 999999).toString();
  console.log(otp);

  await otpService.storeOtp(email, otp);
  await sendEmail({ email, otp });

  return successResponse(req, res, null, 200, messages.OTP_SENT);
});

const verifyAndRegister = asyncHandler(async (req, res) => {
  const { name, email, password, otp } = req.body;

  if (!name || !email || !password || !otp) {
    throw new AppError(messages.ALL_FIELDS_REQUIRED);
  }

  // 1. Verify OTP
  await otpService.verifyOtp({ email, otp });

  // 2. Check user
  const existingUser = await authDao.findUserByEmail(email);
  if (existingUser) {
    throw new AppError(messages.USER_EMAIL_EXISTS, 409);
  }

  // 3. Create user
  const hashedPassword = await bcrypt.hash(
    password,
    Number(process.env.SALT_ROUNDS)
  );

  const user = await authDao.createUser({
    name,
    email,
    password: hashedPassword,
  });

  // 4. Create session (Redis)
  const sessionId = await createSession({
    userId: user.id,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });
  console.log(`session: ${sessionId}`);

  // 5. Issue JWT
  const accessToken = signAccessToken({
    sub: user.id,
    sessionId,
  });
  console.log(`token: ${accessToken}`);

  // 6. Generate refresh token (raw)
  const refreshTokenId = crypto.randomUUID();
  const refreshTokenSecret = await crypto.randomBytes(40).toString('hex');

  const refreshToken = `${refreshTokenId}.${refreshTokenSecret}`;
  console.log(`refresh token: ${refreshToken}`);

  const hashedRefreshToken = await bcrypt.hash(
    refreshTokenSecret,
    Number(process.env.SALT_ROUNDS)
  );
  console.log(`hashed refresh token: ${hashedRefreshToken}`);

  console.log(user.id);

  // 7. Store refresh token (HASHED) in DB
  await refreshTokenDao.create({
    id: refreshTokenId,
    token: hashedRefreshToken,
    sessionId,
    userId: user.id,
  });

  // 8. Set refresh token in HTTP-only cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return successResponse(
    req,
    res,
    {
      accessToken,
      user: { name: user.name, email: user.email },
    },
    201,
    messages.USER_CREATED
  );
});

const resendOtp = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if (!email) {
    throw new AppError(messages.EMAIL_REQUIRED, 400);
  }
  await otpService.acquireOtpLock(email);
  await otpService.checkResendLimit(email);

  const otp = crypto.randomInt(100000, 999999).toString();
  console.log(otp);

  await otpService.storeOtp(email, otp);
  await sendEmail({ email, otp });

  return successResponse(req, res, null, 200, messages.OTP_SENT);
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  console.log(email, password);

  if (!email || !password) {
    throw new AppError(messages.ALL_FIELDS_REQUIRED, 400);
  }

  // 1. Find user
  const user = await authDao.findUserByEmail(email);
  if (!user) {
    throw new AppError(messages.INVALID_CREDENTIALS, 401);
  }
  console.log(user);

  // 2. Verify password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    throw new AppError(messages.INVALID_CREDENTIALS, 401);
  }

  // 3. Create Redis session
  const sessionId = await createSession({
    userId: user.id,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });
  console.log(sessionId);

  // 4. Issue JWT
  const accessToken = signAccessToken({
    sub: user.id,
    sessionId,
  });

  // 5. Generate refresh token (raw)
  const refreshTokenId = crypto.randomUUID();
  const refreshTokenSecret = await crypto.randomBytes(40).toString('hex');
  const refreshToken = `${refreshTokenId}.${refreshTokenSecret}`;

  console.log(`refresh token: ${refreshToken}`);

  const hashedRefreshToken = await bcrypt.hash(
    refreshTokenSecret,
    Number(process.env.SALT_ROUNDS)
  );
  console.log(`hashed refresh token: ${hashedRefreshToken}`);

  console.log(user.id);

  // 6. Store refresh token (HASHED) in DB
  await refreshTokenDao.create({
    id: refreshTokenId,
    token: hashedRefreshToken,
    sessionId,
    userId: user.id,
  });

  // 7. Set refresh token in HTTP-only cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return successResponse(
    req,
    res,
    {
      accessToken,
      user: { name: user.name, email: user.email },
    },
    200,
    messages.LOGIN_SUCCESS
  );
});

const refreshToken = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }
  // 1. Split tokenId.secret
  const parts = refreshToken.split('.');
  if (parts.length !== 2) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  const [tokenId, secret] = parts;
  console.log('token', tokenId);
  console.log('secret', secret);

  // 2. Fetch token row (O(1))
  const savedToken = await refreshTokenDao.findById(tokenId);
  console.log(savedToken);

  if (!savedToken) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  // 3. Check revoked / expired
  if (savedToken.isRevoked || savedToken.expiresAt < new Date()) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  // 4. Verify secret
  const isValid = await bcrypt.compare(secret, savedToken.hashedToken);
  if (!isValid) {
    // Possible token reuse attack
    await refreshTokenDao.revokeBySession(savedToken.sessionId);
    await deleteSession(storedToken.sessionId);
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  // 5. Check Redis session
  const sessionExists = await findSession({ sessionId: savedToken.sessionId });
  console.log(sessionExists);

  if (!sessionExists) {
    throw new AppError(messages.SESSION_EXPIRED, 401);
  }

  // 6. ROTATION: revoke old token
  await refreshTokenDao.revoke(savedToken.id);

  // 7. Generate NEW refresh token
  const newTokenId = crypto.randomUUID();
  const newSecret = crypto.randomBytes(40).toString('hex');
  const newRefreshToken = `${newTokenId}.${newSecret}`;

  const hashedRefreshToken = await bcrypt.hash(
    newSecret,
    Number(process.env.SALT_ROUNDS)
  );

  await refreshTokenDao.create({
    id: newTokenId, // later
    token: hashedRefreshToken,
    userId: savedToken.userId,
    sessionId: savedToken.sessionId,
  });

  // 8. Set new refresh token cookie
  res.cookie('refreshToken', newRefreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  // 9. Issue new access token

  const accessToken = signAccessToken({
    sub: savedToken.userId,
    sessionId: savedToken.sessionId,
  });

  return successResponse(
    req,
    res,
    { accessToken },
    201,
    messages.TOKEN_GENERATED
  );
});

const logout = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    throw new AppError(messages.REFRESH_TOKEN_MISSING, 400);
  }
  const [refreshTokenId] = refreshToken.split('.');
  console.log('refreshtoken id ', refreshTokenId);

  const storedToken = await refreshTokenDao.findById(refreshTokenId);
  console.log(storedToken);

  if (!storedToken) {
    throw new Error(messages.NOT_FOUND, 404);
  }

  await deleteSession({ sessionId: storedToken.sessionId });
  await refreshTokenDao.revoke(refreshTokenId);

  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });

  return successResponse(req, res, {}, 200, messages.LOGOUT_SUCCESSFULLY);
});

const logoutAllDevices = asyncHandler(async (req, res) => {
  const userId = req.user.id;

  // Fetch sessions
  const tokens = await refreshTokenDao.findByUserId(userId);

  // Revoke all refresh tokens
  await refreshTokenDao.revokeAllByUserId(userId);

  // Delete all Redis sessions in parallel
  await Promise.all(
    tokens.map((token) => deleteSession({ sessionId: token.sessionId }))
  );

  // Clear refresh token cookie on current device
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });

  return successResponse(req, res, {}, 200, messages.LOGOUT_SUCCESSFULLY);
});

module.exports = {
  createAndSendOtp,
  verifyAndRegister,
  resendOtp,
  login,
  refreshToken,
  logout,
  logoutAllDevices,
};
