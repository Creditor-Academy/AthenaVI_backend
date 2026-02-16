const { successResponse } = require('../../shared/utils/apiResponse');
const AppError = require('../../shared/utils/AppError');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const { sendEmail } = require('../notification/email.service');
const authDao = require('./auth.dao');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const otpService = require('./otp.service');
const { createSession } = require('../sessions/session.service');
const { signAccessToken } = require('../../shared/utils/jwt');
const { redisClient } = require('../../shared/config/redis');

const createAndSendOtp = asyncHandler(async (req, res) => {
  if (!req.body) {
    throw new AppError(messages.BODY_MISSING, 400);
  }
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
  console.log(`refresh token: ${refreshToken}`);

  const refreshToken = `${refreshTokenId}.${refreshTokenSecret}`;

  const hashedRefreshToken = await bcrypt.hash(
    refreshToken,
    Number(process.env.SALT_ROUNDS)
  );
  console.log(`hashed refresh token: ${hashedRefreshToken}`);

  console.log(user.id);

  // 7. Store refresh token (HASHED) in DB
  await authDao.storeRefreshToken({
    hashedRefreshToken,
    sessionId,
    userId: user.id,
  });

  // 8. Set refresh token in HTTP-only cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth/refresh',
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
  if (!req.body) {
    throw new AppError(messages.BODY_MISSING, 400);
  }
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
  console.log(`refresh token: ${refreshToken}`);

  const refreshToken = `${refreshTokenId}.${refreshTokenSecret}`;

  const hashedRefreshToken = await bcrypt.hash(
    refreshToken,
    Number(process.env.SALT_ROUNDS)
  );
  console.log(`hashed refresh token: ${hashedRefreshToken}`);

  console.log(user.id);

  // 6. Store refresh token (HASHED) in DB
  await authDao.storeRefreshToken({
    hashedRefreshToken,
    sessionId,
    userId: user.id,
  });

  // 7. Set refresh token in HTTP-only cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/api/auth/refresh',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return successResponse(
    req,
    res,
    {
      accessToken,
      user: { id: user.id, name: user.name, email: user.email },
    },
    200,
    messages.LOGIN_SUCCESS
  );
});

// const refreshToken = asyncHandler(async (req, res) => {
//   const refreshToken = req.cookies.refreshToken;

//   if (!refreshToken) {
//     throw new AppError(messages.UNAUTHORIZED, 401);
//   }

//   const payload = refreshToken.split('.')
//   const [tokenId, secret] = payload

//   const tokenData = await authDao.findTokenById(tokenId)

//   await bcrypt.compare(secret,tokenData.refreshToken)
  
//   const sessionExists= await redisClient.get(
//     `sessionId:${tokenData.sessionId}`
//   )

//   await authDao.revokeToken(tokenData.id)

//   const newTokenId = crypto.randomUUID();
//   const newSecret = crypto.randomBytes(40).toString('hex')
//   const newRefreshToken = `${newTokenId}.${newSecret}`


  
//   const hashedRefreshToken = await bcrypt.hash(
//     refreshToken,
//     Number(process.env.SALT_ROUNDS)
//   );


//   await authDao.storeRefreshToken({
//     hashedRefreshToken,
//     userId: tokenData.userId,
//     sessionId: tokenData.sessionId
//   })


//   res.cookies







// });

module.exports = { createAndSendOtp, verifyAndRegister, resendOtp, login };
