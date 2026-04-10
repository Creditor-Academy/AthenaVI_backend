const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const authService = require('./services/auth.service');
const googleOAuth = require('./services/googleOAuth.service');

function setRefreshCookie(res, token) {
  res.cookie('refreshToken', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshCookie(res) {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });
}

const createAndSendOtp = asyncHandler(async (req, res) => {
  await authService.sendOtp(req.body.email);
  return successResponse(req, res, null, 200, messages.OTP_SENT);
});

const resendOtp = asyncHandler(async (req, res) => {
  await authService.sendOtp(req.body.email);
  return successResponse(req, res, null, 200, messages.OTP_SENT);
});

const verifyAndRegister = asyncHandler(async (req, res) => {
  const { name, email, password, otp } = req.body;
  const { accessToken, rawRefreshToken, user } = await authService.registerUser({
    name,
    email,
    password,
    otp,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });
  setRefreshCookie(res, rawRefreshToken);
  return successResponse(req, res, { accessToken, user }, 201, messages.USER_CREATED);
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const { accessToken, rawRefreshToken, user } = await authService.loginUser({
    email,
    password,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });
  setRefreshCookie(res, rawRefreshToken);
  return successResponse(req, res, { accessToken, user }, 200, messages.LOGIN_SUCCESS);
});

const refreshToken = asyncHandler(async (req, res) => {
  const { accessToken, newRawRefreshToken } = await authService.rotateRefreshToken(
    req.cookies.refreshToken
  );
  setRefreshCookie(res, newRawRefreshToken);
  return successResponse(req, res, { accessToken }, 201, messages.TOKEN_GENERATED);
});

const logout = asyncHandler(async (req, res) => {
  await authService.logoutUser(req.cookies.refreshToken);
  clearRefreshCookie(res);
  return successResponse(req, res, {}, 200, messages.LOGOUT_SUCCESSFULLY);
});

const logoutAllDevices = asyncHandler(async (req, res) => {
  await authService.logoutAllDevices(req.user.id);
  clearRefreshCookie(res);
  return successResponse(req, res, {}, 200, messages.LOGOUT_SUCCESSFULLY);
});

const forgetPassword = asyncHandler(async (req, res) => {
  await authService.sendPasswordResetEmail(req.body.email);
  return successResponse(req, res, {}, 200, messages.PASSWORD_LINK_SEND);
});

const resetPassword = asyncHandler(async (req, res) => {
  await authService.resetPassword(req.body);
  return successResponse(req, res, {}, 200, messages.PASSWORD_RESET);
});

// ----- Google OAuth -----

const googleRedirect = asyncHandler(async (req, res) => {
  const state = await googleOAuth.createState();
  const url = googleOAuth.getAuthUrl(state);
  res.redirect(302, url);
});

const googleCallback = asyncHandler(async (req, res) => {
  const { code, state } = req.query;
  const errorRedirect = process.env.FRONTEND_URL || '/';

  if (!code) {
    return res.redirect(302, `${errorRedirect}?error=missing_code`);
  }

  let result;
  try {
    result = await authService.handleGoogleOAuthCallback({
      code,
      state,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    });
  } catch (err) {
    const error = err.message || 'oauth_failed';
    return res.redirect(302, `${errorRedirect}?error=${encodeURIComponent(error)}`);
  }

  const { accessToken, rawRefreshToken, user } = result;
  setRefreshCookie(res, rawRefreshToken);

  const frontendUrl = (process.env.FRONTEND_URL || '').replace(/\/$/, '');
  const successPath = process.env.OAUTH_SUCCESS_PATH || '/auth/callback';
  const redirectUrl = frontendUrl
    ? `${frontendUrl}${successPath}#access_token=${encodeURIComponent(accessToken)}`
    : null;

  if (redirectUrl) {
    res.redirect(302, redirectUrl);
  } else {
    return successResponse(req, res, { accessToken, user }, 200, messages.LOGIN_SUCCESS);
  }
});

module.exports = {
  createAndSendOtp,
  verifyAndRegister,
  resendOtp,
  login,
  refreshToken,
  logout,
  logoutAllDevices,
  forgetPassword,
  resetPassword,
  googleRedirect,
  googleCallback,
};
