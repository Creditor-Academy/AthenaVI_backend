const express = require('express');
const router = express.Router();
const {
  createAndSendOtp,
  verifyAndRegister,
  resendOtp,
  login,
  superadminLogin,
  refreshToken,
  logout,
  logoutAllDevices,
  forgetPassword,
  resetPassword,
} = require('./auth.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const {
  googleRedirect,
  superadminGoogleRedirect,
  googleCallback,
} = require('./auth.controller');
const authValidation = require('../validations/auth.validations');
const validate = require('../../middlewares/validate.middleware');

router.post(
  '/otp/generate',
  validate(authValidation.onlyEmailValidation),
  createAndSendOtp
);
router.post(
  '/otp/resend',
  validate(authValidation.onlyEmailValidation),
  resendOtp
);
router.post(
  '/register',
  validate(authValidation.verifyAndRegisterSchema),
  verifyAndRegister
);
router.post('/login', validate(authValidation.loginSchema), login);
router.post(
  '/superadmin/login',
  validate(authValidation.loginSchema),
  superadminLogin
);
router.post('/refresh', refreshToken);

router.post('/logout', logout);
router.post('/logout-all', authMiddleware, logoutAllDevices);
router.post(
  '/forget-password',
  validate(authValidation.onlyEmailValidation),
  forgetPassword
);
router.post(
  '/reset-password',
  validate(authValidation.resetPasswordSchema),
  resetPassword
);

// Google OAuth (GET so browser can be redirected)
router.get('/google', validate(authValidation.googleRedirectSchema), googleRedirect);
router.get('/superadmin/google', superadminGoogleRedirect);
router.get(
  '/google/callback',
  validate(authValidation.googleCallbackSchema),
  googleCallback
);

module.exports = router;
