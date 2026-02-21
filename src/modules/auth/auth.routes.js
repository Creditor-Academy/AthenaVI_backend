const express = require('express');
const router = express.Router();
const {
  createAndSendOtp,
  verifyAndRegister,
  resendOtp,
  login,
  refreshToken,
  logout,
  logoutAllDevices,
  forgetPassword,
  resetPassword,
} = require('./auth.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { googleRedirect, googleCallback } = require('./auth.controller');

router.post('/otp/generate', createAndSendOtp);
router.post('/otp/resend', resendOtp);
router.post('/register', verifyAndRegister);
router.post('/login', login);
router.post('/refresh', refreshToken);
router.post('/logout', logout);
router.post('/logout-all', authMiddleware, logoutAllDevices);
router.post('/forget-password', forgetPassword);
router.post('/reset-password', resetPassword);

// Google OAuth (GET so browser can be redirected)
router.get('/google', googleRedirect);
router.get('/google/callback', googleCallback);

module.exports = router;
