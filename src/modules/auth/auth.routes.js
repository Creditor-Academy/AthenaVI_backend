const express = require('express');
const router = express.Router();
const {
  createAndSendOtp,
  verifyAndRegister,
  resendOtp,
  login,
  refreshToken,
  googleRedirect,
  googleCallback,
} = require('./auth.controller');

router.post('/otp/generate', createAndSendOtp);
router.post('/otp/resend', resendOtp);
router.post('/register', verifyAndRegister);
router.post('/login', login);
router.post('/refresh', refreshToken);

// Google OAuth (GET so browser can be redirected)
router.get('/google', googleRedirect);
router.get('/google/callback', googleCallback);

module.exports = router;