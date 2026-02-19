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
} = require('./auth.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');

router.post('/otp/generate', createAndSendOtp);
router.post('/otp/resend', resendOtp);
router.post('/register', verifyAndRegister);
router.post('/login', login);
router.post('/refresh', refreshToken);
router.post('/logout', logout);
router.post('/logout-all', authMiddleware, logoutAllDevices)

module.exports = router;
