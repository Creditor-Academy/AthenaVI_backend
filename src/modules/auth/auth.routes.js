const express = require('express')
const router = express.Router()
const {createAndSendOtp, verifyAndRegister, resendOtp, login } = require('./auth.controller')

router.post('/otp/generate', createAndSendOtp)
router.post('/otp/resend', resendOtp)
router.post('/register', verifyAndRegister)
router.post('/login', login )


module.exports = router