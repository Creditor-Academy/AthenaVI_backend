const express = require('express');
const router = express.Router();
const heygenController = require('./heygen.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');

router.get('/tts', authMiddleware, heygenController.getVoiceList);

// router.post('/generate',authMiddleware, heygenController.generateVideo);


// router.get("/status/:jobId", videoController.getVideoStatus);



module.exports = router;