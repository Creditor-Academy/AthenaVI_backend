const express = require('express');
const videoController = require('./video.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');

const router = express.Router();

router.post("/generate", authMiddleware, videoController.generateVideo);

router.get("/status/:jobId",authMiddleware, videoController.getVideoStatus);

module.exports = router;