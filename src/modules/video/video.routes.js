const express = require('express');
const videoController = require('./video.controller');

const router = express.Router();


router.post("/avatar/generate", videoController.generateAvatarVideo);


module.exports = router;