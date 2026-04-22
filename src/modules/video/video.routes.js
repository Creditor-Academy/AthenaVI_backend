const express = require('express');
const videoController = require('./video.controller');

const router = express.Router();


router.post("/generate", videoController.generateVideo);


module.exports = router;