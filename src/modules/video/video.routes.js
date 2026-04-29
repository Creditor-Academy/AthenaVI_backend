const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const videoValidation = require('./video.validation');
const videoController = require('./video.controller');

const router = express.Router();

router.post(
  '/avatar/generate',
  validate(videoValidation.generateAvatarVideoSchema),
  videoController.generateAvatarVideo
);


module.exports = router;