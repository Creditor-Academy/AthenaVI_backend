const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const heygenVideoValidation = require('./heygenVideo.validation');
const heygenVideoController = require('./heygenVideo.controller');

const router = express.Router({ mergeParams: true });

router.post(
  '/videos',
  validate(heygenVideoValidation.createHeygenVideoSchema),
  heygenVideoController.createHeygenVideo
);

router.get(
  '/videos',
  validate(heygenVideoValidation.listHeygenVideosSchema),
  heygenVideoController.listHeygenVideos
);

router.get(
  '/videos/:heygenVideoId',
  validate(heygenVideoValidation.getHeygenVideoSchema),
  heygenVideoController.getHeygenVideo
);

router.get(
  '/videos/:heygenVideoId/download',
  validate(heygenVideoValidation.downloadHeygenVideoSchema),
  heygenVideoController.downloadHeygenVideo
);

module.exports = router;
