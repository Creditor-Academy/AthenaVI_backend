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
  '/videos/:heygenVideoId/s3-location',
  validate(heygenVideoValidation.getS3LocationSchema),
  heygenVideoController.getHeygenVideoS3Location
);

router.head(
  '/videos/:heygenVideoId/stream',
  validate(heygenVideoValidation.getStreamSchema),
  heygenVideoController.headHeygenVideoStream
);

router.get(
  '/videos/:heygenVideoId/stream',
  validate(heygenVideoValidation.getStreamSchema),
  heygenVideoController.streamHeygenVideo
);

router.get(
  '/videos/:heygenVideoId/download',
  validate(heygenVideoValidation.downloadHeygenVideoSchema),
  heygenVideoController.downloadHeygenVideo
);

router.get(
  '/videos/:heygenVideoId',
  validate(heygenVideoValidation.getHeygenVideoSchema),
  heygenVideoController.getHeygenVideo
);

module.exports = router;
