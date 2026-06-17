const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const speechValidation = require('./speech.validation');
const speechController = require('./speech.controller');

const router = express.Router({ mergeParams: true });

router.post('/', validate(speechValidation.createSpeechSchema), speechController.createSpeech);

router.get('/', validate(speechValidation.listSpeechSchema), speechController.listSpeechGenerations);

router.head(
  '/:speechId/stream',
  validate(speechValidation.getStreamSchema),
  speechController.headSpeechStream
);

router.get(
  '/:speechId/stream',
  validate(speechValidation.getStreamSchema),
  speechController.streamSpeech
);

router.get(
  '/:speechId/download',
  validate(speechValidation.downloadSpeechSchema),
  speechController.downloadSpeech
);

router.get(
  '/:speechId',
  validate(speechValidation.getSpeechSchema),
  speechController.getSpeechGeneration
);

module.exports = router;
