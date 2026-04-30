const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const { uploadHeygenAsset } = require('../../middlewares/heygenUpload.middleware');
const heygenController = require('./heygen.controller');
const heygenValidation = require('./heygen.validation');

const router = express.Router();

router.use(authMiddleware);

router.get(
  '/avatars/groups',
  validate(heygenValidation.listAvatarGroupsQuery),
  heygenController.listAvatarGroups
);

router.get(
  '/avatars/looks',
  validate(heygenValidation.listAvatarLooksQuery),
  heygenController.listAvatarLooks
);

router.post('/avatars', heygenController.createAvatar);

router.post(
  '/avatars/:groupId/consent',
  validate(heygenValidation.createAvatarConsentBody),
  heygenController.createAvatarConsent
);

router.get('/voices', validate(heygenValidation.listVoicesQuery), heygenController.listVoices);

router.post(
  '/voices/preview-speech',
  validate(heygenValidation.previewSpeechBody),
  heygenController.previewSpeech
);

router.post(
  '/voices/clone',
  validate(heygenValidation.cloneVoiceBody),
  heygenController.cloneVoice
);

router.get(
  '/voices/:voiceId',
  validate(heygenValidation.getVoiceParams),
  heygenController.getVoice
);

router.post('/voices', validate(heygenValidation.designVoiceBody), heygenController.designVoice);

router.post(
  '/assets',
  uploadHeygenAsset.single('file'),
  heygenController.uploadAsset
);

router.get(
  '/assets/audio-proxy',
  validate(heygenValidation.audioProxyQuery),
  heygenController.proxyAudio
);

router.post('/generate', heygenController.generateHeygenVideo);

module.exports = router;
