const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const { heygenCreateAvatarMultipart } = require('../../middlewares/heygenAvatarCreate.middleware');
const { heygenAvatarFileUpload } = require('../../middlewares/heygenAvatarUpload.middleware');
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

router.post('/avatars/upload', heygenAvatarFileUpload, heygenController.uploadAvatarFile);

router.post('/avatars', heygenCreateAvatarMultipart, heygenController.createAvatar);

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

router.post(
  '/voices/select',
  validate(heygenValidation.selectVoiceBody),
  heygenController.selectVoice
);

router.post('/voices', validate(heygenValidation.designVoiceBody), heygenController.designVoice);

module.exports = router;
