const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const heygenShareController = require('./heygenShare.controller');
const heygenShareValidation = require('../validations/heygenShare.validations');

const router = express.Router({ mergeParams: true });

router.get(
  '/shared-avatars',
  validate(heygenShareValidation.workspaceHeygenListParamsSchema),
  heygenShareController.listSharedAvatars
);

router.get(
  '/shared-voices',
  validate(heygenShareValidation.workspaceHeygenListParamsSchema),
  heygenShareController.listSharedVoices
);

router.post(
  '/avatars/:groupId/share',
  validate(heygenShareValidation.workspaceGroupIdParamsSchema),
  heygenShareController.shareAvatar
);

router.delete(
  '/avatars/:groupId/share',
  validate(heygenShareValidation.workspaceGroupIdParamsSchema),
  heygenShareController.unshareAvatar
);

router.post(
  '/voices/:voiceId/share',
  validate(heygenShareValidation.workspaceVoiceIdParamsSchema),
  heygenShareController.shareVoice
);

router.delete(
  '/voices/:voiceId/share',
  validate(heygenShareValidation.workspaceVoiceIdParamsSchema),
  heygenShareController.unshareVoice
);

module.exports = router;
