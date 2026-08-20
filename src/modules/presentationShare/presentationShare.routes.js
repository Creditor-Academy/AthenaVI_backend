const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const presentationShareValidations = require('../validations/presentationShare.validations');
const presentationShareController = require('./presentationShare.controller');

/**
 * Owner-side share management. Mounted under `/:presentationId/share` from
 * presentation.routes.js, which already sits behind authMiddleware + requireWorkspaceRole.
 */
const router = express.Router({ mergeParams: true });

router.put(
  '/',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.enableShare
);

router.get(
  '/',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.getShare
);

router.patch(
  '/',
  validate(presentationShareValidations.patchShareSchema),
  presentationShareController.updateShare
);

router.post(
  '/rotate',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.rotateShare
);

module.exports = router;
