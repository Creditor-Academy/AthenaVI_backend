const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const presentationShareValidations = require('../validations/presentationShare.validations');
const presentationShareController = require('./presentationShare.controller');

/**
 * Owner-side share management. Mounted under `/:presentationId/share` from
 * presentation.routes.js, which already sits behind authMiddleware + requireWorkspaceRole.
 */
const router = express.Router({ mergeParams: true });

router.get(
  '/',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.getShare
);

router.put(
  '/viewer',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.enableShareViewer
);

router.put(
  '/reviewer',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.enableShareReviewer
);

router.patch(
  '/viewer',
  validate(presentationShareValidations.patchShareSchema),
  presentationShareController.patchShareViewer
);

router.patch(
  '/reviewer',
  validate(presentationShareValidations.patchShareSchema),
  presentationShareController.patchShareReviewer
);

router.post(
  '/viewer/rotate',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.rotateShareViewer
);

router.post(
  '/reviewer/rotate',
  validate(presentationShareValidations.shareByPresentationSchema),
  presentationShareController.rotateShareReviewer
);

module.exports = router;
