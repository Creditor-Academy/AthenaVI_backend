const express = require('express');
const { optionalAuthMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const presentationShareValidations = require('../validations/presentationShare.validations');
const presentationShareController = require('./presentationShare.controller');

/**
 * Public capability-link routes (`/api/p`). Mounted outside `/api/workspaces` because the token
 * itself is the permission: no workspace membership and no login are required. Every handler is
 * read-only; nothing here can mutate a deck.
 */
const router = express.Router();

/**
 * The capability token travels in the URL path, so keep it out of downstream Referer headers
 * (helmet() already defaults to this; pinning it here keeps it true for every response on this
 * router, including validation errors that never reach a controller).
 */
router.use((req, res, next) => {
  res.set('Referrer-Policy', 'no-referrer');
  next();
});

router.use(optionalAuthMiddleware);

router.get(
  '/:token',
  validate(presentationShareValidations.publicShareTokenSchema),
  presentationShareController.getPublicPresentation
);

router.get(
  '/:token/session',
  validate(presentationShareValidations.publicShareTokenSchema),
  presentationShareController.getPublicSession
);

router.put(
  '/:token/presence',
  validate(presentationShareValidations.publicPresenceHeartbeatSchema),
  presentationShareController.heartbeatPresence
);

router.get(
  '/:token/presence',
  validate(presentationShareValidations.publicShareTokenSchema),
  presentationShareController.listPresence
);

router.delete(
  '/:token/presence',
  validate(presentationShareValidations.publicPresenceLeaveSchema),
  presentationShareController.leavePresence
);

module.exports = router;
