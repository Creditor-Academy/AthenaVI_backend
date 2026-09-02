const express = require('express');
const { optionalAuthMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const presentationShareValidations = require('../validations/presentationShare.validations');
const presentationShareController = require('./presentationShare.controller');
const presentationCommentValidations = require('../presentationComment/presentationComment.validation');
const presentationCommentController = require('../presentationComment/presentationComment.controller');

/**
 * Public capability-link routes (`/api/p`). Mounted outside `/api/workspaces` because the token
 * itself is the permission: no workspace membership and no login are required. Nothing here can
 * mutate a deck — comments are the only writes, and only on links with `access: COMMENT`.
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

/**
 * Comments. Guests identify themselves with the same `viewerSessionId` the presence heartbeat
 * uses; the mention picker is members-only so a share link cannot enumerate the workspace.
 */
router.get(
  '/:token/comments/mentionable-users',
  validate(presentationCommentValidations.publicMentionableUsersSchema),
  presentationCommentController.getPublicMentionableUsers
);

router.get(
  '/:token/comments',
  validate(presentationCommentValidations.publicListCommentsSchema),
  presentationCommentController.listPublicComments
);

router.post(
  '/:token/comments',
  validate(presentationCommentValidations.publicCreateCommentSchema),
  presentationCommentController.createPublicComment
);

router.patch(
  '/:token/comments/:commentId',
  validate(presentationCommentValidations.publicUpdateCommentSchema),
  presentationCommentController.updatePublicComment
);

router.delete(
  '/:token/comments/:commentId',
  validate(presentationCommentValidations.publicDeleteCommentSchema),
  presentationCommentController.deletePublicComment
);

router.post(
  '/:token/comments/:commentId/resolve',
  validate(presentationCommentValidations.publicCommentIdSchema),
  presentationCommentController.resolvePublicComment
);

router.post(
  '/:token/comments/:commentId/unresolve',
  validate(presentationCommentValidations.publicCommentIdSchema),
  presentationCommentController.unresolvePublicComment
);

module.exports = router;
