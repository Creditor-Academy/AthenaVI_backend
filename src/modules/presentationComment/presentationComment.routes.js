const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const commentValidation = require('./presentationComment.validation');
const commentController = require('./presentationComment.controller');

/**
 * Editor-side comments. Mounted under `/:presentationId/comments` from presentation.routes.js,
 * which already sits behind authMiddleware + requireWorkspaceRole, so every caller here is a
 * workspace member. Comments keep working regardless of the share link's state.
 */
const router = express.Router({ mergeParams: true });

// Ahead of `/:commentId` so the literal path is not swallowed by the id param.
router.get(
  '/mentionable-users',
  validate(commentValidation.mentionableUsersSchema),
  commentController.getMentionableUsers
);

router.get('/', validate(commentValidation.listCommentsSchema), commentController.listComments);

router.post('/', validate(commentValidation.createCommentSchema), commentController.createComment);

router.patch(
  '/:commentId',
  validate(commentValidation.updateCommentSchema),
  commentController.updateComment
);

router.delete(
  '/:commentId',
  validate(commentValidation.commentIdSchema),
  commentController.deleteComment
);

router.post(
  '/:commentId/resolve',
  validate(commentValidation.commentIdSchema),
  commentController.resolveComment
);

router.post(
  '/:commentId/unresolve',
  validate(commentValidation.commentIdSchema),
  commentController.unresolveComment
);

module.exports = router;
