const express = require('express');
const validate = require('../../middlewares/validate.middleware');
const commentValidation = require('./comment.validation');
const commentController = require('./comment.controller');

const router = express.Router({ mergeParams: true });

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

module.exports = router;
