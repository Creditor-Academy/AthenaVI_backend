const express = require('express');
const router = express.Router();
const inboxController = require('./inbox.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const inboxValidation = require('../validations/inbox.validations');

router.get(
  '/',
  authMiddleware,
  validate(inboxValidation.listInboxSchema),
  inboxController.listInbox
);

router.get('/unread-count', authMiddleware, inboxController.getUnreadCount);

router.patch(
  '/read',
  authMiddleware,
  validate(inboxValidation.bulkReadSchema),
  inboxController.markNotificationsRead
);

router.patch(
  '/read-all',
  authMiddleware,
  inboxController.markAllNotificationsRead
);

router.get(
  '/:notificationId',
  authMiddleware,
  validate(inboxValidation.notificationIdSchema),
  inboxController.getNotification
);

router.patch(
  '/:notificationId/read',
  authMiddleware,
  validate(inboxValidation.notificationIdSchema),
  inboxController.markNotificationRead
);

router.delete(
  '/:notificationId',
  authMiddleware,
  validate(inboxValidation.notificationIdSchema),
  inboxController.dismissNotification
);

module.exports = router;
