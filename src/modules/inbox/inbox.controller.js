const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const inboxService = require('./inbox.service');

const listInbox = asyncHandler(async (req, res) => {
  const unreadOnly = req.query.unreadOnly === 'true';
  const limit = req.query.limit ? Number(req.query.limit) : 50;

  const result = await inboxService.listInbox(req.user.id, {
    unreadOnly,
    limit,
    type: req.query.type,
    category: req.query.category,
    workspaceId: req.query.workspaceId,
  });

  return successResponse(
    req,
    res,
    result,
    200,
    messages.INBOX_FETCHED
  );
});

const getUnreadCount = asyncHandler(async (req, res) => {
  const result = await inboxService.getUnreadCount(req.user.id);

  return successResponse(
    req,
    res,
    result,
    200,
    messages.INBOX_UNREAD_COUNT_FETCHED
  );
});

const getNotification = asyncHandler(async (req, res) => {
  const notification = await inboxService.getNotification(
    req.user.id,
    req.params.notificationId
  );

  return successResponse(
    req,
    res,
    { notification },
    200,
    messages.INBOX_FETCHED
  );
});

const markNotificationRead = asyncHandler(async (req, res) => {
  const notification = await inboxService.markNotificationRead(
    req.user.id,
    req.params.notificationId
  );

  return successResponse(
    req,
    res,
    { notification },
    200,
    messages.INBOX_NOTIFICATION_MARKED_READ
  );
});

const markNotificationsRead = asyncHandler(async (req, res) => {
  const result = await inboxService.markNotificationsRead(
    req.user.id,
    req.body.notificationIds
  );

  return successResponse(
    req,
    res,
    result,
    200,
    messages.INBOX_NOTIFICATION_MARKED_READ
  );
});

const markAllNotificationsRead = asyncHandler(async (req, res) => {
  const result = await inboxService.markAllNotificationsRead(req.user.id);

  return successResponse(
    req,
    res,
    result,
    200,
    messages.INBOX_ALL_MARKED_READ
  );
});

const dismissNotification = asyncHandler(async (req, res) => {
  const result = await inboxService.dismissNotification(
    req.user.id,
    req.params.notificationId
  );

  return successResponse(
    req,
    res,
    result,
    200,
    messages.INBOX_NOTIFICATION_DISMISSED
  );
});

module.exports = {
  listInbox,
  getUnreadCount,
  getNotification,
  markNotificationRead,
  markNotificationsRead,
  markAllNotificationsRead,
  dismissNotification,
};
