const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const settingsService = require('./settings.service');

const getAppearance = asyncHandler(async (req, res) => {
  const appearance = await settingsService.getAppearance(req.user.id);

  return successResponse(
    req,
    res,
    { appearance },
    200,
    messages.SETTINGS_APPEARANCE_FETCHED
  );
});

const updateAppearance = asyncHandler(async (req, res) => {
  const appearance = await settingsService.updateAppearance(req.user.id, req.body);

  return successResponse(
    req,
    res,
    { appearance },
    200,
    messages.SETTINGS_APPEARANCE_UPDATED
  );
});

const getNotifications = asyncHandler(async (req, res) => {
  const notifications = await settingsService.getNotifications(req.user.id);

  return successResponse(
    req,
    res,
    { notifications },
    200,
    messages.SETTINGS_NOTIFICATIONS_FETCHED
  );
});

const updateNotifications = asyncHandler(async (req, res) => {
  const notifications = await settingsService.updateNotifications(req.user.id, req.body);

  return successResponse(
    req,
    res,
    { notifications },
    200,
    messages.SETTINGS_NOTIFICATIONS_UPDATED
  );
});

module.exports = {
  getAppearance,
  updateAppearance,
  getNotifications,
  updateNotifications,
};
