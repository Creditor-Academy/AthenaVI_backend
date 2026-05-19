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

module.exports = {
  getAppearance,
  updateAppearance,
};
