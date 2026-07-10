const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const settingsService = require('./settings.service');
const securityService = require('./security.service');

function clearRefreshCookie(res) {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/',
  });
}

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

const getSecurity = asyncHandler(async (req, res) => {
  const security = await securityService.getSecuritySettings(req.user.id);

  return successResponse(
    req,
    res,
    { security },
    200,
    messages.SETTINGS_SECURITY_FETCHED
  );
});

const updateSecurity = asyncHandler(async (req, res) => {
  const security = await securityService.updateSecuritySettings(req.user.id, req.body);

  return successResponse(
    req,
    res,
    { security },
    200,
    messages.SETTINGS_SECURITY_UPDATED
  );
});

const changePassword = asyncHandler(async (req, res) => {
  await securityService.changePassword(req.user.id, req.body);

  return successResponse(
    req,
    res,
    { passwordChanged: true },
    200,
    messages.PASSWORD_CHANGED_SUCCESSFULLY
  );
});

const deleteAccount = asyncHandler(async (req, res) => {
  const { accountDeletion } = await securityService.requestAccountDeletion(
    req.user.id,
    req.body
  );

  clearRefreshCookie(res);

  return successResponse(
    req,
    res,
    { accountDeletion },
    200,
    messages.ACCOUNT_DELETION_SCHEDULED
  );
});

module.exports = {
  getAppearance,
  updateAppearance,
  getNotifications,
  updateNotifications,
  getSecurity,
  updateSecurity,
  changePassword,
  deleteAccount,
};
