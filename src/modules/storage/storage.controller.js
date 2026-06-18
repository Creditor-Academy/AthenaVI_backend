const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const storageService = require('./storage.service');

const getMyStorage = asyncHandler(async (req, res) => {
  const summary = await storageService.getUserStorageSummary(req.user.id);
  return successResponse(req, res, summary, 200, messages.STORAGE_FETCHED);
});

const getMyStorageHistory = asyncHandler(async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const limit = parseInt(req.query.limit, 10) || 20;
  const history = await storageService.getUserStorageHistory(req.user.id, page, limit, req.query.type);
  return successResponse(req, res, { history }, 200, messages.STORAGE_HISTORY_FETCHED);
});

const getWorkspaceStorage = asyncHandler(async (req, res) => {
  const summary = await storageService.getWorkspaceStorageSummary(req.params.workspaceId);
  return successResponse(req, res, summary, 200, messages.STORAGE_FETCHED);
});

module.exports = {
  getMyStorage,
  getMyStorageHistory,
  getWorkspaceStorage,
};
