const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const workspaceLibraryService = require('./workspaceLibrary.service');

const getLibrary = asyncHandler(async (req, res) => {
  const data = await workspaceLibraryService.getLibrary({
    userId: req.user.id,
    workspace: req.workspace,
    query: req.query,
  });
  return successResponse(req, res, data, 200, messages.WORKSPACE_LIBRARY_FETCHED);
});

module.exports = {
  getLibrary,
};
