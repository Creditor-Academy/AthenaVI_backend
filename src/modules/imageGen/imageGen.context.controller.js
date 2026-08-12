const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const contextService = require('./imageGen.context.service');

const createContext = asyncHandler(async (req, res) => {
  const data = await contextService.createContext({
    userId: req.user.id,
    workspace: req.workspace,
    files: req.files || [],
    body: req.body || {},
  });
  return successResponse(req, res, { context: data }, 201, messages.IMAGE_GEN_CONTEXT_CREATED);
});

const getContext = asyncHandler(async (req, res) => {
  const data = await contextService.getContext({
    userId: req.user.id,
    workspace: req.workspace,
    contextId: req.params.contextId,
  });
  return successResponse(req, res, { context: data }, 200, messages.IMAGE_GEN_CONTEXT_FETCHED);
});

const deleteContext = asyncHandler(async (req, res) => {
  await contextService.deleteContext({
    userId: req.user.id,
    workspace: req.workspace,
    contextId: req.params.contextId,
  });
  return successResponse(req, res, { deleted: true }, 200, messages.IMAGE_GEN_CONTEXT_DELETED);
});

module.exports = {
  createContext,
  getContext,
  deleteContext,
};
