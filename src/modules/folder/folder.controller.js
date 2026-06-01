const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const folderService = require('./folder.service');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const getFolders = asyncHandler(async (req, res) => {
  const workspaceId = req.params.workspaceId;
  const userId = req.user.id;

  const folders = await folderService.listFolders(workspaceId, userId);

  return successResponse(req, res, { folders }, 200, messages.FOLDERS_FETCHED_SUCCESSFULLY);
});

const createFolder = asyncHandler(async (req, res) => {
  const workspaceId = req.params.workspaceId;
  const name  = req.body.name;
  const userId = req.user.id;

  const folder = await folderService.createFolder(workspaceId, userId, name);

  return successResponse(req, res, { folder }, 201, messages.FOLDER_CREATED);
});

const renameFolder = asyncHandler(async (req, res) => {
  const folderId = req.params.folderId;
  const { name } = req.body;
  const userId = req.user.id;

  const folder = await folderService.renameFolder(folderId, userId, name);

  return successResponse(req, res, { folder }, 200, messages.FOLDER_RENAMED);
});

const deleteFolder = asyncHandler(async (req, res) => {
  const folderId = req.params.folderId;

  const folder = await folderService.deleteFolder(folderId);

  return successResponse(req, res, { folder }, 200, messages.FOLDER_DELETED);
});

module.exports = {
  getFolders,
  createFolder,
  renameFolder,
  deleteFolder,
};
