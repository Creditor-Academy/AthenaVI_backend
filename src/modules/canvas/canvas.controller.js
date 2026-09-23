const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const canvasService = require('./canvas.service');
const messages = require('../../shared/utils/messages');

const listCanvases = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const { folderId } = req.query;
  const canvases = await canvasService.listCanvases(workspaceId, folderId);

  return successResponse(req, res, { canvases }, 200, messages.CANVASES_FETCHED);
});

const createCanvas = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const userId = req.user.id;
  const { name, folderId, data, thumbnail } = req.body;

  const canvas = await canvasService.createCanvas(workspaceId, userId, {
    name,
    folderId,
    data,
    thumbnail,
  });

  return successResponse(req, res, { canvas }, 201, messages.CANVAS_CREATED);
});

const getCanvas = asyncHandler(async (req, res) => {
  const { workspaceId, canvasId } = req.params;
  const canvas = await canvasService.getCanvasById(workspaceId, canvasId);

  return successResponse(req, res, { canvas }, 200, messages.CANVAS_FETCHED);
});

const updateCanvas = asyncHandler(async (req, res) => {
  const { workspaceId, canvasId } = req.params;
  const userId = req.user.id;
  const canvas = await canvasService.updateCanvasMeta(workspaceId, canvasId, userId, req.body);

  return successResponse(req, res, { canvas }, 200, messages.CANVAS_UPDATED);
});

const saveCanvasData = asyncHandler(async (req, res) => {
  const { workspaceId, canvasId } = req.params;
  const userId = req.user.id;
  const canvas = await canvasService.saveCanvasData(workspaceId, canvasId, userId, req.body.data);

  return successResponse(req, res, { canvas }, 200, messages.CANVAS_DATA_SAVED);
});

const moveCanvasToFolder = asyncHandler(async (req, res) => {
  const { workspaceId, canvasId } = req.params;
  const userId = req.user.id;
  const canvas = await canvasService.moveCanvasToFolder(
    workspaceId,
    canvasId,
    userId,
    req.body.folderId
  );

  return successResponse(req, res, { canvas }, 200, messages.CANVAS_MOVED);
});

const deleteCanvas = asyncHandler(async (req, res) => {
  const { workspaceId, canvasId } = req.params;
  await canvasService.deleteCanvas(workspaceId, canvasId);

  return successResponse(req, res, {}, 200, messages.CANVAS_DELETED);
});

module.exports = {
  listCanvases,
  createCanvas,
  getCanvas,
  updateCanvas,
  saveCanvasData,
  moveCanvasToFolder,
  deleteCanvas,
};
