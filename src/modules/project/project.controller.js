const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const projectService = require('./project.service');
const messages = require('../../shared/utils/messages');

const listProjects = asyncHandler(async (req, res) => {
  const { workspaceId } = req.params;
  const { folderId } = req.query;
  const projects = await projectService.listProjects(workspaceId, folderId);

  return successResponse(req, res, { projects }, 200, messages.PROJECTS_FETCHED);
});

const createProject = asyncHandler(async (req, res) => {
  const workspaceId = req.params.workspaceId;
  const userId = req.user.id;
  const {
    name,
    title,
    folderId,
    projectState,
    data,
    thumbnail,
    duration,
    status,
    aspectRatio,
    canvasSize,
    customWidth,
    customHeight,
    tags,
  } = req.body;

  const project = await projectService.createProject(workspaceId, userId, {
    name: name ?? title,
    folderId,
    editorState: projectState ?? data,
    thumbnail,
    duration,
    status,
    aspectRatio,
    canvasSize,
    customWidth,
    customHeight,
    tags,
  });

  return successResponse(req, res, { project }, 201, messages.PROJECT_CREATED);
});

const getProject = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const project = await projectService.getProjectById(workspaceId, projectId);

  return successResponse(req, res, { project }, 200, messages.PROJECT_FETCHED);
});

const updateProject = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const userId = req.user.id;
  const project = await projectService.updateProject(workspaceId, projectId, userId, req.body);

  return successResponse(req, res, { project }, 200, messages.PROJECT_UPDATED);
});

const saveProjectData = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const userId = req.user.id;
  const project = await projectService.saveProjectData(
    workspaceId,
    projectId,
    userId,
    req.body.data
  );

  return successResponse(req, res, { project }, 200, messages.PROJECT_DATA_SAVED);
});

const moveProjectToFolder = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const userId = req.user.id;
  const project = await projectService.moveProjectToFolder(
    workspaceId,
    projectId,
    userId,
    req.body.folderId
  );

  return successResponse(req, res, { project }, 200, messages.PROJECT_MOVED);
});

const deleteProject = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  await projectService.deleteProject(workspaceId, projectId);

  return successResponse(req, res, {}, 200, messages.PROJECT_DELETED);
});

module.exports = {
  listProjects,
  createProject,
  getProject,
  updateProject,
  saveProjectData,
  moveProjectToFolder,
  deleteProject,
};
