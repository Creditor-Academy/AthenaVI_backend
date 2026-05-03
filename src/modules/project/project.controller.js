const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const projectService = require('./project.service');
const messages = require('../../shared/utils/messages');

const createProject = asyncHandler(async (req, res) => {
  const workspaceId = req.params.workspaceId;
  const userId = req.user.id;
  const { name, folderId, projectState, data, thumbnail, duration, status } = req.body;
  const editorState = projectState ?? data ?? {};

  const project = await projectService.createProject(
    workspaceId,
    userId,
    name,
    folderId,
    editorState,
    thumbnail,
    duration,
    status
  );

  return successResponse(req, res, { project }, 201, messages.PROJECT_CREATED);
});

module.exports = {
  createProject,
};
