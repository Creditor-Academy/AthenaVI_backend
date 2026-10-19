const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const videoTemplateService = require('./videoTemplate.service');
const projectService = require('./project.service');

const listVideoTemplates = asyncHandler(async (req, res) => {
  const { contentType, type } = req.query || {};
  const templates = await videoTemplateService.listActiveVideoTemplates({ contentType, type });
  return successResponse(req, res, { templates }, 200, messages.VIDEO_TEMPLATES_FETCHED);
});

const getVideoTemplate = asyncHandler(async (req, res) => {
  const template = await videoTemplateService.getActiveVideoTemplate(req.params.templateId);
  return successResponse(req, res, { template }, 200, messages.VIDEO_TEMPLATES_FETCHED);
});

const appendSceneFromTemplate = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const userId = req.user.id;
  const { templateId } = req.body;

  const project = await projectService.appendSceneFromVideoTemplate(
    workspaceId,
    projectId,
    userId,
    templateId
  );

  return successResponse(req, res, { project }, 200, messages.VIDEO_SCENE_FROM_TEMPLATE);
});

module.exports = {
  listVideoTemplates,
  getVideoTemplate,
  appendSceneFromTemplate,
};
