const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const templatePublishService = require('./templatePublish.service');

const publishPresentationAsPack = asyncHandler(async (req, res) => {
  const template = await templatePublishService.publishPresentationAsPack({
    presentationId: req.params.presentationId,
    userId: req.user.id,
    name: req.body.name,
    packId: req.body.packId,
    themeId: req.body.themeId,
    isActive: req.body.isActive,
    variant: req.body.variant,
    contentType: req.body.contentType,
    description: req.body.description,
  });
  return successResponse(req, res, { template }, 201, messages.TEMPLATE_PUBLISHED_AS_PACK);
});

const publishProjectSceneAsTemplate = asyncHandler(async (req, res) => {
  const template = await templatePublishService.publishProjectSceneAsTemplate({
    projectId: req.params.projectId,
    sceneId: req.params.sceneId,
    userId: req.user.id,
    name: req.body.name,
    contentType: req.body.contentType,
    variant: req.body.variant,
    isActive: req.body.isActive,
  });
  return successResponse(req, res, { template }, 201, messages.TEMPLATE_PUBLISHED_AS_VIDEO_SCENE);
});

const publishProjectAsVideoPack = asyncHandler(async (req, res) => {
  const template = await templatePublishService.publishProjectAsVideoPack({
    projectId: req.params.projectId,
    userId: req.user.id,
    name: req.body.name,
    packId: req.body.packId,
    isActive: req.body.isActive,
    variant: req.body.variant,
    contentType: req.body.contentType,
    description: req.body.description,
  });
  return successResponse(req, res, { template }, 201, messages.TEMPLATE_PUBLISHED_AS_VIDEO_PACK);
});

module.exports = {
  publishPresentationAsPack,
  publishProjectSceneAsTemplate,
  publishProjectAsVideoPack,
};
