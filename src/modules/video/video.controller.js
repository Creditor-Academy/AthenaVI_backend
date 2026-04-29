const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const heygenService = require('./services/heygen.service');
const messages = require('../../shared/utils/messages');

const generateAvatarVideo = asyncHandler(async (req, res) => {
  const {
    avatarId,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    expressiveness,
    workspaceId,
    projectId,
  } = req.body;

  const heygenResponse = await heygenService.generateAvatarVideo({
    avatarId,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    expressiveness,
    workspaceId,
    projectId,
  });

  return successResponse(
    req,
    res,
    heygenResponse,
    200,
    messages.VIDEO_GENERATION_SUCCESS
  );
});

module.exports = {
  generateAvatarVideo,
};
