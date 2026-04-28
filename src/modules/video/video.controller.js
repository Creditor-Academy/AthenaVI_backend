const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const videoService = require('./services/video.service');
const axios = require('axios');
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
  } = req.body;
  console.log('Received request to generate video with data:', {
    avatarId,
    title,
    voiceId,
    script,
  });

  const heygenResponse = await heygenService.generateAvatarVideo(
    avatarId,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    expressiveness
  );

  console.log('HeyGen API response :', heygenResponse);

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
