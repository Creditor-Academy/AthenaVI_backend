const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const heygenShareService = require('./heygenShare.service');

const shareAvatar = asyncHandler(async (req, res) => {
  const { workspaceId, groupId } = req.params;
  const result = await heygenShareService.shareAvatarWithWorkspace({
    userId: req.user.id,
    workspaceId,
    groupId,
  });
  return successResponse(req, res, result, 200, messages.HEYGEN_AVATAR_SHARED);
});

const unshareAvatar = asyncHandler(async (req, res) => {
  const { workspaceId, groupId } = req.params;
  const result = await heygenShareService.unshareAvatarFromWorkspace({
    userId: req.user.id,
    workspaceId,
    groupId,
  });
  return successResponse(req, res, result, 200, messages.HEYGEN_AVATAR_UNSHARED);
});

const shareVoice = asyncHandler(async (req, res) => {
  const { workspaceId, voiceId } = req.params;
  const result = await heygenShareService.shareVoiceWithWorkspace({
    userId: req.user.id,
    workspaceId,
    voiceId,
  });
  return successResponse(req, res, result, 200, messages.HEYGEN_VOICE_SHARED);
});

const unshareVoice = asyncHandler(async (req, res) => {
  const { workspaceId, voiceId } = req.params;
  const result = await heygenShareService.unshareVoiceFromWorkspace({
    userId: req.user.id,
    workspaceId,
    voiceId,
  });
  return successResponse(req, res, result, 200, messages.HEYGEN_VOICE_UNSHARED);
});

const listSharedAvatars = asyncHandler(async (req, res) => {
  const result = await heygenShareService.listSharedAvatars(req.params.workspaceId);
  return successResponse(req, res, result, 200, messages.HEYGEN_SHARED_AVATARS_OK);
});

const listSharedVoices = asyncHandler(async (req, res) => {
  const result = await heygenShareService.listSharedVoices(req.params.workspaceId);
  return successResponse(req, res, result, 200, messages.HEYGEN_SHARED_VOICES_OK);
});

module.exports = {
  shareAvatar,
  unshareAvatar,
  shareVoice,
  unshareVoice,
  listSharedAvatars,
  listSharedVoices,
};
