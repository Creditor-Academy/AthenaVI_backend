const axios = require('axios');
const { Prisma } = require('@prisma/client');
const heygenDao = require('../heygen.dao');
const { generateHeygenRequestHash } = require('../../../shared/utils/requestHash')

const generateAvatarVideo = async ({
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
}) => {
  const requestHash = generateHeygenRequestHash({
    workspaceId,
    projectId,
    avatarId,
    voiceId,
    script,
  });

  const existingResponse = await heygenDao.findHeygenResponseByRequestHash(requestHash);
  if (existingResponse) {
    return existingResponse;
  }

  const response = await axios.post(
    `${process.env.HEYGEN_BASE_URL}/v3/videos`,
    {
      type: 'avatar',
      avatar_id: avatarId,
      title: title,
      resolution: resolution,
      aspect_ratio: aspectRatio,
      background: {
        type: 'color',
        value: backgroundColor,
      },
      remove_background: false,
      output_format: 'mp4',
      script: script,
      voice_id: voiceId,
      voice_settings: {
        speed: 1,
        pitch: 0,
        volume: 1,
        locale: '<string>',
        engine_settings: {
          engine_type: 'elevenlabs',
          model: 'eleven_multilingual_v2',
          similarity_boost: 0.5,
          stability: 0.5,
          style: 0.5,
          use_speaker_boost: true,
        },
      },
      expressiveness: expressiveness,
    },
    {
      headers: {
        'x-api-key': `${process.env.HEYGEN_API_KEY}`,
        'Content-Type': 'application/json',
      },
    }
  );

  const payload = response.data;
  const videoId =
    payload?.id ||
    payload?.video?.id ||
    payload?.videoId ||
    payload?.video_id;
  const videoUrl =
    payload?.url ||
    payload?.video?.url ||
    payload?.videoUrl ||
    payload?.video_url ||
    payload?.output?.url ||
    '';

  try {
    return await heygenDao.saveHeygenResponse({
      workspaceId,
      projectId,
      videoId,
      videoUrl,
      requestHash,
      status: payload?.status || 'processing',
    });
  } catch (error) {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === 'P2002'
    ) {
      const duplicateResponse = await heygenDao.findHeygenResponseByRequestHash(requestHash);
      if (duplicateResponse) {
        return duplicateResponse;
      }
    }
    throw error;
  }
};

module.exports = { generateAvatarVideo };
