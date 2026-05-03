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
  console.log('HeyGen API response:', response.data);
  console.log('HeyGen API response:', response.data.data.video_id);

  const saveHeygenResponse = await heygenDao.saveHeygenResponse({
      workspaceId,
      projectId,
      videoId: response.data?.data?.video_id || '',
      requestHash,
      status: response.data?.status || 'processing',
    });

  console.log('Saving HeyGen response to DB with hash:', requestHash);

    console.log(saveHeygenResponse);
    
  

  
};

module.exports = { generateAvatarVideo };
