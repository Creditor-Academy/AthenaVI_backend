const axios = require('axios');
const heygenDao = require('../heygen.dao');

const API_KEY = process.env.HEYGEN_API_KEY;

// helper sleep
const wait = (ms) => new Promise((res) => setTimeout(res, ms));

const generateAvatarVideo = async (
  avatarId,
  title,
  resolution,
  aspectRatio,
  backgroundColor,
  voiceId,
  script,
  expressiveness
) => {
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
  console.log(response.data);

  const heygenResponse = await heygenDao.saveHeygenResponse({
    avatarId,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    expressiveness,
    heygenResponse: response.data,
  });

  return response.data;
};

module.exports = { generateAvatarVideo };
