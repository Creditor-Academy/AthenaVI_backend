const axios = require("axios");

async function generateHeygenVideo(scenes) {
  const videoInputs = scenes.map((scene) => ({
    character: {
      type: "avatar",
      avatar_id: scene.avatarId,
    },
    voice: {
      type: "text",
      input_text: scene.script,
      voice_id: scene.voiceId,
    },
    background: {
      type: "video",
      url: scene.backgroundUrl,
    },
  }));

  console.log(videoInputs);
  

  // const res = await axios.post(
  //   "https://api.heygen.com/v2/video/generate",
  //   {
  //     video_inputs: videoInputs,
  //     dimension: { width: 1280, height: 720 },
  //   },
  //   {
  //     headers: {
  //       "X-Api-Key": process.env.HEYGEN_API_KEY,
  //     },
  //   }
  // );

  const res = {
    data: {
      data: { video_id: "demo-video-id" },
    },
  };

  return res.data.data.video_id;
}

module.exports = {
  generateHeygenVideo,
};