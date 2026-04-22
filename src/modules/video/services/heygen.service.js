const axios = require("axios");

const API_KEY = process.env.HEYGEN_API_KEY;

// helper sleep
const wait = (ms) => new Promise((res) => setTimeout(res, ms));

async function generateAvatarVideo(task) {
  // 1️⃣ Create video
  const createRes = await axios.post(
    "https://api.heygen.com/v2/video/generate",
    {
      video_inputs: [
        {
          character: {
            type: "avatar",
            avatar_id: task.avatarId
          },
          voice: {
            type: "text",
            input_text: task.script
          }
        }
      ]
    },
    {
      headers: {
        Authorization: `Bearer ${API_KEY}`
      }
    }
  );

  const videoId = createRes.data.video_id;

  if (!videoId) {
    throw new Error("Failed to create HeyGen video");
  }

  // 2️⃣ Poll status
  let status = "processing";
  let videoUrl = null;
  let attempts = 0;

  while (status === "processing" && attempts < 20) {
    await wait(3000);
    attempts++;

    const statusRes = await axios.get(
      `https://api.heygen.com/v2/video/status?video_id=${videoId}`,
      {
        headers: {
          Authorization: `Bearer ${API_KEY}`
        }
      }
    );

    status = statusRes.data.status;

    console.log(`⏳ Avatar ${videoId} status:`, status);

    if (status === "completed") {
      videoUrl = statusRes.data.video_url;
    }

    if (status === "failed") {
      throw new Error(`Avatar generation failed for ${videoId}`);
    }
  }

  if (!videoUrl) {
    throw new Error("Timeout: Avatar generation took too long");
  }

  return {
    sceneIndex: task.sceneIndex,
    elementIndex: task.elementIndex,
    url: videoUrl
  };
}

module.exports = { generateAvatarVideo };