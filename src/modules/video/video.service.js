const renderScene = require("./remotion.service.js").renderScene;
const generateHeygenVideo = require("./heygen.service.js")
const videoDao = require("./video.dao.js")



 async function createJob({ userId, scenes }) {
  const job = await videoDao.createJob({
    userId,
    status: "PROCESSING",
  });

  const videoProcessor = processVideo(job.id, scenes).catch(console.error);

  return videoProcessor;
}

async function processVideo(jobId, scenes) {
  try {
    const processedScenes = await Promise.all(
      scenes.map(async (scene) => {
        if (!scene.duration) {
          throw new Error("Duration required");
        }

        const videoPath = await renderScene({
          text: scene.script,
          duration: scene.duration,
        });

        const backgroundUrl = `video url from s3${videoPath}`; // Placeholder for actual S3 URL after upload
        // await uploadToS3(videoPath);

        return {
          ...scene,
          backgroundUrl,
        };
      })
    );

    const videoId = await generateHeygenVideo(processedScenes);

    await videoDao.updateJob(jobId, {
      heygenVideoId: videoId,
      status: "RENDERING_AVATAR",
    });

    return videoId

  } catch (err) {
    console.error(err);

    await videoDao.updateJob(jobId, {
      status: "FAILED",
    });
  }
}

 async function getStatus(jobId) {
  const job = await videoDao.getJob(jobId);

  if (!job) {
    throw new Error("Job not found");
  }

  return job;
}

module.exports = {
    createJob,
    getStatus
}