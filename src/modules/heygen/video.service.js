import * as videoDao from "./video.dao.js";
import { renderScene } from "../../services/remotion.service.js";
import { uploadToS3 } from "../../services/s3.service.js";
import { generateHeygenVideo } from "../../services/heygen.service.js";

export async function createJob({ userId, scenes }) {
  const job = await videoDao.createJob({
    userId,
    status: "PROCESSING",
  });

  processVideo(job.id, scenes).catch(console.error);

  return job;
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

        const backgroundUrl = await uploadToS3(videoPath);

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

  } catch (err) {
    console.error(err);

    await videoDao.updateJob(jobId, {
      status: "FAILED",
    });
  }
}

export async function getStatus(jobId) {
  const job = await videoDao.getJob(jobId);

  if (!job) {
    throw new Error("Job not found");
  }

  return job;
}