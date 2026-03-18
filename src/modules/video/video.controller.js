const videoService = require("./video.service");

async function generateVideo(req, res) {
  try {
    const { scenes } = req.body;
    console.log(scenes);
    
    const userId = req.user?.id || "demo-user";

    if (!scenes || !scenes.length) {
      return res.status(400).json({
        success: false,
        message: "Scenes are required",
      });
    }

    const job = await videoService.createJob({ userId, scenes });

    res.json({
      success: true,
      jobId: job.id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: "Failed to generate video",
    });
  }
}
async function getVideoStatus(req, res) {
  try {
    const { jobId } = req.params;

    const status = await videoService.getStatus(jobId);

    res.json(status);
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch status",
    });
  }
}

module.exports = {
  generateVideo,
  getVideoStatus
};