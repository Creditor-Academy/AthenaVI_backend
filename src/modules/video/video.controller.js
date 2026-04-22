const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const videoService = require('./services/video.service');

const generateVideo = async (req, res) => {
  try {
    const { project } = req.body;

    // ✅ Basic validation
    if (!project || !project.timeline) {
      return res.status(400).json({
        error: "Invalid project data. 'project.timeline' is required."
      });
    }

    const timeline = project.timeline;

    // 👉 call service (we'll build next)
    const result = await videoService.generateVideo(timeline);

    return res.json({
      success: true,
      videoUrl: result.videoUrl
    });

  } catch (error) {
    console.error("Error generating video:", error);

    return res.status(500).json({
      error: error.message || "Something went wrong"
    });
  }
};

module.exports = {
  generateVideo,
};
