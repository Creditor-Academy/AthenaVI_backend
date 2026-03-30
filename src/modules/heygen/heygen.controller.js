const asyncHandler = require("../../shared/utils/asyncHandler");
const { successResponse } = require("../../shared/utils/apiResponse");
const heygenService = require("./heygen.service");
const messages = require("../../shared/utils/messages");

// // POST /api/heygen/generate
// const generateVideo = asyncHandler(async (req, res) =>{

//     const { scenes } = req.body;
//     const userId = req.user?.id ;

//     if (!scenes || !scenes.length) {
//       return res.status(400).json({
//         success: false,
//         message: "Scenes are required",
//       });
//     }

//     const job = await videoService.createJob({ userId, scenes });

//     res.json({
//       success: true,
//       jobId: job.id,
//       job 
//     });
    
// })

//  async function getVideoStatus(req, res) {
//   try {
//     const { jobId } = req.params;

//     const status = await videoService.getStatus(jobId);

//     res.json(status);
//   } catch (err) {
//     res.status(500).json({
//       success: false,
//       message: "Failed to fetch status",
//     });
//   }
// }


const getVoiceList = asyncHandler(async (req, res) => {
  const voices = await heygenService.getVoiceList();
  successResponse(req,res, { voices }, 200 , messages.VOICE_LIST_FETCHED);
});


module.exports = {
    // generateVideo,
    // getVideoStatus,
    getVoiceList
}
