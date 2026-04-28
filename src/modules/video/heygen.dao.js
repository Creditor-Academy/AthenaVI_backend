const prisma = require("../../shared/config/prismaClient");

const saveHeygenResponse = async ({
  workspaceId,
  projectId,
  videoId,
  videoUrl,
  status,
  heygenResponse,
}) => {
  if (!workspaceId || !projectId) {
    throw new Error("workspaceId and projectId are required to save Heygen response");
  }

  const resolvedVideoId =
    videoId ||
    heygenResponse?.id ||
    heygenResponse?.video?.id ||
    heygenResponse?.videoId ||
    heygenResponse?.video_id;

  const resolvedVideoUrl =
    videoUrl ||
    heygenResponse?.url ||
    heygenResponse?.video?.url ||
    heygenResponse?.videoUrl ||
    heygenResponse?.video_url ||
    heygenResponse?.output?.url ||
    "";

  if (!resolvedVideoId) {
    throw new Error("Unable to derive videoId from Heygen response");
  }

  return await prisma.heygenResponse.create({
    data: {
      workspaceId,
      projectId,
      videoId: resolvedVideoId,
      videoUrl: resolvedVideoUrl,
      status: status || heygenResponse?.status || "processing",
    },
  });
};

module.exports = { saveHeygenResponse };
