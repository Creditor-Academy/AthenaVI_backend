const prisma = require("../shared/config/prismaClient");
const AppError = require("../shared/utils/AppError");
const asyncHandler = require("../shared/utils/asyncHandler");
const messages = require("../shared/utils/messages");


const checkWorkspaceAccess = asyncHandler( async (req, res, next) => {
  const userId = req.user.id;
  const {workspaceId} = req.params;

   const workspace = await prisma.workspace.findUnique({
      where: { id: workspaceId },
      include: { members: true }
    });

    if (!workspace) {
        throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
    }

    if(workspace.type === 'PRIVATE') {
        if(workspace.ownerId !== userId) {
            throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
        }
    }else{
        const isMember = workspace.members.some(
        (m) => m.userId === userId
      );
      if (!isMember) {
        throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
      }
    }

    req.workspace = workspace;
    next();
}
);

module.exports = {
    checkWorkspaceAccess
}