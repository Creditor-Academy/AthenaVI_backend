const prisma = require('../../shared/config/prismaClient');

// Raw aggregate query
const findWorkspaceMember = async (userId) => {
  return prisma.workspaceMember.findFirst({
    where: { userId },
    include: {
      workspace: true,
    },
  });
};

// Raw history query
const getCreditTransactionsByUserId = async (workspaceId) => {
  return prisma.creditTransaction.findMany({
    where: { workspaceId },
    orderBy: {
      createdAt: 'desc',
    },
  });
};

module.exports = {
  findWorkspaceMember,
  getCreditTransactionsByUserId,
};
