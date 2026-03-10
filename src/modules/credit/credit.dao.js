const prisma = require('../../shared/config/prismaClient');
const messages = require('../../shared/utils/messages');

// Raw aggregate query
 const getWorkspaceCredits = async (workspaceId) => {
  return await prisma.workspace.findUnique({
    where: { id: workspaceId },
    select: {
      credits: true,
    },
  });

};
const getWorkspaceCreditHistory = async (workspaceId, page, limit) => {
  const skip = (page - 1) * limit;
  

  const [transactions, total] = await Promise.all([
    prisma.creditTransaction.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
      skip,
      take: limit,
    }),
    prisma.creditTransaction.count({
      where: { workspaceId },
    }),
  ]);

  return {
    transactions,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    },
  };
};


const getUserCreditHistory = async (workspaceId, userId, page, limit) => {
  const skip = (page - 1) * limit;

  const [transactions, total] = await Promise.all([
    prisma.creditTransaction.findMany({
      where: {
        workspaceId,
        userId,
      },
      orderBy: { createdAt: "desc" },
      skip,
      take: limit,
    }),
    prisma.creditTransaction.count({
      where: {
        workspaceId,
        userId,
      },
    }),
  ]);

  return {
    transactions,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    },
  };
};

module.exports = {
  getWorkspaceCredits,
  getUserCreditHistory,
  getWorkspaceCreditHistory
};
