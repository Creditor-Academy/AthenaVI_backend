const prisma = require("../../shared/config/prismaClient");

// Raw aggregate query
const getCreditSumByUserId = async (userId) => {
  return prisma.creditTransaction.aggregate({
    where: { userId },
    _sum: { amount: true },
  });
};

// Raw history query
const getCreditTransactionsByUserId = async (userId) => {
  return prisma.creditTransaction.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
  });
};

module.exports = {
  getCreditSumByUserId,
  getCreditTransactionsByUserId,
};