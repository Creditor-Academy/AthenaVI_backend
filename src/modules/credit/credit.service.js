const creditDao = require("./credit.dao");

// Business meaning of "available credits"
const getAvailableCredits = async (userId) => {
  const result = await creditDao.getCreditSumByUserId(userId);

  return result?._sum?.amount ?? 0;
};

const getCreditHistory = async (userId) => {
  return creditDao.getCreditTransactionsByUserId(userId);
};

module.exports = {
  getAvailableCredits,
  getCreditHistory,
};