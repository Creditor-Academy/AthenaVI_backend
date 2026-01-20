const prisma = require("../../shared/config/prismaClient");

const getAllUsers = async () => {
  return prisma.user.findMany();
};

module.exports = {
  getAllUsers,
};