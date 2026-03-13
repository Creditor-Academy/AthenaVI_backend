const prisma = require('../../shared/config/prismaClient');

const getAllUsers = async () => {
  return prisma.user.findMany();
};

const getUserById = async (userId) => {
  return prisma.user.findUnique({
    where: { id: userId },
    select: {
      email: true,
      name: true,
      profileImage: true,
      phoneNumber: true,
      createdAt: true,
    },
  });
};

const updateUserById = async (userId, updateData) => {
  return prisma.user.update({
    where: { id: userId },
    data: updateData,
    select: {
      email: true,
      name: true,
      phoneNumber: true,
      createdAt: true,
    },
  });
};

module.exports = {
  getAllUsers,
  getUserById,
  updateUserById,
};
