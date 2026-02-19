const prisma = require('../../shared/config/prismaClient');

const findById = async (id) => {
  return await prisma.refreshToken.findUnique({
    where: { id },
  });
};

const findByUserId = async (userId) => {
  return await prisma.refreshToken.findMany({
    where: {
      userId,
      isRevoked: false,
    },
  });
};

const revoke = async (id) => {
  return prisma.refreshToken.update({
    where: { id },
    data: {
      isRevoked: true,
    },
  });
};

const revokeBySession = async (sessionId) => {
  return prisma.refreshToken.updateMany({
    where: { sessionId },
    data: { isRevoked: true },
  });
};

const revokeAllByUserId = (userId) => {
  return prisma.refreshToken.updateMany({
    where: { userId },
    data: { isRevoked: true },
  });
};

const create = async ({ id, userId, sessionId, token }) => {
  console.log(`token: ${token}, sessionID: ${sessionId}, userID: ${userId}`);

  return await prisma.refreshToken.create({
    data: {
      id: id,
      hashedToken: token,
      sessionId,
      userId,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });
};

module.exports = {
  findById,
  revoke,
  revokeBySession,
  create,
  findByUserId,
  revokeAllByUserId,
};
