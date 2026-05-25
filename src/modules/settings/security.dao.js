const prisma = require('../../shared/config/prismaClient');

const findSecurityByUserId = async (userId) => {
  return prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      password: true,
      deletionRequestedAt: true,
      deletionScheduledAt: true,
    },
  });
};

const scheduleAccountDeletion = async (userId, { requestedAt, scheduledAt }) => {
  return prisma.user.update({
    where: { id: userId },
    data: {
      deletionRequestedAt: requestedAt,
      deletionScheduledAt: scheduledAt,
    },
    select: {
      deletionRequestedAt: true,
      deletionScheduledAt: true,
    },
  });
};

const clearAccountDeletion = async (userId) => {
  return prisma.user.update({
    where: { id: userId },
    data: {
      deletionRequestedAt: null,
      deletionScheduledAt: null,
    },
  });
};

const findUsersDueForPermanentDeletion = async () => {
  return prisma.user.findMany({
    where: {
      deletionScheduledAt: {
        lte: new Date(),
      },
    },
    select: { id: true },
  });
};

module.exports = {
  findSecurityByUserId,
  scheduleAccountDeletion,
  clearAccountDeletion,
  findUsersDueForPermanentDeletion,
};
