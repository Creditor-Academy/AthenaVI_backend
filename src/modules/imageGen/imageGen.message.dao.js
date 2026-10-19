const prisma = require('../../shared/config/prismaClient');

function createMessage(data) {
  return prisma.imageGenMessage.create({ data });
}

function createMessages(messages) {
  return prisma.imageGenMessage.createMany({ data: messages });
}

function listUserMessages(threadId, { take = 12 } = {}) {
  return prisma.imageGenMessage.findMany({
    where: { threadId, role: 'user' },
    orderBy: { createdAt: 'desc' },
    take: Math.min(Math.max(Number(take) || 12, 1), 50),
    select: {
      id: true,
      content: true,
      type: true,
      createdAt: true,
    },
  });
}

module.exports = {
  createMessage,
  createMessages,
  listUserMessages,
};
