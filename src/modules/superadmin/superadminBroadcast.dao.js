const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const broadcastSelect = {
  id: true,
  subject: true,
  htmlBody: true,
  textBody: true,
  recipientCount: true,
  sentCount: true,
  failedCount: true,
  createdAt: true,
  sentBy: {
    select: { id: true, email: true, name: true },
  },
};

const createBroadcast = async (data) => {
  return prisma.productEmailBroadcast.create({ data });
};

const updateBroadcastCounts = async (broadcastId, { sentCount, failedCount }) => {
  return prisma.productEmailBroadcast.update({
    where: { id: broadcastId },
    data: { sentCount, failedCount },
  });
};

const createRecipients = async (recipients) => {
  if (!recipients.length) return { count: 0 };
  return prisma.productEmailBroadcastRecipient.createMany({ data: recipients });
};

const listBroadcasts = async ({ page, limit }) => {
  const skip = (page - 1) * limit;
  const [broadcasts, total] = await Promise.all([
    prisma.productEmailBroadcast.findMany({
      select: broadcastSelect,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.productEmailBroadcast.count(),
  ]);

  return {
    broadcasts,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const getBroadcastById = async (broadcastId) => {
  const broadcast = await prisma.productEmailBroadcast.findUnique({
    where: { id: broadcastId },
    select: broadcastSelect,
  });
  if (!broadcast) {
    throw new AppError(messages.PRODUCT_EMAIL_BROADCAST_NOT_FOUND, 404);
  }
  return broadcast;
};

const listBroadcastRecipients = async ({ broadcastId, page, limit, status }) => {
  await getBroadcastById(broadcastId);

  const skip = (page - 1) * limit;
  const where = {
    broadcastId,
    ...(status ? { status } : {}),
  };

  const [recipients, total] = await Promise.all([
    prisma.productEmailBroadcastRecipient.findMany({
      where,
      select: {
        id: true,
        userId: true,
        email: true,
        name: true,
        status: true,
        error: true,
        sentAt: true,
        createdAt: true,
        user: {
          select: { id: true, email: true, name: true },
        },
      },
      orderBy: [{ status: 'asc' }, { email: 'asc' }],
      skip,
      take: limit,
    }),
    prisma.productEmailBroadcastRecipient.count({ where }),
  ]);

  return {
    recipients,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};


const templateSelect = {
  id: true,
  name: true,
  subject: true,
  htmlBody: true,
  textBody: true,
  type: true,
  createdByUserId: true,
  createdAt: true,
  updatedAt: true,
  createdBy: {
    select: { id: true, email: true, name: true },
  },
};

const createEmailTemplate = async (data) => {
  return prisma.emailTemplate.create({
    data,
    select: templateSelect,
  });
};

const getEmailTemplateById = async (id) => {
  const template = await prisma.emailTemplate.findUnique({
    where: { id },
    select: templateSelect,
  });
  if (!template) {
    throw new AppError(messages.EMAIL_TEMPLATE_NOT_FOUND, 404);
  }
  return template;
};

const listEmailTemplates = async ({ page = 1, limit = 50, search, type } = {}) => {
  const skip = (page - 1) * limit;
  const where = {
    ...(type ? { type } : {}),
    ...(search
      ? {
          OR: [
            { name: { contains: search, mode: 'insensitive' } },
            { subject: { contains: search, mode: 'insensitive' } },
          ],
        }
      : {}),
  };

  const [templates, total] = await Promise.all([
    prisma.emailTemplate.findMany({
      where,
      select: templateSelect,
      orderBy: { updatedAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.emailTemplate.count({ where }),
  ]);

  return {
    templates,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
};

const updateEmailTemplate = async (id, data) => {
  await getEmailTemplateById(id);
  return prisma.emailTemplate.update({
    where: { id },
    data,
    select: templateSelect,
  });
};

const deleteEmailTemplate = async (id) => {
  await getEmailTemplateById(id);
  return prisma.emailTemplate.delete({
    where: { id },
  });
};

module.exports = {
  createBroadcast,
  updateBroadcastCounts,
  createRecipients,
  listBroadcasts,
  getBroadcastById,
  listBroadcastRecipients,
  createEmailTemplate,
  getEmailTemplateById,
  listEmailTemplates,
  updateEmailTemplate,
  deleteEmailTemplate,
};
