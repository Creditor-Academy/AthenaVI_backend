const prisma = require('../../shared/config/prismaClient');
const { OPEN_STATUSES, isTerminalStatus } = require('./earlyAccess.status');

async function findByEmail(email) {
  return prisma.earlyAccessRequest.findUnique({
    where: { email },
  });
}

async function create(data) {
  return prisma.earlyAccessRequest.create({ data });
}

async function listRequests({ page, limit, status }) {
  const skip = (page - 1) * limit;
  const where = status ? { status } : {};

  const [requests, total] = await Promise.all([
    prisma.earlyAccessRequest.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.earlyAccessRequest.count({ where }),
  ]);

  return {
    requests,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 0,
    },
  };
}

async function findById(requestId) {
  return prisma.earlyAccessRequest.findUnique({
    where: { id: requestId },
  });
}

async function countOpen() {
  return prisma.earlyAccessRequest.count({
    where: { status: { in: OPEN_STATUSES } },
  });
}

async function updateStatus({ requestId, status, reviewerId }) {
  const existing = await findById(requestId);
  if (!existing) {
    return null;
  }
  if (isTerminalStatus(existing.status)) {
    return { error: 'terminal', request: existing };
  }
  if (existing.status === status) {
    return { error: 'unchanged', request: existing };
  }

  const data = {
    status,
    reviewerId,
  };
  if (isTerminalStatus(status)) {
    data.reviewedAt = new Date();
  }

  const request = await prisma.earlyAccessRequest.update({
    where: { id: requestId },
    data,
  });

  return { request, previousStatus: existing.status };
}

module.exports = {
  findByEmail,
  create,
  listRequests,
  findById,
  countOpen,
  updateStatus,
};
