const prisma = require('../../shared/config/prismaClient');

async function findByEmail(email) {
  return prisma.earlyAccessRequest.findUnique({
    where: { email },
  });
}

async function create(data) {
  return prisma.earlyAccessRequest.create({ data });
}

module.exports = {
  findByEmail,
  create,
};
