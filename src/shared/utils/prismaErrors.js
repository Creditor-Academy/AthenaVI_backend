const { Prisma } = require('@prisma/client');

function isPrismaUniqueConstraintError(err) {
  return (
    err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002'
  );
}

module.exports = { isPrismaUniqueConstraintError };
