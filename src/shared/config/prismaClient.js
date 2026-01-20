const { PrismaPg } = require("@prisma/adapter-pg");
const { PrismaClient } = require("@prisma/client");

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, 
  },
});

const prismaClientSingleton = () => {
  return new PrismaClient({ adapter });
};

const globalForPrisma = global;

const prisma =
  globalForPrisma.prismaGlobal ?? prismaClientSingleton();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prismaGlobal = prisma;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

module.exports = prisma;
