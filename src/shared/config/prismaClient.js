const { PrismaPg } = require("@prisma/adapter-pg");
const { PrismaClient } = require("@prisma/client");

/**
 * pg v8+ treats sslmode=require in the URL as verify-full, which breaks Aiven
 * and other managed Postgres with custom CAs. SSL is enforced via adapter options.
 */
function getDatabaseConnectionString() {
  const raw = process.env.DATABASE_URL;
  if (!raw) return raw;

  try {
    const url = new URL(raw);
    url.searchParams.delete("sslmode");
    url.searchParams.delete("sslaccept");
    url.searchParams.delete("sslrootcert");
    return url.toString();
  } catch {
    return raw
      .replace(/([?&])sslmode=[^&]*&?/g, "$1")
      .replace(/([?&])sslaccept=[^&]*&?/g, "$1")
      .replace(/[?&]$/, "");
  }
}

const adapter = new PrismaPg({
  connectionString: getDatabaseConnectionString(),
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
}

module.exports = prisma;
