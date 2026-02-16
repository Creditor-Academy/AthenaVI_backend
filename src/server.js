const dotenv = require('dotenv');

const envFile =
  process.env.NODE_ENV === 'production'
    ? '.env.production'
    : '.env.development';
dotenv.config({ path: envFile });

const app = require('./app');
const prisma = require("./shared/config/prismaClient");
const logger = require('./shared/utils/logger');

const PORT = process.env.PORT || 9000;

async function connectDatabase() {
  await prisma.$connect();
  await prisma.$queryRaw`SELECT 1`;
  console.log('Database connected and verified');
}

async function initialize() {
  try {
    await connectDatabase();
  } catch (error) {
    console.error(' Startup failed');
    console.error(error);
    process.exit(1);
  }
}
initialize();

const server = app.listen(PORT, () => {
  logger.info(`Server running bHYon port ${PORT}`);
  console.log(`Server running on port ${PORT}`);
});

const shutdown = async (signal) => {
  console.log(`Received ${signal}. Shutting down...`);
  try {
    await prisma.$disconnect();
    server.close(() => {
      console.log('Server closed');
      process.exit(0);
    });
  } catch (err) {
    console.error('Error during shutdown', err);
    process.exit(1);
  }
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
