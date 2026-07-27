const { createClient } = require('redis');

async function main() {
  const c = createClient({
    url: process.env.REDIS_URL,
    socket: { connectTimeout: 10000 },
  });
  c.on('error', (e) => console.log('redis-err', e.message));
  try {
    await c.connect();
    console.log('redis', await c.ping());
    await c.quit();
  } catch (e) {
    console.log('redis-fail', e.message);
  }

  try {
    const prisma = require('../src/shared/config/prismaClient');
    await prisma.$queryRaw`SELECT 1 as ok`;
    console.log('db-ok');
    try {
      const counts = await prisma.template.groupBy({
        by: ['type'],
        _count: { _all: true },
      });
      console.log('templates', JSON.stringify(counts));
    } catch (err) {
      console.log('template-table', String(err.message).split('\n')[0]);
    }
    await prisma.$disconnect();
  } catch (e) {
    console.log('db-fail', String(e.message).split('\n')[0]);
  }
}

main();
