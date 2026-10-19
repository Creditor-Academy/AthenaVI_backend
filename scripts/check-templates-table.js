const prisma = require('../src/shared/config/prismaClient');

async function main() {
  try {
    const counts = await prisma.template.groupBy({
      by: ['type'],
      _count: { _all: true },
    });
    console.log('templates', JSON.stringify(counts));
  } catch (err) {
    console.log('ERR_CODE', err.code);
    console.log('ERR_MSG', err.message);
    console.log('ERR_META', JSON.stringify(err.meta || {}));
  } finally {
    await prisma.$disconnect();
  }
}

main();
