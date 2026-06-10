/**
 * One-off: lowercase and trim user emails before auth normalization deploy.
 * Run: dotenv -e .env.development -- node scripts/normalize-user-emails.js
 */
const dotenv = require('dotenv');

const envFile =
  process.env.NODE_ENV === 'production' ? '.env.production' : '.env.development';
dotenv.config({ path: envFile });

const prisma = require('../src/shared/config/prismaClient');

async function main() {
  const users = await prisma.user.findMany({ select: { id: true, email: true } });
  let updated = 0;

  for (const user of users) {
    const normalized = String(user.email || '').trim().toLowerCase();
    if (!normalized || normalized === user.email) {
      continue;
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { email: normalized },
    });
    updated += 1;
    console.log(`Normalized ${user.email} -> ${normalized}`);
  }

  console.log(`Done. Updated ${updated} user(s).`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
