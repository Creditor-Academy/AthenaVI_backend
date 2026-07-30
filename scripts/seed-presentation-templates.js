/**
 * Seed DECK_LAYOUT templates from seed-layouts.json (idempotent for system-seed).
 *
 * Usage (development):
 *   npm run seed:presentation-templates
 */
const prisma = require('../src/shared/config/prismaClient');
const presentationDao = require('../src/modules/presentation/presentation.dao');
const { assertDeckLayoutSchema } = require('../src/modules/templates/templateAdmin.service');
const seedLayouts = require('../src/modules/presentation/templates/seed-layouts.json');

const SYSTEM_SEED = 'system-seed';

async function main() {
  const layouts = Array.isArray(seedLayouts) ? seedLayouts : [];

  for (const layout of layouts) {
    assertDeckLayoutSchema(layout.schema);
  }

  const deleted = await prisma.template.deleteMany({
    where: {
      createdBy: SYSTEM_SEED,
      type: 'DECK_LAYOUT',
    },
  });
  if (deleted.count > 0) {
    console.log(`Removed ${deleted.count} existing system-seed DECK_LAYOUT template(s)`);
  }

  const payloads = layouts.map((layout) => ({
    type: 'DECK_LAYOUT',
    name: layout.name,
    contentType: layout.contentType ?? null,
    variant: layout.variant ?? null,
    schema: layout.schema,
    version: layout.version ?? 1,
    isActive: layout.isActive !== false,
    createdBy: SYSTEM_SEED,
  }));

  const results = await presentationDao.upsertTemplates(payloads);
  console.log(`Seeded ${results.length} DECK_LAYOUT template(s)`);
}

main()
  .then(async () => {
    await prisma.$disconnect();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error(err);
    await prisma.$disconnect();
    process.exit(1);
  });
