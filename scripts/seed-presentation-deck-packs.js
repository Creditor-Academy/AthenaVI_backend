/**
 * Seed DECK_PACK templates from seed-deck-packs.json (idempotent for system-seed).
 * Requires DECK_LAYOUT templates to exist (run seed:presentation-templates first).
 *
 * Usage (development):
 *   npm run seed:presentation-deck-packs
 */
const prisma = require('../src/shared/config/prismaClient');
const presentationDao = require('../src/modules/presentation/presentation.dao');
const { assertDeckPackSchema } = require('../src/modules/templates/templateAdmin.service');
const seedPacks = require('../src/modules/presentation/templates/seed-deck-packs.json');

const SYSTEM_SEED = 'system-seed';

async function assertLayoutsExist(schema) {
  const layoutIds = (schema.slides || []).map((s) => s.layout_id);
  for (const layoutId of layoutIds) {
    const found = await prisma.template.findFirst({
      where: {
        type: 'DECK_LAYOUT',
        isActive: true,
        schema: { path: ['layout_id'], equals: layoutId },
      },
      select: { id: true },
    });
    if (!found) {
      throw new Error(
        `Missing DECK_LAYOUT layout_id=${layoutId}. Run npm run seed:presentation-templates first.`
      );
    }
  }
}

async function main() {
  const packs = Array.isArray(seedPacks) ? seedPacks : [];

  for (const pack of packs) {
    assertDeckPackSchema(pack.schema);
    await assertLayoutsExist(pack.schema);
  }

  const deleted = await prisma.template.deleteMany({
    where: {
      createdBy: SYSTEM_SEED,
      type: 'DECK_PACK',
    },
  });
  if (deleted.count > 0) {
    console.log(`Removed ${deleted.count} existing system-seed DECK_PACK template(s)`);
  }

  const payloads = packs.map((pack) => ({
    type: 'DECK_PACK',
    name: pack.name,
    contentType: pack.contentType ?? 'pack',
    variant: pack.variant ?? null,
    schema: pack.schema,
    version: pack.version ?? 1,
    isActive: pack.isActive !== false,
    createdBy: SYSTEM_SEED,
  }));

  const results = await presentationDao.upsertTemplates(payloads);
  console.log(`Seeded ${results.length} DECK_PACK template(s)`);
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
