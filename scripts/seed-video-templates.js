/**
 * Seed VIDEO_SCENE templates only (never touches DECK_LAYOUT).
 *
 * Usage:
 *   npm run seed:video-templates
 */
const prisma = require('../src/shared/config/prismaClient');
const seedScenes = require('../src/modules/project/templates/seed-video-scenes.json');
const { assertVideoSceneTemplateSchema } = require('../src/modules/validations/videoTemplate.validations');

const SYSTEM_SEED = 'system-seed';

async function main() {
  const rows = Array.isArray(seedScenes) ? seedScenes : [];

  const deleted = await prisma.template.deleteMany({
    where: {
      createdBy: SYSTEM_SEED,
      type: 'VIDEO_SCENE',
    },
  });
  if (deleted.count > 0) {
    console.log(`Removed ${deleted.count} existing system-seed VIDEO_SCENE template(s)`);
  }

  let created = 0;
  for (const row of rows) {
    const schema = assertVideoSceneTemplateSchema(row.schema);
    await prisma.template.create({
      data: {
        type: 'VIDEO_SCENE',
        name: row.name,
        contentType: row.contentType ?? null,
        variant: row.variant ?? null,
        schema,
        version: row.version ?? 1,
        isActive: row.isActive !== false,
        createdBy: SYSTEM_SEED,
      },
    });
    created += 1;
  }

  console.log(`Seeded ${created} VIDEO_SCENE template(s)`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => {});
  });
