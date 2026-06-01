/**
 * One-time backfill: project.storageBytes and missing fileSizeBytes on S3 rows.
 *
 * Usage (development):
 *   dotenv -e .env.development -- node scripts/backfill-project-storage.js
 */
const prisma = require('../src/shared/config/prismaClient');
const { headObjectMeta } = require('../src/modules/s3/s3.service');
const projectStorageService = require('../src/modules/project/projectStorage.service');

async function resolveFileSizeBytes(s3Key, existing) {
  if (existing != null && existing > 0) {
    return existing;
  }
  if (!s3Key) {
    return null;
  }
  try {
    const meta = await headObjectMeta(s3Key);
    return meta.contentLength ?? 0;
  } catch {
    return 0;
  }
}

async function backfillS3RowSizes() {
  const heygenRows = await prisma.heygenResponse.findMany({
    where: { s3Key: { not: null }, fileSizeBytes: null },
    select: { id: true, s3Key: true, fileSizeBytes: true },
  });
  for (const row of heygenRows) {
    const fileSizeBytes = await resolveFileSizeBytes(row.s3Key, row.fileSizeBytes);
    await prisma.heygenResponse.update({
      where: { id: row.id },
      data: { fileSizeBytes },
    });
  }

  const renderRows = await prisma.projectRender.findMany({
    where: { s3Key: { not: null }, fileSizeBytes: null },
    select: { id: true, s3Key: true, fileSizeBytes: true },
  });
  for (const row of renderRows) {
    const fileSizeBytes = await resolveFileSizeBytes(row.s3Key, row.fileSizeBytes);
    await prisma.projectRender.update({
      where: { id: row.id },
      data: { fileSizeBytes },
    });
  }

  const cacheRows = await prisma.sceneRenderCache.findMany({
    where: { fileSizeBytes: null },
    select: { id: true, s3Key: true, fileSizeBytes: true },
  });
  for (const row of cacheRows) {
    const fileSizeBytes = await resolveFileSizeBytes(row.s3Key, row.fileSizeBytes);
    await prisma.sceneRenderCache.update({
      where: { id: row.id },
      data: { fileSizeBytes },
    });
  }
}

async function main() {
  console.log('Backfilling S3 row file sizes...');
  await backfillS3RowSizes();

  const projects = await prisma.project.findMany({ select: { id: true } });
  console.log(`Recalculating storage for ${projects.length} project(s)...`);

  let index = 0;
  for (const { id } of projects) {
    index += 1;
    const bytes = await projectStorageService.recalculateProjectStorage(id);
    if (index % 50 === 0 || index === projects.length) {
      console.log(`  ${index}/${projects.length} — latest ${bytes} bytes`);
    }
  }

  console.log('Done.');
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
