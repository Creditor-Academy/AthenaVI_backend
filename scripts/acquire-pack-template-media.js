/**
 * After DECK_PACK seed: acquire durable system images into TemplateMedia.
 * Stock once → S3 under presentations/_system/packs/{pack_id}/slide-N.jpg
 * Falls back to solid placeholder PNG when stock is unavailable.
 */
const path = require('path');
const prisma = require('../src/shared/config/prismaClient');
const s3Service = require('../src/modules/s3/s3.service');
const stockService = require('../src/modules/stock/stock.service');
const templateMediaDao = require('../src/modules/templates/templateMedia.dao');
const templateMediaService = require('../src/modules/templates/templateMedia.service');
const { downloadRemote } = require('../src/shared/utils/downloadRemote');
const generationFlowService = require('../src/modules/presentation/generationFlow.service');

async function s3Exists(key) {
  try {
    await s3Service.headObjectMeta(key);
    return true;
  } catch {
    return false;
  }
}

async function acquireBufferForPrompt(query) {
  try {
    const result = await stockService.searchStock({
      q: query || 'professional office presentation',
      type: 'photo',
      page: 1,
      perPage: 5,
      provider: 'all',
    });
    const item = (result.items || [])[0];
    if (!item) return null;

    const url =
      item.previewUrl ||
      item.downloadUrl ||
      item.urls?.regular ||
      item.urls?.full ||
      item.src?.large2x ||
      item.src?.large ||
      item.url;
    if (!url) return null;
    const buffer = await downloadRemote(url, { maxBytes: 8 * 1024 * 1024 });
    return { buffer, contentType: 'image/jpeg', ext: '.jpg' };
  } catch (err) {
    console.warn(`Stock acquire failed for "${query}":`, err.message);
  }
  return null;
}

async function ensurePackSlideMedia(packTemplate) {
  const schema = packTemplate.schema || {};
  const packId = schema.pack_id || packTemplate.variant || packTemplate.id;
  const slides = Array.isArray(schema.slides) ? schema.slides : [];
  const defaults = schema.generationDefaults || {};
  const imageStyle = defaults.imageStyle || 'professional corporate photography';

  const layoutIds = [...new Set(slides.map((s) => s.layout_id).filter(Boolean))];
  const layouts = await prisma.template.findMany({
    where: {
      type: 'DECK_LAYOUT',
      OR: layoutIds.map((layoutId) => ({
        schema: { path: ['layout_id'], equals: layoutId },
      })),
    },
    select: { schema: true },
  });
  const layoutById = new Map(layouts.map((l) => [l.schema?.layout_id, l.schema]));

  let firstPhotoKey = null;
  let created = 0;

  for (const slide of slides) {
    const layoutSchema = layoutById.get(slide.layout_id);
    const imageSlots = templateMediaService.listLayoutImageSlots(layoutSchema);
    if (!imageSlots.length) continue;

    const order = slide.order || 1;
    const slideHint = templateMediaService.slotHintForSlideOrder(order);
    const prompts = slide.placeholder?.imagePrompts || {};
    const defaultPrompt =
      slide.placeholder?.imagePrompt ||
      slide.generationHints?.imagePromptStyle ||
      `${imageStyle}, ${slide.placeholder?.title || slide.contentType || 'presentation'}`;

    let firstSlotKey = null;

    for (let i = 0; i < imageSlots.length; i += 1) {
      const slotId = imageSlots[i];
      const slotHint = templateMediaService.slotHintForSlideSlot(order, slotId);
      const key = templateMediaService.packSlideSlotMediaKey(packId, order, slotId, '.jpg');

      let s3Key = key;
      let mimeType = 'image/jpeg';

      if (!(await s3Exists(key))) {
        const prompt = prompts[slotId] || (i === 0 ? defaultPrompt : `${defaultPrompt}, ${slotId.replace(/_/g, ' ').toLowerCase()}`);

        let acquired = await acquireBufferForPrompt(prompt);
        if (!acquired) {
          const ph = await generationFlowService.ensurePlaceholderImage();
          try {
            const buf = await s3Service.getObjectBuffer(ph.s3Key);
            await s3Service.uploadFileToKey(buf, key, 'image/png');
            s3Key = key;
            mimeType = 'image/png';
          } catch {
            s3Key = ph.s3Key;
            mimeType = 'image/png';
          }
          console.log(`  slide ${order}/${slotId}: placeholder fallback`);
        } else {
          const uploadKey = templateMediaService.packSlideSlotMediaKey(
            packId,
            order,
            slotId,
            acquired.ext || '.jpg'
          );
          await s3Service.uploadFileToKey(acquired.buffer, uploadKey, acquired.contentType);
          s3Key = uploadKey;
          mimeType = acquired.contentType;
          console.log(`  slide ${order}/${slotId}: stock → ${uploadKey}`);
        }
      } else {
        console.log(`  slide ${order}/${slotId}: reuse ${key}`);
      }

      await templateMediaDao.upsertBySlotHint({
        templateId: packTemplate.id,
        kind: 'photo',
        slotHint,
        name: `${packId}-slide-${order}-${slotId}`,
        s3Key,
        mimeType,
        sortOrder: order * 10 + i,
      });
      created += 1;
      if (!firstSlotKey) firstSlotKey = s3Key;
      if (!firstPhotoKey) firstPhotoKey = s3Key;
    }

    if (firstSlotKey) {
      await templateMediaDao.upsertBySlotHint({
        templateId: packTemplate.id,
        kind: 'photo',
        slotHint: slideHint,
        name: `${packId}-slide-${order}`,
        s3Key: firstSlotKey,
        mimeType: path.extname(firstSlotKey) === '.png' ? 'image/png' : 'image/jpeg',
        sortOrder: order,
      });
    }
  }

  if (firstPhotoKey) {
    await templateMediaDao.upsertBySlotHint({
      templateId: packTemplate.id,
      kind: 'preview',
      slotHint: 'preview',
      name: `${packId}-preview`,
      s3Key: firstPhotoKey,
      mimeType: path.extname(firstPhotoKey) === '.png' ? 'image/png' : 'image/jpeg',
      sortOrder: 0,
    });
  }

  return created;
}

async function acquireMediaForAllPacks() {
  const packs = await prisma.template.findMany({
    where: { type: 'DECK_PACK', isActive: true },
    orderBy: { name: 'asc' },
  });

  let total = 0;
  for (const pack of packs) {
    const packId = pack.schema?.pack_id || pack.id;
    console.log(`Acquiring media for pack ${packId} (${pack.id})`);
    total += await ensurePackSlideMedia(pack);
  }
  console.log(`Template media rows upserted for ${total} image slide(s) across ${packs.length} pack(s)`);
}

module.exports = {
  ensurePackSlideMedia,
  acquireMediaForAllPacks,
  acquireBufferForPrompt,
};
