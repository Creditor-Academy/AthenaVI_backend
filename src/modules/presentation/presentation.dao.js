const prisma = require('../../shared/config/prismaClient');

const slidesOrderedInclude = {
  slides: {
    orderBy: { order: 'asc' },
  },
};

/**
 * Create a PRESENTATION Project and linked Deck in one transaction.
 * Does not call video project create helpers.
 */
async function createPresentationProject({
  workspaceId,
  folderId,
  name,
  createdBy,
  themeTokens,
  aspectRatio = '16:9',
  locale = 'en',
}) {
  return prisma.$transaction(async (tx) => {
    const project = await tx.project.create({
      data: {
        name,
        workspaceId,
        folderId,
        createdBy,
        updatedBy: createdBy,
        type: 'PRESENTATION',
        status: 'draft',
        data: { presentation: { version: 1 } },
      },
      include: {
        folder: {
          select: { id: true, name: true },
        },
      },
    });

    const deck = await tx.deck.create({
      data: {
        projectId: project.id,
        themeTokens: themeTokens || {},
        status: 'DRAFT',
        aspectRatio,
        locale,
        outline: null,
      },
      include: slidesOrderedInclude,
    });

    return { project, deck };
  });
}

async function findDeckByProjectId(projectId) {
  return prisma.deck.findUnique({
    where: { projectId },
    include: slidesOrderedInclude,
  });
}

async function findDeckById(deckId) {
  return prisma.deck.findUnique({
    where: { id: deckId },
    include: slidesOrderedInclude,
  });
}

async function updateDeck(deckId, data) {
  return prisma.deck.update({
    where: { id: deckId },
    data,
    include: slidesOrderedInclude,
  });
}

async function updateProjectName(projectId, name) {
  return prisma.project.update({
    where: { id: projectId },
    data: { name },
    select: { id: true, name: true, type: true, folderId: true, workspaceId: true },
  });
}

/**
 * @param {string} deckId
 * @param {Array<object>} slidesData
 */
async function createSlides(deckId, slidesData) {
  if (!Array.isArray(slidesData) || slidesData.length === 0) {
    return [];
  }

  await prisma.slide.createMany({
    data: slidesData.map((slide) => ({
      deckId,
      order: slide.order,
      contentType: slide.contentType ?? null,
      layoutId: slide.layoutId ?? null,
      content: slide.content ?? null,
      imageRef: slide.imageRef ?? null,
      elements: slide.elements ?? null,
      status: slide.status || 'PENDING',
      manuallyEdited: slide.manuallyEdited === true,
    })),
  });

  return prisma.slide.findMany({
    where: { deckId },
    orderBy: { order: 'asc' },
  });
}

async function createOneSlide(slide) {
  return prisma.slide.create({
    data: {
      deckId: slide.deckId,
      order: slide.order,
      contentType: slide.contentType ?? null,
      layoutId: slide.layoutId ?? null,
      content: slide.content ?? null,
      imageRef: slide.imageRef ?? null,
      elements: slide.elements ?? null,
      status: slide.status || 'READY',
      manuallyEdited: slide.manuallyEdited === true,
    },
  });
}

async function updateSlide(slideId, data) {
  return prisma.slide.update({
    where: { id: slideId },
    data,
  });
}

async function findSlideById(slideId) {
  return prisma.slide.findUnique({
    where: { id: slideId },
  });
}

async function deleteSlideById(slideId) {
  return prisma.slide.delete({
    where: { id: slideId },
  });
}

async function deleteSlidesByDeckId(deckId) {
  return prisma.slide.deleteMany({
    where: { deckId },
  });
}

/**
 * Increment order for all slides with order >= fromOrder by delta.
 */
async function shiftSlideOrders(deckId, fromOrder, delta) {
  const slides = await prisma.slide.findMany({
    where: { deckId, order: { gte: fromOrder } },
    orderBy: { order: delta > 0 ? 'desc' : 'asc' },
  });
  for (const s of slides) {
    await prisma.slide.update({
      where: { id: s.id },
      data: { order: s.order + delta },
    });
  }
}

async function resequenceSlideOrders(deckId) {
  const slides = await prisma.slide.findMany({
    where: { deckId },
    orderBy: { order: 'asc' },
  });
  let order = 1;
  for (const s of slides) {
    if (s.order !== order) {
      await prisma.slide.update({ where: { id: s.id }, data: { order } });
    }
    order += 1;
  }
}

async function reorderSlides(deckId, slideIds) {
  return prisma.$transaction(async (tx) => {
    // Temporary high orders to avoid unique conflicts if any composite unique existed
    for (let i = 0; i < slideIds.length; i += 1) {
      await tx.slide.update({
        where: { id: slideIds[i] },
        data: { order: 10_000 + i },
      });
    }
    for (let i = 0; i < slideIds.length; i += 1) {
      await tx.slide.update({
        where: { id: slideIds[i] },
        data: { order: i + 1 },
      });
    }
  });
}

async function createJob(data) {
  return prisma.slideGenerationJob.create({
    data,
  });
}

async function updateJob(jobId, data) {
  return prisma.slideGenerationJob.update({
    where: { id: jobId },
    data,
  });
}

async function findJobByRequestHash(requestHash) {
  return prisma.slideGenerationJob.findUnique({
    where: { requestHash },
  });
}

async function findExport(exportId) {
  return prisma.deckExport.findUnique({
    where: { id: exportId },
  });
}

async function createExport(data) {
  return prisma.deckExport.create({
    data,
  });
}

async function updateExport(exportId, data) {
  return prisma.deckExport.update({
    where: { id: exportId },
    data,
  });
}

async function findActiveTemplatesByContentType(contentType) {
  const where = {
    type: 'DECK_LAYOUT',
    isActive: true,
  };
  if (Array.isArray(contentType) && contentType.length) {
    where.contentType = { in: contentType };
  } else if (contentType) {
    where.contentType = contentType;
  }
  return prisma.template.findMany({
    where,
    orderBy: [{ contentType: 'asc' }, { variant: 'asc' }, { version: 'desc' }],
  });
}

async function findActiveDeckPacks() {
  return prisma.template.findMany({
    where: { type: 'DECK_PACK', isActive: true },
    orderBy: [{ name: 'asc' }, { version: 'desc' }],
  });
}

async function findLayoutsByLayoutIds(layoutIds) {
  const ids = Array.isArray(layoutIds) ? [...new Set(layoutIds.filter(Boolean))] : [];
  if (!ids.length) return [];
  const all = await prisma.template.findMany({
    where: { type: 'DECK_LAYOUT', isActive: true },
  });
  const wanted = new Set(ids);
  return all.filter((t) => wanted.has(t.schema?.layout_id));
}

async function findTemplateById(templateId) {
  return prisma.template.findUnique({
    where: { id: templateId },
  });
}

async function upsertTemplate(template) {
  const {
    id,
    type = 'DECK_LAYOUT',
    name,
    contentType,
    variant,
    schema,
    version = 1,
    isActive = true,
    createdBy,
  } = template;

  if (id) {
    return prisma.template.upsert({
      where: { id },
      create: {
        id,
        type,
        name,
        contentType: contentType ?? null,
        variant: variant ?? null,
        schema,
        version,
        isActive,
        createdBy,
      },
      update: {
        type,
        name,
        contentType: contentType ?? null,
        variant: variant ?? null,
        schema,
        version,
        isActive,
      },
    });
  }

  return prisma.template.create({
    data: {
      type,
      name,
      contentType: contentType ?? null,
      variant: variant ?? null,
      schema,
      version,
      isActive,
      createdBy,
    },
  });
}

async function upsertTemplates(templates) {
  const results = [];
  for (const template of templates || []) {
    results.push(await upsertTemplate(template));
  }
  return results;
}

async function findImageCacheByHash(briefHash) {
  return prisma.presentationImageCache.findUnique({
    where: { briefHash },
  });
}

async function createImageCache(data) {
  return prisma.presentationImageCache.create({
    data,
  });
}

async function incrementDeckCreditsCharged(deckId, amountAc) {
  const amount = Math.max(0, Math.floor(Number(amountAc) || 0));
  if (amount === 0) {
    return findDeckById(deckId);
  }

  return prisma.deck.update({
    where: { id: deckId },
    data: {
      creditsChargedSoFar: { increment: amount },
    },
    include: slidesOrderedInclude,
  });
}

module.exports = {
  createPresentationProject,
  findDeckByProjectId,
  findDeckById,
  updateDeck,
  updateProjectName,
  createSlides,
  createOneSlide,
  updateSlide,
  findSlideById,
  deleteSlideById,
  deleteSlidesByDeckId,
  shiftSlideOrders,
  resequenceSlideOrders,
  reorderSlides,
  createJob,
  updateJob,
  findJobByRequestHash,
  findExport,
  createExport,
  updateExport,
  findActiveTemplatesByContentType,
  findActiveDeckPacks,
  findLayoutsByLayoutIds,
  findTemplateById,
  upsertTemplate,
  upsertTemplates,
  findImageCacheByHash,
  createImageCache,
  incrementDeckCreditsCharged,
};
