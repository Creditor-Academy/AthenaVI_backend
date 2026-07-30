const crypto = require('crypto');
const path = require('path');
const prisma = require('../../shared/config/prismaClient');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const { downloadRemote } = require('../../shared/utils/downloadRemote');
const {
  moderateText,
  chatJson,
  generateImage,
  checkImageRelevance,
  DEFAULT_OUTLINE_MODEL,
  DEFAULT_SLIDE_MODEL,
  DEFAULT_IMAGE_MODEL,
} = require('../../shared/services/ai');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const presentationRateLimit = require('./presentationRateLimit.service');
const { selectLayout } = require('./layoutSelector.service');
const { validateSlide } = require('./layoutQa.service');
const imageCache = require('./imageCache.service');
const documentParse = require('./documentParse.service');
const themeService = require('./theme.service');
const {
  PROMPT_BUNDLE_VERSION,
  getOutlinePrompt,
  getSlideContentPrompt,
  getClassifyPrompt,
  getImageBriefPrompt,
  getPathBPrompt,
} = require('./prompts');
const stockService = require('../stock/stock.service');
const s3Service = require('../s3/s3.service');
const inboxService = require('../inbox/inbox.service');
const { PPT_FEATURE } = require('../../shared/config/presentationCreditPricing');
const { layoutSlotsToElements } = require('./layoutToElements');
const { AI_SLIDE_MAX } = require('./presentation.constants');

const CONTENT_TIMEOUT_MS =
  Number(process.env.PPT_SLIDE_CONTENT_TIMEOUT_MS) > 0
    ? Number(process.env.PPT_SLIDE_CONTENT_TIMEOUT_MS)
    : 6000;

const PPT_SLIDE_CONCURRENCY =
  Number(process.env.PPT_SLIDE_CONCURRENCY) > 0
    ? Number(process.env.PPT_SLIDE_CONCURRENCY)
    : 4;

const SEED_LAYOUTS = require('./templates/seed-layouts.json');

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new AppError(`${label || 'Operation'} timed out after ${ms}ms`, 504)),
      ms
    );
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

function hashPayload(parts) {
  return crypto.createHash('sha256').update(parts.filter(Boolean).join('|')).digest('hex');
}

function loadSeedTemplates(contentType) {
  const type = contentType != null ? String(contentType) : null;
  return (SEED_LAYOUTS || [])
    .filter((t) => !type || String(t.contentType) === type)
    .map((t) => ({
      id: t.schema?.layout_id || `${t.contentType}_${t.variant}`,
      name: t.name,
      contentType: t.contentType,
      variant: t.variant,
      schema: t.schema,
      isActive: true,
    }));
}

async function resolveLayoutTemplates(contentType) {
  let templates = await presentationDao.findActiveTemplatesByContentType(contentType);
  if (!templates || templates.length === 0) {
    templates = loadSeedTemplates(contentType);
  }
  if ((!templates || templates.length === 0) && contentType) {
    templates = await presentationDao.findActiveTemplatesByContentType(null);
    if (!templates || templates.length === 0) {
      templates = loadSeedTemplates(null);
    }
  }
  return templates || [];
}

async function loadPresentationDeck(presentationId, { requireWorkspaceId } = {}) {
  const deck = await presentationDao.findDeckByProjectId(presentationId);
  if (!deck) {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }

  const project = await prisma.project.findUnique({
    where: { id: presentationId },
    select: {
      id: true,
      name: true,
      workspaceId: true,
      type: true,
      folderId: true,
      createdBy: true,
    },
  });

  if (!project || project.type !== 'PRESENTATION') {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }
  if (requireWorkspaceId && project.workspaceId !== requireWorkspaceId) {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }

  return { deck, project };
}

async function mapPool(items, concurrency, fn) {
  const list = Array.isArray(items) ? items : [];
  const results = new Array(list.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < list.length) {
      const i = nextIndex;
      nextIndex += 1;
      results[i] = await fn(list[i], i);
    }
  }

  const workers = Array.from(
    { length: Math.min(Math.max(1, concurrency), Math.max(1, list.length)) },
    () => worker()
  );
  await Promise.all(workers);
  return results;
}

async function trackCharge(deckId, chargeResult) {
  if (!chargeResult || chargeResult.skipped) return chargeResult;
  const amount =
    chargeResult.charged != null
      ? chargeResult.charged
      : chargeResult.pricing?.athenaCredits != null
        ? chargeResult.pricing.athenaCredits
        : 0;
  if (amount > 0) {
    await presentationDao.incrementDeckCreditsCharged(deckId, amount);
  }
  return chargeResult;
}

/**
 * Create or reuse SlideGenerationJob by unique requestHash. Skip charge on duplicate.
 */
async function beginJob({ slideId, jobType, requestHash, promptVersion, model }) {
  const existing = await presentationDao.findJobByRequestHash(requestHash);
  if (existing) {
    return { job: existing, duplicate: true };
  }

  try {
    const job = await presentationDao.createJob({
      slideId,
      jobType,
      status: 'RUNNING',
      requestHash,
      promptVersion: promptVersion || PROMPT_BUNDLE_VERSION,
      model: model || null,
      creditCharged: false,
    });
    return { job, duplicate: false };
  } catch (err) {
    if (err?.code === 'P2002') {
      const raced = await presentationDao.findJobByRequestHash(requestHash);
      if (raced) return { job: raced, duplicate: true };
    }
    throw err;
  }
}

async function finishJob(jobId, { status, usage, visionScore, error, creditCharged, latencyMs, model }) {
  return presentationDao.updateJob(jobId, {
    status,
    ...(usage !== undefined ? { usage } : {}),
    ...(visionScore !== undefined ? { visionScore } : {}),
    ...(error !== undefined ? { error: error == null ? null : String(error).slice(0, 2000) } : {}),
    ...(creditCharged !== undefined ? { creditCharged } : {}),
    ...(latencyMs !== undefined ? { latencyMs } : {}),
    ...(model !== undefined ? { model } : {}),
  });
}

async function notifyGenerationFinished({
  userId,
  workspaceId,
  projectId,
  deckId,
  status,
  projectName,
  partial,
  creditsChargedSoFar,
  error,
}) {
  try {
    const ok = status === 'READY';
    await inboxService.notifyUser({
      userId,
      type: ok ? 'PRESENTATION_GENERATION_COMPLETED' : 'PRESENTATION_GENERATION_FAILED',
      referenceId: deckId,
      workspaceId,
      title: ok ? 'Presentation generation completed' : 'Presentation generation failed',
      message: ok
        ? `"${projectName || 'Presentation'}" is ready${partial ? ' (partial)' : ''}.`
        : `"${projectName || 'Presentation'}" generation failed${error ? `: ${error}` : '.'}`,
      metadata: {
        workspaceId,
        projectId,
        deckId,
        status,
        partial: Boolean(partial),
        creditsChargedSoFar: creditsChargedSoFar ?? null,
        actionUrl: `${process.env.FRONTEND_URL || ''}/workspaces/${workspaceId}/presentations/${projectId}`,
      },
    });
  } catch (notifyErr) {
    logger.error?.('presentation_generation_notify_failed', notifyErr) ||
      console.error('presentation generation notify failed', notifyErr);
  }
}

function normalizeOutline(data, { slideCount, density, locale }) {
  const slides = Array.isArray(data?.slides) ? data.slides : [];
  const normalizedSlides = slides
    .map((s, idx) => ({
      order: Number(s.order) > 0 ? Number(s.order) : idx + 1,
      title: String(s.title || `Slide ${idx + 1}`).trim(),
      summary: s.summary != null ? String(s.summary) : '',
      suggestedContentType: s.suggestedContentType || s.content_type || null,
    }))
    .slice(0, AI_SLIDE_MAX);

  const requested =
    slideCount != null ? Math.min(AI_SLIDE_MAX, Math.max(1, Number(slideCount) || 12)) : null;

  return {
    title: String(data?.title || 'Untitled presentation').trim(),
    slideCount: requested || Math.min(AI_SLIDE_MAX, normalizedSlides.length || 12),
    density: density || 'balanced',
    locale: locale || 'en',
    slides: normalizedSlides,
  };
}

function slideTextForVision(content) {
  if (!content || typeof content !== 'object') return '';
  const parts = [];
  if (content.title) parts.push(String(content.title));
  if (content.body) parts.push(String(content.body));
  if (Array.isArray(content.bullets)) {
    parts.push(
      content.bullets
        .map((b) => (typeof b === 'string' ? b : b?.text || ''))
        .filter(Boolean)
        .join('; ')
    );
  }
  return parts.join(' — ').slice(0, 1500);
}

async function uploadPresentationImage({ workspaceId, deckId, slideId, buffer, ext, contentType }) {
  const key = `presentations/${workspaceId}/${deckId}/images/${slideId}-${crypto.randomUUID()}${ext}`;
  return s3Service.uploadFileToKey(buffer, key, contentType);
}

async function tryStockImage({ query, workspaceId, deckId, slideId, brief }) {
  try {
    const result = await stockService.searchStock({
      q: query,
      type: 'photo',
      page: 1,
      perPage: 5,
    });
    const item = result?.items?.[0];
    if (!item?.previewUrl) return null;

    const buffer = await downloadRemote(item.previewUrl, { maxBytes: 8 * 1024 * 1024 });
    const uploaded = await uploadPresentationImage({
      workspaceId,
      deckId,
      slideId,
      buffer,
      ext: '.jpg',
      contentType: 'image/jpeg',
    });

    return {
      source: 'stock',
      provider: item.provider || null,
      externalId: item.externalId || null,
      url: uploaded.url,
      s3Key: uploaded.key,
      brief,
      attribution: item.attribution || null,
    };
  } catch {
    return null;
  }
}

async function generateAiImageRef({
  prompt,
  workspaceId,
  deckId,
  slideId,
  brief,
  source = 'ai_gen',
  quality = 'standard',
}) {
  const image = await generateImage({ prompt, quality });
  const uploaded = await uploadPresentationImage({
    workspaceId,
    deckId,
    slideId,
    buffer: image.buffer,
    ext: '.png',
    contentType: 'image/png',
  });
  return {
    source,
    url: uploaded.url,
    s3Key: uploaded.key,
    brief,
    model: DEFAULT_IMAGE_MODEL,
    revised_prompt: image.revised_prompt || null,
  };
}

async function resolveSlideImage({
  ctx,
  slide,
  content,
  visualNeed,
  brief,
  pathBSpec,
}) {
  const need = String(visualNeed || 'none').toLowerCase();

  if (need === 'none' || need === 'chart' || need === 'icon' || need === 'diagram_template') {
    return {
      imageRef: { source: 'none', visual_need: need, brief: brief || null },
      chargedFeature: null,
      cacheHit: false,
      visionScore: null,
    };
  }

  if (need === 'path_b') {
    const pathBPrompt = getPathBPrompt();
    const promptText = pathBPrompt.buildUser({
      pathBSpec: pathBSpec || content?.pathBSpec || {},
      brandPalette: ctx.themeTokens?.palette?.primary || undefined,
    });
    const requestHash = hashPayload([
      'IMAGE_PATH_B',
      slide.id,
      PROMPT_BUNDLE_VERSION,
      crypto.createHash('sha256').update(promptText).digest('hex'),
    ]);
    const { job, duplicate } = await beginJob({
      slideId: slide.id,
      jobType: 'IMAGE_PATH_B',
      requestHash,
      promptVersion: PROMPT_BUNDLE_VERSION,
      model: DEFAULT_IMAGE_MODEL,
    });
    if (duplicate) {
      return {
        imageRef: slide.imageRef || { source: 'path_b', brief },
        chargedFeature: null,
        cacheHit: false,
        visionScore: job.visionScore ?? null,
        skippedCharge: true,
      };
    }

    const started = Date.now();
    try {
      const imageRef = await generateAiImageRef({
        prompt: `${pathBPrompt.buildSystem()}\n\n${promptText}`,
        workspaceId: ctx.workspaceId,
        deckId: ctx.deckId,
        slideId: slide.id,
        brief,
        source: 'path_b',
        quality: 'hd',
      });
      if (!duplicate) {
        await trackCharge(
          ctx.deckId,
          await presentationCredit.chargeFlat({
            workspaceId: ctx.workspaceId,
            userId: ctx.userId,
            feature: PPT_FEATURE.IMAGE_PATH_B,
            idempotencyKey: `ppt:path_b:${requestHash}`,
            metadata: { deckId: ctx.deckId, slideId: slide.id },
          })
        );
      }
      await finishJob(job.id, {
        status: 'SUCCEEDED',
        creditCharged: !duplicate,
        latencyMs: Date.now() - started,
      });
      return {
        imageRef,
        chargedFeature: PPT_FEATURE.IMAGE_PATH_B,
        cacheHit: false,
        visionScore: null,
      };
    } catch (err) {
      await finishJob(job.id, {
        status: 'FAILED',
        error: err.message,
        latencyMs: Date.now() - started,
      });
      throw err;
    }
  }

  // photo / illustration / default → stock then Path A
  const searchQuery =
    brief?.search_query || brief?.searchQuery || brief?.subject || content?.title || 'presentation visual';
  const briefHash = imageCache.hashBrief({
    searchQuery,
    imageStyle: ctx.themeTokens?.imageStyle,
    colorTreatment: ctx.themeTokens?.colorTreatment,
    tier: 'standard',
  });

  const cached = await imageCache.getOrNull(briefHash);
  if (cached) {
    const requestHash = hashPayload(['IMAGE_CACHE', slide.id, briefHash]);
    const { job, duplicate } = await beginJob({
      slideId: slide.id,
      jobType: 'IMAGE_PATH_A',
      requestHash,
      promptVersion: PROMPT_BUNDLE_VERSION,
      model: 'cache',
    });
    if (!duplicate) {
      await presentationCredit.chargeFlat({
        workspaceId: ctx.workspaceId,
        userId: ctx.userId,
        feature: PPT_FEATURE.IMAGE_CACHE_HIT,
        idempotencyKey: `ppt:img_cache:${requestHash}`,
        metadata: { deckId: ctx.deckId, slideId: slide.id, briefHash },
        amountAc: 0,
      });
      await finishJob(job.id, { status: 'SUCCEEDED', creditCharged: false, latencyMs: 0 });
    }
    return {
      imageRef: {
        source: cached.source || 'ai_gen',
        url: cached.url,
        s3Key: cached.s3Key,
        brief,
        cacheHit: true,
      },
      chargedFeature: PPT_FEATURE.IMAGE_CACHE_HIT,
      cacheHit: true,
      visionScore: null,
    };
  }

  const requestHash = hashPayload(['IMAGE_PATH_A', slide.id, briefHash, PROMPT_BUNDLE_VERSION]);
  const { job, duplicate } = await beginJob({
    slideId: slide.id,
    jobType: 'IMAGE_PATH_A',
    requestHash,
    promptVersion: PROMPT_BUNDLE_VERSION,
    model: DEFAULT_IMAGE_MODEL,
  });
  if (duplicate) {
    return {
      imageRef: slide.imageRef || { source: 'none', brief },
      chargedFeature: null,
      cacheHit: false,
      visionScore: job.visionScore ?? null,
      skippedCharge: true,
    };
  }

  const started = Date.now();
  try {
    let imageRef = await tryStockImage({
      query: searchQuery,
      workspaceId: ctx.workspaceId,
      deckId: ctx.deckId,
      slideId: slide.id,
      brief,
    });

    let visionScore = null;
    if (imageRef?.url) {
      try {
        const vision = await checkImageRelevance({
          imageUrl: imageRef.url,
          slideTitle: content?.title || '',
          slideText: slideTextForVision(content),
          briefSubject: brief?.subject || searchQuery,
        });
        visionScore = vision.score;
        if (!vision.relevant) {
          imageRef = null;
        }
      } catch {
        // soft-fail vision; keep stock candidate
      }
    }

    if (!imageRef) {
      const prompt = [
        brief?.subject || searchQuery,
        brief?.composition || '',
        ctx.themeTokens?.imageStyle || '',
        ctx.themeTokens?.colorTreatment || '',
        Array.isArray(brief?.negative_terms)
          ? `Avoid: ${brief.negative_terms.join(', ')}`
          : '',
      ]
        .filter(Boolean)
        .join('. ');

      imageRef = await generateAiImageRef({
        prompt,
        workspaceId: ctx.workspaceId,
        deckId: ctx.deckId,
        slideId: slide.id,
        brief,
        source: 'ai_gen',
      });

      try {
        const vision = await checkImageRelevance({
          imageUrl: imageRef.url,
          imageBase64: undefined,
          slideTitle: content?.title || '',
          slideText: slideTextForVision(content),
          briefSubject: brief?.subject || searchQuery,
        });
        visionScore = vision.score;
      } catch {
        // ignore
      }
    }

    try {
      await imageCache.put({
        briefHash,
        s3Key: imageRef.s3Key,
        url: imageRef.url,
        source: imageRef.source,
        metadata: { slideId: slide.id, searchQuery },
      });
    } catch {
      // unique race — ignore
    }

    if (!duplicate) {
      await trackCharge(
        ctx.deckId,
        await presentationCredit.chargeFlat({
          workspaceId: ctx.workspaceId,
          userId: ctx.userId,
          feature: PPT_FEATURE.IMAGE_PATH_A,
          idempotencyKey: `ppt:path_a:${requestHash}`,
          metadata: { deckId: ctx.deckId, slideId: slide.id, briefHash },
        })
      );
    }

    await finishJob(job.id, {
      status: 'SUCCEEDED',
      visionScore,
      creditCharged: !duplicate,
      latencyMs: Date.now() - started,
    });

    return {
      imageRef,
      chargedFeature: PPT_FEATURE.IMAGE_PATH_A,
      cacheHit: false,
      visionScore,
    };
  } catch (err) {
    await finishJob(job.id, {
      status: 'FAILED',
      error: err.message,
      latencyMs: Date.now() - started,
    });
    throw err;
  }
}

async function processSlide(ctx, slide) {
  const startedAll = Date.now();
  await presentationDao.updateSlide(slide.id, { status: 'GENERATING' });

  try {
    const outlineSlide =
      (ctx.outline?.slides || []).find((s) => Number(s.order) === Number(slide.order)) ||
      (ctx.outline?.slides || [])[slide.order - 1] ||
      {};

    const neighbors = (ctx.outline?.slides || []).sort((a, b) => a.order - b.order);
    const prev = neighbors.find((s) => s.order === slide.order - 1);
    const next = neighbors.find((s) => s.order === slide.order + 1);

    // 1) Content LLM
    const contentPrompt = getSlideContentPrompt();
    const contentHash = hashPayload([
      'CONTENT',
      slide.id,
      PROMPT_BUNDLE_VERSION,
      ctx.density,
      outlineSlide.title,
      outlineSlide.summary,
      outlineSlide.suggestedContentType,
    ]);
    const contentJob = await beginJob({
      slideId: slide.id,
      jobType: 'CONTENT',
      requestHash: contentHash,
      promptVersion: PROMPT_BUNDLE_VERSION,
      model: DEFAULT_SLIDE_MODEL,
    });

    let content = slide.content && typeof slide.content === 'object' ? slide.content : null;
    if (!contentJob.duplicate) {
      const contentStarted = Date.now();
      try {
        const llmResult = await withTimeout(
          chatJson({
            system: contentPrompt.buildSystem(),
            user: contentPrompt.buildUser({
              deckTitle: ctx.outline?.title || ctx.projectName,
              themeTone: ctx.themeTokens?.imageStyle || 'professional',
              density: ctx.density || 'balanced',
              slideOrder: slide.order,
              slideTotal: neighbors.length || ctx.outline?.slideCount || 1,
              title: outlineSlide.title || content?.title,
              summary: outlineSlide.summary || '',
              suggestedContentType: outlineSlide.suggestedContentType || slide.contentType,
              previousSlideTitle: prev?.title,
              nextSlideTitle: next?.title,
              locale: ctx.locale || 'en',
            }),
            model: DEFAULT_SLIDE_MODEL,
          }),
          CONTENT_TIMEOUT_MS,
          'Slide content generation'
        );
        content = llmResult.data;
        await trackCharge(
          ctx.deckId,
          await presentationCredit.chargeFlat({
            workspaceId: ctx.workspaceId,
            userId: ctx.userId,
            feature: PPT_FEATURE.SLIDE_CONTENT,
            idempotencyKey: `ppt:content:${contentHash}`,
            metadata: {
              deckId: ctx.deckId,
              slideId: slide.id,
              usage: llmResult.usage,
            },
          })
        );
        await finishJob(contentJob.job.id, {
          status: 'SUCCEEDED',
          usage: llmResult.usage,
          model: llmResult.model,
          creditCharged: true,
          latencyMs: Date.now() - contentStarted,
        });
      } catch (err) {
        await finishJob(contentJob.job.id, {
          status: 'FAILED',
          error: err.message,
          latencyMs: Date.now() - contentStarted,
        });
        throw err;
      }
    } else if (!content) {
      content = {
        title: outlineSlide.title || `Slide ${slide.order}`,
        bullets: [],
        notes: '',
      };
    }

    // 2) Classify
    let contentType = content?.content_type || slide.contentType || outlineSlide.suggestedContentType;
    let visualNeed = content?.visual_need || null;

    const classifyPrompt = getClassifyPrompt();
    const classifyHash = hashPayload([
      'CLASSIFY',
      slide.id,
      PROMPT_BUNDLE_VERSION,
      crypto.createHash('sha256').update(JSON.stringify(content || {})).digest('hex'),
    ]);
    const classifyJob = await beginJob({
      slideId: slide.id,
      jobType: 'CLASSIFY',
      requestHash: classifyHash,
      promptVersion: PROMPT_BUNDLE_VERSION,
      model: DEFAULT_SLIDE_MODEL,
    });

    if (!classifyJob.duplicate) {
      try {
        const classified = await chatJson({
          system: classifyPrompt.buildSystem(),
          user: classifyPrompt.buildUser({
            slideContent: content,
            suggestedContentType: outlineSlide.suggestedContentType || contentType,
            title: content?.title || outlineSlide.title,
          }),
          model: DEFAULT_SLIDE_MODEL,
          temperature: 0.2,
        });
        contentType = classified.data?.content_type || contentType || 'bullet_list';
        visualNeed = classified.data?.visual_need || visualNeed || 'none';
        await finishJob(classifyJob.job.id, {
          status: 'SUCCEEDED',
          usage: classified.usage,
          latencyMs: classified.latencyMs,
          creditCharged: false,
        });
      } catch (err) {
        await finishJob(classifyJob.job.id, {
          status: 'FAILED',
          error: err.message,
        });
        contentType = contentType || 'bullet_list';
        visualNeed = visualNeed || 'none';
      }
    } else {
      contentType = contentType || 'bullet_list';
      visualNeed = visualNeed || 'none';
    }

    // 3) Layout select + QA
    const templates = await resolveLayoutTemplates(contentType);
    const { layoutId, template } = selectLayout({
      contentType,
      content,
      previousLayoutId: ctx.previousLayoutId || null,
      templates,
    });
    ctx.previousLayoutId = layoutId;

    const qa = validateSlide({
      content,
      layoutSchema: template?.schema || null,
    });
    content = qa.content;

    // 4) Image brief when needed
    let brief = null;
    const needsBrief =
      visualNeed &&
      !['none', 'chart', 'icon', 'diagram_template'].includes(String(visualNeed).toLowerCase());

    if (needsBrief) {
      const briefPrompt = getImageBriefPrompt();
      const briefHash = hashPayload([
        'IMAGE_BRIEF',
        slide.id,
        PROMPT_BUNDLE_VERSION,
        visualNeed,
        crypto.createHash('sha256').update(JSON.stringify(content || {})).digest('hex'),
      ]);
      const briefJob = await beginJob({
        slideId: slide.id,
        jobType: 'IMAGE_BRIEF',
        requestHash: briefHash,
        promptVersion: PROMPT_BUNDLE_VERSION,
        model: DEFAULT_SLIDE_MODEL,
      });
      if (!briefJob.duplicate) {
        try {
          const briefResult = await chatJson({
            system: briefPrompt.buildSystem(),
            user: briefPrompt.buildUser({
              slideTitle: content?.title,
              slideContent: content,
              themeImageStyle: ctx.themeTokens?.imageStyle,
              themeColorTreatment: ctx.themeTokens?.colorTreatment,
            }),
            model: DEFAULT_SLIDE_MODEL,
            temperature: 0.3,
          });
          brief = briefResult.data;
          await finishJob(briefJob.job.id, {
            status: 'SUCCEEDED',
            usage: briefResult.usage,
            latencyMs: briefResult.latencyMs,
            creditCharged: false,
          });
        } catch (err) {
          await finishJob(briefJob.job.id, { status: 'FAILED', error: err.message });
          brief = {
            subject: content?.title || outlineSlide.title,
            search_query: content?.title || outlineSlide.title,
            image_type: visualNeed === 'illustration' ? 'illustration' : 'photo',
          };
        }
      }
    }

    // 5) Images
    let imageRef = { source: 'none' };
    try {
      const imageResult = await resolveSlideImage({
        ctx,
        slide,
        content,
        visualNeed,
        brief,
        pathBSpec: content?.pathBSpec,
      });
      imageRef = imageResult.imageRef || imageRef;
    } catch (imgErr) {
      logger.warn?.('presentation_slide_image_failed', {
        slideId: slide.id,
        error: imgErr.message,
      });
      imageRef = { source: 'none', error: imgErr.message, brief };
    }

    const elementsDoc = layoutSlotsToElements(
      template?.schema || { slots: [] },
      content,
      imageRef
    );

    const updated = await presentationDao.updateSlide(slide.id, {
      status: 'READY',
      contentType: contentType || null,
      layoutId: layoutId || null,
      content,
      imageRef,
      elements: elementsDoc,
    });

    return {
      slide: updated,
      latencyMs: Date.now() - startedAll,
      ok: true,
    };
  } catch (err) {
    const failed = await presentationDao.updateSlide(slide.id, {
      status: 'FAILED',
      imageRef: { source: 'none', error: err.message },
    });
    return {
      slide: failed,
      latencyMs: Date.now() - startedAll,
      ok: false,
      error: err.message,
    };
  }
}

async function processDeckGeneration({
  workspaceId,
  deckId,
  userId,
  density,
  projectId,
  projectName,
}) {
  try {
    const deck = await presentationDao.findDeckById(deckId);
    if (!deck) return;

    const ctx = {
      workspaceId,
      deckId,
      userId,
      density: density || deck.outline?.density || 'balanced',
      locale: deck.locale || 'en',
      outline: deck.outline,
      themeTokens: deck.themeTokens || {},
      projectName,
      projectId: projectId || deck.projectId,
      previousLayoutId: null,
    };

    const pending = (deck.slides || []).filter(
      (s) => s.status === 'PENDING' || s.status === 'GENERATING'
    );

    await mapPool(pending, PPT_SLIDE_CONCURRENCY, async (slide) => processSlide(ctx, slide));

    const refreshed = await presentationDao.findDeckById(deckId);
    const slides = refreshed?.slides || [];
    const failedCount = slides.filter((s) => s.status === 'FAILED').length;
    const readyCount = slides.filter((s) => s.status === 'READY').length;
    const partial = failedCount > 0 && readyCount > 0;
    const allFailed = slides.length > 0 && failedCount === slides.length;
    const status = allFailed ? 'FAILED' : 'READY';

    const updated = await presentationDao.updateDeck(deckId, {
      status,
      partial,
      generationMetrics: {
        finishedAt: new Date().toISOString(),
        readyCount,
        failedCount,
        slideCount: slides.length,
        concurrency: PPT_SLIDE_CONCURRENCY,
      },
    });

    await notifyGenerationFinished({
      userId,
      workspaceId,
      projectId: updated.projectId,
      deckId,
      status,
      projectName,
      partial,
      creditsChargedSoFar: updated.creditsChargedSoFar,
      error: allFailed ? 'All slides failed' : null,
    });
  } catch (err) {
    logger.error?.('processDeckGeneration failed', err) ||
      console.error('processDeckGeneration failed', err);
    try {
      await presentationDao.updateDeck(deckId, {
        status: 'FAILED',
        partial: true,
        generationMetrics: {
          error: err.message,
          finishedAt: new Date().toISOString(),
        },
      });
      await notifyGenerationFinished({
        userId,
        workspaceId,
        projectId,
        deckId,
        status: 'FAILED',
        projectName,
        partial: true,
        error: err.message,
      });
    } catch {
      // ignore secondary failures
    }
  }
}

async function generateOutline({
  workspaceId,
  presentationId,
  userId,
  source,
  prompt,
  outlineText,
  file,
  documentText,
  slideCount = 12,
  density = 'balanced',
  locale = 'en',
}) {
  await presentationRateLimit.assertGenerateAllowed(userId, workspaceId);
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });

  let sourceText = '';
  if (source === 'prompt') {
    sourceText = String(prompt || '').trim();
  } else if (source === 'outline') {
    sourceText = String(outlineText || '').trim();
  } else if (source === 'document') {
    if (documentText && String(documentText).trim()) {
      sourceText = String(documentText).trim();
    } else if (file) {
      const parsed = await documentParse.extractTextFromUpload(file);
      sourceText = parsed.text;
    } else {
      throw new AppError(messages.PRESENTATION_DOCUMENT_UNPARSEABLE, 400);
    }
  } else {
    throw new AppError('Invalid outline source', 400);
  }

  if (!sourceText) {
    throw new AppError('Outline source text is required', 400);
  }

  try {
    await moderateText(sourceText);
  } catch (err) {
    if (err instanceof AppError && err.statusCode === 400) {
      throw new AppError(messages.PRESENTATION_CONTENT_BLOCKED, 400);
    }
    throw err;
  }

  const estimate = presentationCredit.estimateOutlineAc();
  await presentationCredit.assertAfford(workspaceId, userId, estimate.athenaCredits);

  const outlinePrompt = getOutlinePrompt();
  const llmResult = await chatJson({
    system: outlinePrompt.buildSystem(),
    user: outlinePrompt.buildUser({
      sourceText,
      slideCount,
      density,
      locale,
    }),
    model: DEFAULT_OUTLINE_MODEL,
  });

  const outline = normalizeOutline(llmResult.data, { slideCount, density, locale });

  const chargeResult = await presentationCredit.chargeOutlineReconcile({
    workspaceId,
    userId,
    deckId: deck.id,
    usage: llmResult.usage,
    idempotencyKey: `ppt:outline:${deck.id}:${hashPayload([source, sourceText.slice(0, 200), String(slideCount), density])}`,
    metadata: { projectId: project.id },
  });
  await trackCharge(deck.id, chargeResult);

  const updated = await presentationDao.updateDeck(deck.id, {
    outline,
    locale: locale || deck.locale || 'en',
    promptBundleVersion: PROMPT_BUNDLE_VERSION,
    status: deck.status === 'READY' ? 'DRAFT' : deck.status,
  });

  return {
    outline: updated.outline,
    deckId: updated.id,
    promptBundleVersion: updated.promptBundleVersion,
    creditsCharged: chargeResult.skipped ? 0 : chargeResult.charged || chargeResult.pricing?.athenaCredits || 0,
  };
}

async function updateOutline({ presentationId, outline, workspaceId }) {
  const { deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  if (deck.status === 'GENERATING') {
    throw new AppError(messages.PRESENTATION_ALREADY_GENERATING, 409);
  }

  const normalized = normalizeOutline(outline, {
    slideCount: outline.slideCount,
    density: outline.density,
    locale: outline.locale || deck.locale,
  });

  const updated = await presentationDao.updateDeck(deck.id, {
    outline: normalized,
    ...(outline.locale ? { locale: outline.locale } : {}),
  });
  return { outline: updated.outline, deckId: updated.id };
}

async function setTheme({ presentationId, themeId, themeTokens, workspaceId }) {
  const { deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  const resolved = themeService.resolveThemeTokens({ themeId, themeTokens });
  const updated = await presentationDao.updateDeck(deck.id, {
    themeTokens: resolved,
  });
  return {
    deckId: updated.id,
    themeId: themeId || null,
    themeTokens: updated.themeTokens,
  };
}

async function startGenerate({
  workspaceId,
  presentationId,
  userId,
  density = 'balanced',
  overwriteManualEdits = false,
  requestHash,
}) {
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });

  if (deck.status === 'GENERATING') {
    throw new AppError(messages.PRESENTATION_ALREADY_GENERATING, 409);
  }
  if (!deck.outline || !Array.isArray(deck.outline.slides) || deck.outline.slides.length === 0) {
    throw new AppError(messages.PRESENTATION_OUTLINE_REQUIRED, 400);
  }

  await presentationRateLimit.assertGenerateAllowed(userId, workspaceId);

  const outlineSlides = deck.outline.slides;
  const slideCount = outlineSlides.length;
  const estimate = presentationCredit.estimateGenerateCost(slideCount);
  await presentationCredit.assertAfford(workspaceId, userId, estimate.athenaCredits);

  const deckRequestHash =
    requestHash ||
    hashPayload([
      'GENERATE_DECK',
      deck.id,
      PROMPT_BUNDLE_VERSION,
      density,
      crypto.createHash('sha256').update(JSON.stringify(deck.outline)).digest('hex'),
      String(overwriteManualEdits),
    ]);

  // Preserve manually edited slides unless overwrite
  const existing = deck.slides || [];
  if (overwriteManualEdits) {
    await presentationDao.deleteSlidesByDeckId(deck.id);
  } else {
    const toDelete = existing.filter((s) => !s.manuallyEdited).map((s) => s.id);
    if (toDelete.length) {
      await prisma.slide.deleteMany({ where: { id: { in: toDelete } } });
    }
  }

  const preserved = overwriteManualEdits
    ? []
    : existing.filter((s) => s.manuallyEdited);
  const preservedOrders = new Set(preserved.map((s) => s.order));

  const pendingData = outlineSlides
    .filter((s) => !preservedOrders.has(Number(s.order)))
    .map((s) => ({
      order: Number(s.order),
      contentType: s.suggestedContentType || null,
      content: null,
      imageRef: null,
      status: 'PENDING',
      manuallyEdited: false,
    }));

  if (pendingData.length) {
    await presentationDao.createSlides(deck.id, pendingData);
  }

  await presentationDao.updateDeck(deck.id, {
    status: 'GENERATING',
    partial: false,
    creditsChargedSoFar: overwriteManualEdits ? 0 : deck.creditsChargedSoFar,
    generationMetrics: {
      startedAt: new Date().toISOString(),
      requestHash: deckRequestHash,
      density,
      estimatedCredits: estimate.athenaCredits,
    },
    promptBundleVersion: PROMPT_BUNDLE_VERSION,
  });

  setImmediate(() => {
    processDeckGeneration({
      workspaceId,
      deckId: deck.id,
      userId,
      density,
      projectId: project.id,
      projectName: project.name,
    });
  });

  return {
    deckId: deck.id,
    status: 'GENERATING',
    slideCount,
    estimatedCredits: estimate.athenaCredits,
  };
}

async function getStatus(presentationId, workspaceId) {
  const { deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  const slides = deck.slides || [];
  const terminal = slides.filter((s) => s.status === 'READY' || s.status === 'FAILED');
  const remaining = slides.filter((s) => s.status === 'PENDING' || s.status === 'GENERATING');
  const progress = slides.length ? Math.round((terminal.length / slides.length) * 100) : 0;
  const etaSeconds = remaining.length * 4;

  return {
    deckId: deck.id,
    status: deck.status,
    partial: Boolean(deck.partial),
    progress,
    etaSeconds,
    creditsChargedSoFar: deck.creditsChargedSoFar || 0,
    slides: slides.map((s) => ({
      id: s.id,
      order: s.order,
      status: s.status,
      contentType: s.contentType,
      layoutId: s.layoutId,
      manuallyEdited: s.manuallyEdited,
    })),
  };
}

async function regenerateSlide({
  workspaceId,
  presentationId,
  slideId,
  userId,
  target = 'all',
  overwriteManualEdits = true,
}) {
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  const slide = await presentationDao.findSlideById(slideId);
  if (!slide || slide.deckId !== deck.id) {
    throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  }
  if (slide.manuallyEdited && !overwriteManualEdits) {
    throw new AppError('Slide has manual edits; set overwriteManualEdits to regenerate', 409);
  }

  await presentationRateLimit.assertRegenerateAllowed(userId, workspaceId);

  const estimateSlides = target === 'image' ? 0 : 1;
  const estimateImages = target === 'content' ? 0 : 1;
  const estimatedAc =
    estimateSlides * presentationCredit.getFlatAc(PPT_FEATURE.SLIDE_CONTENT) +
    estimateImages * presentationCredit.getFlatAc(PPT_FEATURE.IMAGE_PATH_A);
  if (estimatedAc > 0) {
    await presentationCredit.assertAfford(workspaceId, userId, estimatedAc);
  }

  // Reset fields based on target
  const reset = { status: 'PENDING' };
  if (target === 'all' || target === 'content') {
    reset.content = null;
    reset.layoutId = null;
  }
  if (target === 'all' || target === 'image') {
    reset.imageRef = null;
  }
  await presentationDao.updateSlide(slideId, reset);

  const ctx = {
    workspaceId,
    deckId: deck.id,
    userId,
    density: deck.outline?.density || 'balanced',
    locale: deck.locale || 'en',
    outline: deck.outline,
    themeTokens: deck.themeTokens || {},
    projectName: project.name,
    projectId: project.id,
    previousLayoutId: null,
    regenerateTarget: target,
  };

  // For image-only, keep content and skip content LLM by marking duplicate-like path:
  // processSlide always runs content; for image-only restore content after if wiped — we kept content when target=image.
  setImmediate(async () => {
    try {
      const fresh = await presentationDao.findSlideById(slideId);
      if (target === 'image' && fresh) {
        // Minimal path: only images
        await presentationDao.updateSlide(slideId, { status: 'GENERATING' });
        try {
          let content = fresh.content || {};
          let visualNeed = 'photo';
          try {
            const classifyPrompt = getClassifyPrompt();
            const classified = await chatJson({
              system: classifyPrompt.buildSystem(),
              user: classifyPrompt.buildUser({
                slideContent: content,
                title: content?.title,
              }),
              temperature: 0.2,
            });
            visualNeed = classified.data?.visual_need || visualNeed;
          } catch {
            // keep default
          }
          let brief = null;
          try {
            const briefPrompt = getImageBriefPrompt();
            const briefResult = await chatJson({
              system: briefPrompt.buildSystem(),
              user: briefPrompt.buildUser({
                slideTitle: content?.title,
                slideContent: content,
                themeImageStyle: ctx.themeTokens?.imageStyle,
                themeColorTreatment: ctx.themeTokens?.colorTreatment,
              }),
            });
            brief = briefResult.data;
          } catch {
            brief = { subject: content?.title, search_query: content?.title };
          }
          const imageResult = await resolveSlideImage({
            ctx,
            slide: fresh,
            content,
            visualNeed,
            brief,
            pathBSpec: content?.pathBSpec,
          });
          await presentationDao.updateSlide(slideId, {
            status: 'READY',
            imageRef: imageResult.imageRef,
          });
        } catch (err) {
          await presentationDao.updateSlide(slideId, {
            status: 'FAILED',
            imageRef: { source: 'none', error: err.message },
          });
        }
        return;
      }

      await processSlide(ctx, fresh || slide);
    } catch (err) {
      console.error('regenerateSlide failed', err);
    }
  });

  return {
    slideId,
    status: 'GENERATING',
    target,
    estimatedCredits: estimatedAc,
  };
}

async function patchSlide({ workspaceId, presentationId, slideId, patch }) {
  const { deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  const slide = await presentationDao.findSlideById(slideId);
  if (!slide || slide.deckId !== deck.id) {
    throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  }

  const data = {
    manuallyEdited: patch.manuallyEdited !== undefined ? patch.manuallyEdited : true,
  };
  if (patch.content !== undefined) data.content = patch.content;
  if (patch.layoutId !== undefined) data.layoutId = patch.layoutId;
  if (patch.contentType !== undefined) data.contentType = patch.contentType;
  if (patch.imageRef !== undefined) data.imageRef = patch.imageRef;
  if (patch.elements !== undefined) data.elements = patch.elements;

  const updated = await presentationDao.updateSlide(slideId, data);
  return { slide: updated };
}

module.exports = {
  withTimeout,
  generateOutline,
  updateOutline,
  setTheme,
  startGenerate,
  processDeckGeneration,
  processSlide,
  getStatus,
  regenerateSlide,
  patchSlide,
  loadPresentationDeck,
  PPT_SLIDE_CONCURRENCY,
  CONTENT_TIMEOUT_MS,
};
