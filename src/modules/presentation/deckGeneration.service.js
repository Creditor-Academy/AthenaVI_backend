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
const { layoutSlotsToElements, injectBrandLogo } = require('./layoutToElements');
const { AI_SLIDE_MAX } = require('./presentation.constants');
const generationFlowService = require('./generationFlow.service');
const brandKitService = require('../brandKit/brandKit.service');

/** Prefer pack/slide author image brief when present. */
function resolveAuthorImagePrompt(content) {
  if (!content || typeof content !== 'object') return '';
  const direct = typeof content.imagePrompt === 'string' ? content.imagePrompt.trim() : '';
  if (direct) return direct;
  const hints = content.generationHints;
  if (hints && typeof hints === 'object') {
    const style =
      typeof hints.imagePromptStyle === 'string' ? hints.imagePromptStyle.trim() : '';
    if (style) return style;
  }
  return '';
}

const CONTENT_TIMEOUT_MS =
  Number(process.env.PPT_SLIDE_CONTENT_TIMEOUT_MS) > 0
    ? Number(process.env.PPT_SLIDE_CONTENT_TIMEOUT_MS)
    : 45000;

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

async function resolveLayoutTemplates(contentType, { layoutIdWhitelist = null } = {}) {
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

  const allow = Array.isArray(layoutIdWhitelist) ? new Set(layoutIdWhitelist.filter(Boolean)) : null;
  if (allow && allow.size > 0) {
    const filtered = (templates || []).filter((t) => allow.has(t.schema?.layout_id || t.id));
    if (filtered.length > 0) return filtered;
    // Fallback: load whitelist layouts by id even if contentType mismatch
    const byIds = await presentationDao.findLayoutsByLayoutIds([...allow]);
    if (byIds.length) return byIds;
  }

  return templates || [];
}

function scoreBrandPhoto(photo, searchQuery) {
  const hay = `${photo.name || ''} ${photo.role || ''}`.toLowerCase();
  const tokens = String(searchQuery || '')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 2);
  if (!tokens.length) return 0;
  return tokens.reduce((score, t) => (hay.includes(t) ? score + 1 : score), 0);
}

function pickBrandPhoto(themeTokens, searchQuery) {
  const photos = themeTokens?.brand?.photos;
  if (!Array.isArray(photos) || photos.length === 0) return null;
  let best = photos[0];
  let bestScore = -1;
  for (const photo of photos) {
    if (!photo?.url && !photo?.s3Key) continue;
    const score = scoreBrandPhoto(photo, searchQuery);
    if (score > bestScore) {
      bestScore = score;
      best = photo;
    }
  }
  return best || null;
}

async function loadPackAndBrandForGenerate({ workspaceId, deck, flowCtx }) {
  const metricsPack =
    deck.generationMetrics && typeof deck.generationMetrics === 'object'
      ? deck.generationMetrics.deckPack
      : null;

  const packId = flowCtx.packId || metricsPack?.packId || null;
  const brandKitId = flowCtx.brandKitId || metricsPack?.brandKitId || null;

  let pack = null;
  let layoutIdWhitelist = null;
  let packDefaults = null;

  if (packId) {
    pack = await presentationDao.findTemplateById(packId);
    if (pack && pack.type === 'DECK_PACK' && pack.isActive) {
      const defaults = pack.schema?.generationDefaults || {};
      layoutIdWhitelist =
        Array.isArray(defaults.layoutWhitelist) && defaults.layoutWhitelist.length
          ? defaults.layoutWhitelist
          : (pack.schema?.slides || []).map((s) => s.layout_id).filter(Boolean);
      packDefaults = defaults;
      if (pack.schema?.narrative?.summary || pack.schema?.narrative?.arc) {
        const narr = [
          pack.schema.narrative.arc ? `Deck narrative arc: ${pack.schema.narrative.arc}` : null,
          pack.schema.narrative.summary
            ? `Deck narrative: ${pack.schema.narrative.summary}`
            : null,
        ]
          .filter(Boolean)
          .join('\n');
        flowCtx.wizardBrief = [flowCtx.wizardBrief, narr].filter(Boolean).join('\n');
        flowCtx.packNarrative = pack.schema.narrative;
      }
      if (defaults.contentDistribution) {
        flowCtx.contentDistribution = defaults.contentDistribution;
      }
      flowCtx.packSlides = pack.schema?.slides || [];
      if (!flowCtx.baseTemplateBias && packDefaults?.baseTemplate) {
        flowCtx.baseTemplateBias = generationFlowService.baseTemplateBias(
          packDefaults.baseTemplate
        );
      }
      if (packDefaults?.preferVisuals != null && flowCtx.preferVisuals == null) {
        flowCtx.preferVisuals = Boolean(packDefaults.preferVisuals);
      }
      if (packDefaults?.imageStyle && !flowCtx.imageStylePhrase) {
        flowCtx.imageStylePhrase = generationFlowService.resolveImageStylePhrase(
          packDefaults.imageStyle,
          null
        );
      }
      if (!flowCtx.themeTokens && pack.schema?.themeId) {
        try {
          flowCtx.themeTokens = themeService.resolveThemeTokens({
            themeId: pack.schema.themeId,
          });
        } catch {
          // keep existing
        }
      }
    } else {
      pack = null;
    }
  }

  if (brandKitId) {
    try {
      const kitTokens = await brandKitService.loadKitThemeTokens(workspaceId, brandKitId);
      flowCtx.themeTokens = kitTokens;
      const voiceBrief = brandKitService.buildBrandVoiceBrief(kitTokens);
      if (voiceBrief) {
        flowCtx.wizardBrief = [flowCtx.wizardBrief, voiceBrief].filter(Boolean).join('\n');
      }
    } catch (err) {
      logger.warn('Brand kit resolve failed during generate', { brandKitId, error: err.message });
    }
  }

  return {
    pack,
    packId: pack?.id || null,
    brandKitId,
    layoutIdWhitelist,
  };
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

function detectPreferVisuals(text) {
  const t = String(text || '').toLowerCase();
  if (
    /\b(text[\s-]?only|no images|without images|no visuals|without visuals|no pictures)\b/.test(t)
  ) {
    return false;
  }
  // AI PPT default: generate supporting visuals unless explicitly opted out
  return true;
}

/**
 * Force photo/illustration visuals for most slides when preferVisuals is on.
 * Chart / path_b keep their specialized modes.
 */
function applyVisualPolicy({ visualNeed, contentType, preferVisuals, baseTemplateBias: bias }) {
  const type = String(contentType || 'bullet_list').toLowerCase();
  let need = String(visualNeed || 'none').toLowerCase();

  if (need === 'path_b') {
    return { visualNeed: 'path_b', contentType: type, layoutContentType: type, preferImageSlot: false };
  }

  if (type === 'chart' || need === 'chart') {
    return {
      visualNeed: 'chart',
      contentType: 'chart',
      layoutContentType: 'chart',
      preferImageSlot: false,
    };
  }

  if (!preferVisuals) {
    return {
      visualNeed: need || 'none',
      contentType: type,
      layoutContentType: type,
      preferImageSlot: false,
    };
  }

  if (need === 'none' || need === 'icon' || need === 'diagram_template' || !need) {
    need = type === 'quote' || type === 'stat' ? 'illustration' : 'photo';
  }

  let layoutContentType = type;
  if (['bullet_list', 'comparison', 'stat', 'timeline', 'team', 'section_divider'].includes(type)) {
    layoutContentType = 'image+text';
  } else if (type === 'title' || type === 'agenda' || type === 'closing' || type === 'quote') {
    layoutContentType = type;
  } else if (type === 'image+text') {
    layoutContentType = 'image+text';
  } else {
    layoutContentType = 'image+text';
  }

  // Soft bias from wizard baseTemplate
  if (bias?.preferredContentTypes?.length) {
    const preferred = bias.preferredContentTypes.map((t) => String(t).toLowerCase());
    if (preferred.includes('image+text') && layoutContentType !== 'chart') {
      layoutContentType = 'image+text';
    } else if (preferred.includes(type)) {
      layoutContentType = type;
    }
  }

  return {
    visualNeed: need,
    contentType: type === 'image+text' ? 'image+text' : type,
    layoutContentType,
    preferImageSlot: bias?.preferImageSlot !== false,
  };
}

function withImageStatus(imageRef, status, extra = {}) {
  if (!imageRef || typeof imageRef !== 'object') {
    return { source: 'none', status, error: null, ...extra };
  }
  return {
    ...imageRef,
    status,
    error: extra.error !== undefined ? extra.error : imageRef.error ?? null,
    ...extra,
  };
}

function sanitizePresentationTitle(raw) {
  const FALLBACK = 'Untitled Presentation';
  let title = String(raw || '').trim().replace(/\s+/g, ' ');
  if (!title) return FALLBACK;

  const lower = title.toLowerCase();
  if (
    /^(create|make|build|write|generate)\s+(a\s+|an\s+|me\s+)?(presentation|deck|ppt|slides?)\b/.test(
      lower
    ) ||
    /^please\s+(create|make|build|write|generate)\b/.test(lower)
  ) {
    return FALLBACK;
  }

  const words = title.split(/\s+/).filter(Boolean);
  if (words.length > 12) {
    title = words.slice(0, 10).join(' ');
  }
  if (title.length > 255) title = title.slice(0, 255).trim();
  return title || FALLBACK;
}

function normalizeOutline(data, { slideCount, density, locale, sourceText } = {}) {
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

  const sourcePrompt = sourceText != null ? String(sourceText).trim().slice(0, 8000) : data?.sourcePrompt || null;

  return {
    title: sanitizePresentationTitle(data?.title),
    slideCount: requested || Math.min(AI_SLIDE_MAX, normalizedSlides.length || 12),
    density: density || 'balanced',
    locale: locale || 'en',
    slides: normalizedSlides,
    sourcePrompt: sourcePrompt || null,
    preferVisuals:
      data?.preferVisuals !== undefined ? Boolean(data.preferVisuals) : detectPreferVisuals(sourcePrompt),
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
      status: 'ready',
      error: null,
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
    status: 'ready',
    error: null,
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
  const imageSource = ctx.imageSource || null;

  if (imageSource === 'none') {
    return {
      imageRef: withImageStatus(
        { source: 'none', visual_need: visualNeed || 'none', brief: brief || null },
        'skipped',
        { reason: 'imageType=none' }
      ),
      chargedFeature: null,
      cacheHit: false,
      visionScore: null,
    };
  }

  if (imageSource === 'placeholder') {
    try {
      const ph = await generationFlowService.ensurePlaceholderImage();
      return {
        imageRef: withImageStatus(
          {
            source: 'placeholder',
            url: ph.url,
            s3Key: ph.s3Key,
            brief: brief || null,
            visual_need: visualNeed || 'photo',
          },
          'ready'
        ),
        chargedFeature: null,
        cacheHit: false,
        visionScore: null,
      };
    } catch (err) {
      return {
        imageRef: withImageStatus(
          { source: 'none', brief: brief || null },
          'failed',
          { error: err.message }
        ),
        chargedFeature: null,
        cacheHit: false,
        visionScore: null,
      };
    }
  }

  const need = String(visualNeed || 'none').toLowerCase();

  if (need === 'none' || need === 'chart' || need === 'icon' || need === 'diagram_template') {
    return {
      imageRef: withImageStatus(
        { source: 'none', visual_need: need, brief: brief || null },
        'skipped',
        { reason: `visual_need=${need}` }
      ),
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
        imageRef: withImageStatus(slide.imageRef || { source: 'path_b', brief }, 'ready'),
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

  // photo / illustration / default → brand photos then stock then Path A
  const searchQuery =
    brief?.search_query || brief?.searchQuery || brief?.subject || content?.title || 'presentation visual';

  const brandPhoto = pickBrandPhoto(ctx.themeTokens, searchQuery);
  if (brandPhoto && (brandPhoto.url || brandPhoto.s3Key)) {
    let url = brandPhoto.url || null;
    if (!url && brandPhoto.s3Key) {
      try {
        url = await s3Service.getPresignedGetUrl(brandPhoto.s3Key, 3600);
      } catch {
        url = s3Service.buildPublicUrl(brandPhoto.s3Key);
      }
    }
    if (url) {
      return {
        imageRef: withImageStatus(
          {
            source: 'brand_kit',
            url,
            s3Key: brandPhoto.s3Key || null,
            mediaId: brandPhoto.id || null,
            brief: brief || null,
            visual_need: visualNeed || 'photo',
          },
          'ready'
        ),
        chargedFeature: null,
        cacheHit: false,
        visionScore: null,
      };
    }
  }

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
      imageRef: withImageStatus(
        {
          source: cached.source || 'ai_gen',
          url: cached.url,
          s3Key: cached.s3Key,
          brief,
          cacheHit: true,
        },
        'ready'
      ),
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
      imageRef: withImageStatus(slide.imageRef || { source: 'none', brief }, slide.imageRef?.url ? 'ready' : 'skipped'),
      chargedFeature: null,
      cacheHit: false,
      visionScore: job.visionScore ?? null,
      skippedCharge: true,
    };
  }

  const started = Date.now();
  try {
    let imageRef = null;
    let visionScore = null;
    const styleBits = [
      ctx.imageStylePhrase || ctx.themeTokens?.imageStyle || '',
      ctx.themeTokens?.colorTreatment || '',
    ]
      .filter(Boolean)
      .join('. ');

    const buildAiPrompt = () =>
      [
        brief?.subject || searchQuery,
        brief?.composition || '',
        styleBits,
        Array.isArray(brief?.negative_terms)
          ? `Avoid: ${brief.negative_terms.join(', ')}`
          : '',
      ]
        .filter(Boolean)
        .join('. ');

    // stock/web: stock only. ai (default): AI-first.
    if (imageSource === 'stock') {
      imageRef = await tryStockImage({
        query: searchQuery,
        workspaceId: ctx.workspaceId,
        deckId: ctx.deckId,
        slideId: slide.id,
        brief,
      });
      if (imageRef?.url) {
        try {
          const vision = await checkImageRelevance({
            imageUrl: imageRef.url,
            slideTitle: content?.title || '',
            slideText: slideTextForVision(content),
            briefSubject: brief?.subject || searchQuery,
          });
          visionScore = vision.score;
          if (!vision.relevant) imageRef = null;
        } catch {
          // keep stock
        }
      }
      if (!imageRef) {
        throw new AppError('Stock image search returned no suitable visual', 502);
      }
    } else {
      // AI-first (imageType=ai or unset)
      try {
        imageRef = await generateAiImageRef({
          prompt: buildAiPrompt(),
          workspaceId: ctx.workspaceId,
          deckId: ctx.deckId,
          slideId: slide.id,
          brief,
          source: 'ai_gen',
        });
      } catch (aiErr) {
        imageRef = await tryStockImage({
          query: searchQuery,
          workspaceId: ctx.workspaceId,
          deckId: ctx.deckId,
          slideId: slide.id,
          brief,
        });
        if (!imageRef) throw aiErr;
      }
      if (imageRef?.url) {
        try {
          const vision = await checkImageRelevance({
            imageUrl: imageRef.url,
            slideTitle: content?.title || '',
            slideText: slideTextForVision(content),
            briefSubject: brief?.subject || searchQuery,
          });
          visionScore = vision.score;
        } catch {
          // ignore
        }
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
      imageRef: withImageStatus(imageRef, 'ready'),
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

function wordCount(text) {
  return String(text || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean).length;
}

function truncateWords(text, max) {
  if (!max || max < 1) return text;
  const parts = String(text || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (parts.length <= max) return text;
  return parts.slice(0, max).join(' ');
}

function applyGenerationHints(content, hints) {
  if (!content || !hints) return content;
  const next = { ...content };
  if (hints.maxTitleWords && next.title) {
    next.title = truncateWords(next.title, hints.maxTitleWords);
  }
  if (hints.maxBodyWords && next.body) {
    next.body = truncateWords(next.body, hints.maxBodyWords);
  }
  if (hints.itemCountMax && Array.isArray(next.bullets) && next.bullets.length > hints.itemCountMax) {
    next.bullets = next.bullets.slice(0, hints.itemCountMax);
  }
  if (hints.itemCountMax && Array.isArray(next.stats) && next.stats.length > hints.itemCountMax) {
    next.stats = next.stats.slice(0, hints.itemCountMax);
  }
  return next;
}

function slotConstraintsFromLayout(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots
    .filter((s) => {
      const role = String(s.role || '').toLowerCase();
      return !['decoration', 'background', 'image', 'chart', 'table', 'divider'].includes(role);
    })
    .map((s) => {
      const ty = s.typography || {};
      return {
        id: s.id,
        role: s.role || null,
        max_lines: s.max_lines || null,
        max_words: s.max_words || null,
        fontHint: ty.fontSize
          ? `~${ty.fontSize}px${ty.fontWeight ? ` weight ${ty.fontWeight}` : ''}`
          : s.role
            ? `role ${s.role}`
            : null,
      };
    });
}

function applyContentDistribution(contentType, ctx) {
  const dist = ctx.contentDistribution;
  if (!dist || typeof dist !== 'object') return contentType;
  let next = contentType;
  const history = Array.isArray(ctx.contentTypeHistory) ? ctx.contentTypeHistory : [];
  const maxBullet = dist.maxConsecutiveBulletSlides;
  if (
    maxBullet != null &&
    String(next).toLowerCase() === 'bullet_list' &&
    history.slice(-Number(maxBullet)).every((t) => String(t).toLowerCase() === 'bullet_list')
  ) {
    next = 'image+text';
  }
  return next;
}

function packSlideMeta(ctx, slideOrder) {
  const slides = Array.isArray(ctx.packSlides) ? ctx.packSlides : [];
  return (
    slides.find((s) => Number(s.order) === Number(slideOrder)) ||
    slides[Number(slideOrder) - 1] ||
    null
  );
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
    const packMeta = packSlideMeta(ctx, slide.order);
    const slideIntent =
      packMeta?.intent ||
      (slide.content && slide.content.intent) ||
      null;
    const generationHints =
      packMeta?.generationHints ||
      (slide.content && slide.content.generationHints) ||
      null;
    const designTokens =
      packMeta?.designTokens ||
      (slide.content && slide.content.designTokens) ||
      null;

    // Prefer pack layout schema early for slot constraints when fixed pack layout
    let earlyLayoutSchema = null;
    if (packMeta?.layout_id) {
      const early = await presentationDao.findLayoutsByLayoutIds([packMeta.layout_id]);
      earlyLayoutSchema = early[0]?.schema || null;
    }

    // 1) Content LLM
    const contentPrompt = getSlideContentPrompt();
    const resolvedTitle =
      outlineSlide.title ||
      (slide.content && slide.content.title) ||
      ctx.userPrompt ||
      '';
    const resolvedSummary = outlineSlide.summary || ctx.userPrompt || '';

    const contentHash = hashPayload([
      'CONTENT',
      slide.id,
      PROMPT_BUNDLE_VERSION,
      ctx.density,
      resolvedTitle,
      resolvedSummary,
      outlineSlide.suggestedContentType,
      ctx.userPrompt || '',
      slideIntent || '',
    ]);
    const contentJob = await beginJob({
      slideId: slide.id,
      jobType: 'CONTENT',
      requestHash: contentHash,
      promptVersion: PROMPT_BUNDLE_VERSION,
      model: DEFAULT_SLIDE_MODEL,
    });

    let content = slide.content && typeof slide.content === 'object' ? { ...slide.content } : null;
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
              title: resolvedTitle || content?.title,
              summary: resolvedSummary,
              suggestedContentType:
                packMeta?.contentType ||
                outlineSlide.suggestedContentType ||
                slide.contentType,
              previousSlideTitle: prev?.title,
              nextSlideTitle: next?.title,
              locale: ctx.locale || 'en',
              wizardBrief: ctx.wizardBrief || '',
              intent: slideIntent,
              generationHints,
              slotConstraints: slotConstraintsFromLayout(earlyLayoutSchema),
            }),
            model: DEFAULT_SLIDE_MODEL,
          }),
          CONTENT_TIMEOUT_MS,
          'Slide content generation'
        );
        content = { ...(content || {}), ...llmResult.data };
        content = applyGenerationHints(content, generationHints);
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
        title: resolvedTitle || outlineSlide.title || `Slide ${slide.order}`,
        bullets: [],
        notes: '',
      };
    }

    // 2) Classify
    let contentType = content?.content_type || slide.contentType || outlineSlide.suggestedContentType;
    let visualNeed = content?.visual_need || null;
    const preferVisuals = ctx.preferVisuals !== false;

    const classifyPrompt = getClassifyPrompt();
    const classifyHash = hashPayload([
      'CLASSIFY',
      slide.id,
      PROMPT_BUNDLE_VERSION,
      crypto.createHash('sha256').update(JSON.stringify(content || {})).digest('hex'),
      preferVisuals ? 'viz1' : 'viz0',
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
            preferVisuals,
            wizardBrief: ctx.wizardBrief || '',
          }),
          model: DEFAULT_SLIDE_MODEL,
          temperature: 0.2,
        });
        contentType = classified.data?.content_type || contentType || 'bullet_list';
        visualNeed = classified.data?.visual_need || visualNeed || (preferVisuals ? 'photo' : 'none');
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
        visualNeed = visualNeed || (preferVisuals ? 'photo' : 'none');
      }
    } else {
      contentType = contentType || 'bullet_list';
      visualNeed = visualNeed || (preferVisuals ? 'photo' : 'none');
    }

    const policy = applyVisualPolicy({
      visualNeed,
      contentType,
      preferVisuals,
      baseTemplateBias: ctx.baseTemplateBias || null,
    });
    visualNeed = policy.visualNeed;
    contentType = applyContentDistribution(policy.contentType, ctx);
    policy.layoutContentType = contentType;
    if (content && typeof content === 'object') {
      content.visual_need = visualNeed;
      content.content_type = contentType;
      if (slideIntent) content.intent = slideIntent;
      if (designTokens) content.designTokens = designTokens;
      if (generationHints) content.generationHints = generationHints;
    }
    if (!Array.isArray(ctx.contentTypeHistory)) ctx.contentTypeHistory = [];
    ctx.contentTypeHistory.push(contentType);

    // 3) Layout select + QA
    let layoutId = null;
    let template = null;
    const existingLayoutId = slide.layoutId || null;
    if (
      ctx.preferExistingPackLayout &&
      existingLayoutId &&
      Array.isArray(ctx.layoutIdWhitelist) &&
      ctx.layoutIdWhitelist.includes(existingLayoutId)
    ) {
      const existingLayouts = await presentationDao.findLayoutsByLayoutIds([existingLayoutId]);
      template = existingLayouts[0] || null;
      layoutId = existingLayoutId;
    }
    if (!template) {
      const templates = await resolveLayoutTemplates(policy.layoutContentType, {
        layoutIdWhitelist: ctx.layoutIdWhitelist || null,
      });
      ({ layoutId, template } = selectLayout({
        contentType: policy.layoutContentType,
        content,
        previousLayoutId: ctx.previousLayoutId || null,
        templates,
        preferImageSlot: policy.preferImageSlot,
      }));
    }
    ctx.previousLayoutId = layoutId;

    const qa = validateSlide({
      content,
      layoutSchema: template?.schema || null,
    });
    content = qa.content;
    if (content && typeof content === 'object') {
      content.visual_need = visualNeed;
      content.content_type = contentType;
    }

    // 4) Image brief when needed
    let brief = null;
    const skipImagePipeline =
      ctx.imageSource === 'none' || ctx.imageSource === 'placeholder';
    const needsBrief =
      !skipImagePipeline &&
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
              themeImageStyle: ctx.imageStylePhrase || ctx.themeTokens?.imageStyle,
              themeColorTreatment: ctx.themeTokens?.colorTreatment,
              wizardBrief: ctx.wizardBrief || '',
              authorImagePrompt: resolveAuthorImagePrompt(content),
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
          const authorBrief = resolveAuthorImagePrompt(content);
          brief = {
            subject: authorBrief || content?.title || outlineSlide.title,
            search_query: authorBrief || content?.title || outlineSlide.title,
            image_type: visualNeed === 'illustration' ? 'illustration' : 'photo',
          };
        }
      }
    }

    // 5) Images
    let imageRef = withImageStatus({ source: 'none' }, 'skipped');
    try {
      const imageResult = await resolveSlideImage({
        ctx,
        slide,
        content,
        visualNeed,
        brief,
        pathBSpec: content?.pathBSpec,
      });
      imageRef = withImageStatus(
        imageResult.imageRef || imageRef,
        imageResult.imageRef?.url ? 'ready' : imageResult.imageRef?.status || 'skipped'
      );
    } catch (imgErr) {
      logger.warn?.('presentation_slide_image_failed', {
        slideId: slide.id,
        error: imgErr.message,
      });
      // Explicit failure — do not silently pretend there was no visual need
      imageRef = withImageStatus(
        { source: 'none', brief, visual_need: visualNeed },
        'failed',
        { error: imgErr.message }
      );
    }

    const canvasSize = ctx.canvasSize || {};
    let elementsDoc = layoutSlotsToElements(
      template?.schema || { slots: [] },
      content,
      imageRef,
      { width: canvasSize.width, height: canvasSize.height },
      {
        themeTokens: ctx.themeTokens || null,
        designTokens,
      }
    );
    const logo = brandKitService.pickLogoForBackground(ctx.themeTokens);
    elementsDoc = injectBrandLogo(elementsDoc, logo, { contentType });

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
      imageRef: withImageStatus({ source: 'none' }, 'failed', { error: err.message }),
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
  flowCtx = null,
}) {
  try {
    const deck = await presentationDao.findDeckById(deckId);
    if (!deck) return;

    const resolvedFlow =
      flowCtx ||
      generationFlowService.resolveFlowToGenerateCtx(deck.generationMetrics?.generationFlow, {
        topLevelDensity: density,
      });

    const preferVisuals =
      resolvedFlow.preferVisuals != null
        ? resolvedFlow.preferVisuals
        : deck.outline?.preferVisuals !== undefined
          ? Boolean(deck.outline.preferVisuals)
          : detectPreferVisuals(deck.outline?.sourcePrompt);

    const packBrand = await loadPackAndBrandForGenerate({
      workspaceId,
      deck,
      flowCtx: resolvedFlow,
    });

    const ctx = {
      workspaceId,
      deckId,
      userId,
      density: resolvedFlow.density || density || deck.outline?.density || 'balanced',
      locale: resolvedFlow.locale || deck.locale || 'en',
      outline: deck.outline,
      themeTokens: resolvedFlow.themeTokens || deck.themeTokens || {},
      projectName,
      projectId: projectId || deck.projectId,
      previousLayoutId: null,
      userPrompt: resolvedFlow.userPrompt || deck.outline?.sourcePrompt || null,
      preferVisuals,
      wizardBrief: resolvedFlow.wizardBrief || '',
      imageSource: resolvedFlow.imageSource || null,
      imageStylePhrase: resolvedFlow.imageStylePhrase || null,
      canvasSize: resolvedFlow.canvas || generationFlowService.resolveCanvas(deck.aspectRatio),
      baseTemplateBias: resolvedFlow.baseTemplateBias || null,
      layoutIdWhitelist: packBrand.layoutIdWhitelist || resolvedFlow.layoutIdWhitelist || null,
      preferExistingPackLayout: Boolean(packBrand.packId || resolvedFlow.packId),
    };

    if (resolvedFlow.themeTokens) {
      await presentationDao.updateDeck(deckId, { themeTokens: resolvedFlow.themeTokens });
      ctx.themeTokens = resolvedFlow.themeTokens;
    }

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

    const priorMetrics =
      refreshed?.generationMetrics && typeof refreshed.generationMetrics === 'object'
        ? refreshed.generationMetrics
        : {};

    const updated = await presentationDao.updateDeck(deckId, {
      status,
      partial,
      generationMetrics: {
        ...priorMetrics,
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
      const prior = await presentationDao.findDeckById(deckId);
      await presentationDao.updateDeck(deckId, {
        status: 'FAILED',
        partial: true,
        generationMetrics: {
          ...(prior?.generationMetrics && typeof prior.generationMetrics === 'object'
            ? prior.generationMetrics
            : {}),
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

  const outline = normalizeOutline(llmResult.data, {
    slideCount,
    density,
    locale,
    sourceText,
  });

  const chargeResult = await presentationCredit.chargeOutlineReconcile({
    workspaceId,
    userId,
    deckId: deck.id,
    usage: llmResult.usage,
    idempotencyKey: `ppt:outline:${deck.id}:${hashPayload([source, sourceText.slice(0, 200), String(slideCount), density])}`,
    metadata: { projectId: project.id },
  });
  await trackCharge(deck.id, chargeResult);

  // Persist generated deck title on the Project before returning
  const presentation = await presentationDao.updateProjectName(project.id, outline.title);

  const updated = await presentationDao.updateDeck(deck.id, {
    outline,
    locale: locale || deck.locale || 'en',
    promptBundleVersion: PROMPT_BUNDLE_VERSION,
    status: deck.status === 'READY' ? 'DRAFT' : deck.status,
  });

  return {
    presentation: {
      id: presentation.id,
      title: presentation.name,
    },
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

  const normalized = normalizeOutline(
    {
      ...outline,
      sourcePrompt: outline.sourcePrompt || deck.outline?.sourcePrompt || null,
      preferVisuals:
        outline.preferVisuals !== undefined
          ? outline.preferVisuals
          : deck.outline?.preferVisuals,
    },
    {
      slideCount: outline.slideCount,
      density: outline.density,
      locale: outline.locale || deck.locale,
      sourceText: outline.sourcePrompt || deck.outline?.sourcePrompt || null,
    }
  );

  const presentation = await presentationDao.updateProjectName(deck.projectId, normalized.title);

  const updated = await presentationDao.updateDeck(deck.id, {
    outline: normalized,
    ...(outline.locale ? { locale: outline.locale } : {}),
  });
  return {
    presentation: {
      id: presentation.id,
      title: presentation.name,
    },
    outline: updated.outline,
    deckId: updated.id,
  };
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
  density,
  overwriteManualEdits = false,
  requestHash,
  generationFlow = null,
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

  const flowCtx = generationFlowService.resolveFlowToGenerateCtx(generationFlow, {
    topLevelDensity: density || null,
  });
  const packBrand = await loadPackAndBrandForGenerate({ workspaceId, deck, flowCtx });
  flowCtx.layoutIdWhitelist = packBrand.layoutIdWhitelist;
  flowCtx.packId = packBrand.packId;
  flowCtx.brandKitId = packBrand.brandKitId;
  flowCtx.preferExistingPackLayout = Boolean(packBrand.packId);

  const resolvedDensity =
    flowCtx.density || density || deck.outline?.density || 'balanced';

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
      resolvedDensity,
      crypto.createHash('sha256').update(JSON.stringify(deck.outline)).digest('hex'),
      String(overwriteManualEdits),
      flowCtx.generationFlow
        ? crypto
            .createHash('sha256')
            .update(JSON.stringify(flowCtx.generationFlow.selections || {}))
            .digest('hex')
        : '',
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

  if (flowCtx.title) {
    await presentationDao.updateProjectName(project.id, flowCtx.title);
  }

  const outlinePatch = {
    ...(deck.outline || {}),
  };
  if (flowCtx.preferVisuals != null) {
    outlinePatch.preferVisuals = flowCtx.preferVisuals;
  }
  if (flowCtx.userPrompt && !outlinePatch.sourcePrompt) {
    outlinePatch.sourcePrompt = flowCtx.userPrompt;
  }

  const deckUpdate = {
    status: 'GENERATING',
    partial: false,
    creditsChargedSoFar: overwriteManualEdits ? 0 : deck.creditsChargedSoFar,
    outline: outlinePatch,
    generationMetrics: {
      ...(deck.generationMetrics && typeof deck.generationMetrics === 'object'
        ? deck.generationMetrics
        : {}),
      startedAt: new Date().toISOString(),
      requestHash: deckRequestHash,
      density: resolvedDensity,
      estimatedCredits: estimate.athenaCredits,
      generationFlow: flowCtx.generationFlow,
      deckPack: {
        packId: flowCtx.packId || null,
        brandKitId: flowCtx.brandKitId || null,
      },
      resolved: {
        imageSource: flowCtx.imageSource,
        canvas: flowCtx.canvas,
        locale: flowCtx.locale,
        slideCountMeta: flowCtx.slideCountMeta,
        colorTheme: flowCtx.generationFlow?.selections?.colorTheme || null,
        packId: flowCtx.packId || null,
        brandKitId: flowCtx.brandKitId || null,
      },
    },
    promptBundleVersion: PROMPT_BUNDLE_VERSION,
  };
  if (flowCtx.themeTokens) deckUpdate.themeTokens = flowCtx.themeTokens;
  if (flowCtx.canvas?.aspectRatio) deckUpdate.aspectRatio = flowCtx.canvas.aspectRatio;
  if (flowCtx.locale) deckUpdate.locale = flowCtx.locale;

  await presentationDao.updateDeck(deck.id, deckUpdate);

  setImmediate(() => {
    processDeckGeneration({
      workspaceId,
      deckId: deck.id,
      userId,
      density: resolvedDensity,
      projectId: project.id,
      projectName: flowCtx.title || project.name,
      flowCtx,
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

function seedTitleFromPrompt(prompt) {
  const text = String(prompt || '').trim();
  if (!text) return '';
  const firstLine = text.split(/\r?\n/)[0].trim();
  return firstLine.length > 120 ? `${firstLine.slice(0, 117)}...` : firstLine;
}

async function regenerateSlide({
  workspaceId,
  presentationId,
  slideId,
  userId,
  target = 'all',
  overwriteManualEdits = true,
  prompt = null,
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

  const userPrompt = prompt != null && String(prompt).trim() ? String(prompt).trim() : null;
  const outlineSlideMatch =
    (deck.outline?.slides || []).find((s) => Number(s.order) === Number(slide.order)) ||
    (deck.outline?.slides || [])[slide.order - 1] ||
    null;
  const existingTitle =
    (slide.content && slide.content.title && String(slide.content.title).trim()) ||
    (outlineSlideMatch && outlineSlideMatch.title && String(outlineSlideMatch.title).trim()) ||
    '';

  if ((target === 'content' || target === 'all') && !userPrompt && !existingTitle) {
    throw new AppError('Provide prompt or slide title to regenerate content', 400);
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

  // Reset fields based on target; keep prompt/title seed for content LLM context
  const reset = { status: 'PENDING' };
  if (target === 'all' || target === 'content') {
    reset.content = userPrompt
      ? { title: seedTitleFromPrompt(userPrompt), summary: userPrompt }
      : existingTitle
        ? { title: existingTitle }
        : null;
    reset.layoutId = null;
  }
  if (target === 'all' || target === 'image') {
    reset.imageRef = null;
  }
  await presentationDao.updateSlide(slideId, reset);

  const flowCtx = generationFlowService.resolveFlowToGenerateCtx(
    deck.generationMetrics?.generationFlow,
    { topLevelDensity: deck.outline?.density || null }
  );
  const packBrand = await loadPackAndBrandForGenerate({ workspaceId, deck, flowCtx });

  const preferVisuals =
    flowCtx.preferVisuals != null
      ? flowCtx.preferVisuals
      : deck.outline?.preferVisuals !== undefined
        ? Boolean(deck.outline.preferVisuals)
        : detectPreferVisuals(deck.outline?.sourcePrompt || userPrompt);

  const ctx = {
    workspaceId,
    deckId: deck.id,
    userId,
    density: flowCtx.density || deck.outline?.density || 'balanced',
    locale: flowCtx.locale || deck.locale || 'en',
    outline: deck.outline,
    themeTokens: flowCtx.themeTokens || deck.themeTokens || {},
    projectName: project.name,
    projectId: project.id,
    previousLayoutId: null,
    regenerateTarget: target,
    userPrompt: userPrompt || existingTitle || flowCtx.userPrompt || deck.outline?.sourcePrompt || null,
    preferVisuals,
    wizardBrief: flowCtx.wizardBrief || '',
    imageSource: flowCtx.imageSource || null,
    imageStylePhrase: flowCtx.imageStylePhrase || null,
    canvasSize: flowCtx.canvas || generationFlowService.resolveCanvas(deck.aspectRatio),
    baseTemplateBias: flowCtx.baseTemplateBias || null,
    layoutIdWhitelist: packBrand.layoutIdWhitelist || null,
    preferExistingPackLayout: Boolean(packBrand.packId) && target === 'image',
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
          const preferVisuals = ctx.preferVisuals !== false;
          try {
            const classifyPrompt = getClassifyPrompt();
            const classified = await chatJson({
              system: classifyPrompt.buildSystem(),
              user: classifyPrompt.buildUser({
                slideContent: content,
                title: content?.title,
                preferVisuals,
                wizardBrief: ctx.wizardBrief || '',
              }),
              temperature: 0.2,
            });
            visualNeed = classified.data?.visual_need || visualNeed;
          } catch {
            // keep default
          }
          const policy = applyVisualPolicy({
            visualNeed,
            contentType: fresh.contentType || content?.content_type || 'bullet_list',
            preferVisuals,
            baseTemplateBias: ctx.baseTemplateBias || null,
          });
          visualNeed = policy.visualNeed;
          let brief = null;
          try {
            const briefPrompt = getImageBriefPrompt();
            const briefResult = await chatJson({
              system: briefPrompt.buildSystem(),
              user: briefPrompt.buildUser({
                slideTitle: content?.title,
                slideContent: content,
                themeImageStyle: ctx.imageStylePhrase || ctx.themeTokens?.imageStyle,
                themeColorTreatment: ctx.themeTokens?.colorTreatment,
                wizardBrief: ctx.wizardBrief || '',
                authorImagePrompt: resolveAuthorImagePrompt(content),
              }),
            });
            brief = briefResult.data;
          } catch {
            const authorBrief = resolveAuthorImagePrompt(content);
            brief = {
              subject: authorBrief || content?.title,
              search_query: authorBrief || content?.title,
            };
          }
          const imageResult = await resolveSlideImage({
            ctx,
            slide: fresh,
            content,
            visualNeed,
            brief,
            pathBSpec: content?.pathBSpec,
          });
          const imageRef = withImageStatus(
            imageResult.imageRef,
            imageResult.imageRef?.url ? 'ready' : imageResult.imageRef?.status || 'skipped'
          );
          let elementsDoc = fresh.elements;
          if (
            elementsDoc &&
            typeof elementsDoc === 'object' &&
            Array.isArray(elementsDoc.elements)
          ) {
            const hasImage = elementsDoc.elements.some((el) => el?.type === 'image');
            elementsDoc = {
              ...elementsDoc,
              elements: elementsDoc.elements.map((el) => {
                if (!el || el.type !== 'image') return el;
                return {
                  ...el,
                  content: {
                    ...(el.content || {}),
                    url: imageRef?.url || null,
                  },
                };
              }),
            };
            if (!hasImage && imageRef?.url) {
              elementsDoc = layoutSlotsToElements(
                { slots: [] },
                content,
                imageRef,
                {},
                { themeTokens: ctx.themeTokens || null, designTokens: content?.designTokens || null }
              );
              // merge: keep prior text elements + appended image
              const prior = Array.isArray(fresh.elements?.elements) ? fresh.elements.elements : [];
              const imgs = (elementsDoc.elements || []).filter((e) => e.type === 'image');
              elementsDoc = {
                version: fresh.elements?.version || 1,
                canvas: fresh.elements?.canvas || elementsDoc.canvas,
                elements: [...prior.filter((e) => e.type !== 'image'), ...imgs],
              };
            }
          } else {
            const seed = (SEED_LAYOUTS || []).find(
              (l) => l.layout_id === fresh.layoutId || l.id === fresh.layoutId
            );
            elementsDoc = layoutSlotsToElements(
              seed || { slots: [] },
              content,
              imageRef,
              {},
              { themeTokens: ctx.themeTokens || null, designTokens: content?.designTokens || null }
            );
          }
          await presentationDao.updateSlide(slideId, {
            status: 'READY',
            imageRef,
            elements: elementsDoc,
            content: {
              ...(content || {}),
              visual_need: visualNeed,
            },
          });
        } catch (err) {
          await presentationDao.updateSlide(slideId, {
            status: 'READY',
            imageRef: withImageStatus(
              { source: 'none' },
              'failed',
              { error: err.message }
            ),
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
  sanitizePresentationTitle,
  detectPreferVisuals,
  applyVisualPolicy,
};
