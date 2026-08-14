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
const { selectLayout, filterTemplatesForSlideOrder, layoutFamilyExcludeIds } = require('./layoutSelector.service');
const {
  enrichOutlineWithArrangement,
  preferredLayoutForSlide,
} = require('./slideArrangementPlan.service');
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
const { layoutSlotsToElements, injectBrandLogo, rebindContentToElements, elementsHaveRebindRoles, applySlideDesignTokens, finalizeElementsDoc, isMediaImageSlot, isPackPlaceholderText, shouldRecompileLayout, resolveImageGenSize } = require('./layoutToElements');
const templateMediaService = require('../templates/templateMedia.service');
const templateMediaDao = require('../templates/templateMedia.dao');
const { AI_SLIDE_MAX } = require('./presentation.constants');
const generationFlowService = require('./generationFlow.service');
const brandKitService = require('../brandKit/brandKit.service');
const fontPairingService = require('./fontPairing.service');

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

function deriveSlotImagePrompt(slotId, content = {}, layoutSchema = null) {
  const id = String(slotId || '');
  const imagePrompts =
    content?.imagePrompts && typeof content.imagePrompts === 'object' ? content.imagePrompts : {};
  const direct =
    imagePrompts[id] ||
    imagePrompts[id.toUpperCase()] ||
    imagePrompts[id.toLowerCase()] ||
    null;
  if (direct) return String(direct).trim();

  const imageMatch = id.match(/^IMAGE_(\d+)$/i);
  if (imageMatch) {
    const idx = Number(imageMatch[1]) - 1;
    const col = (content.columns || content.cards || content.features || [])[idx];
    if (col && typeof col === 'object') {
      const title = String(col.title ?? col.heading ?? col.label ?? '').trim();
      const body = String(col.body ?? col.text ?? '').trim();
      if (title && body) return `${title}: ${body.slice(0, 100)}`;
      if (title) return title;
    }
  }

  const deviceMatch = id.match(/^DEVICE_IMAGE_(\d+)$/i);
  if (deviceMatch) {
    const idx = Number(deviceMatch[1]) - 1;
    const col = (content.columns || content.cards || content.features || [])[idx];
    const label = col
      ? String(col.title ?? col.heading ?? col.label ?? '').trim()
      : '';
    const base = label || String(content.title || '').trim();
    if (base) return `${base} — app UI screenshot`;
  }

  const gridImageMatch = id.match(/^(?:GRID_)?IMAGE_(\d+)$/i);
  if (gridImageMatch && !imageMatch) {
    const idx = Number(gridImageMatch[1]) - 1;
    const col = (content.columns || content.cards || content.features || [])[idx];
    if (col) {
      const title = String(col.title ?? col.heading ?? '').trim();
      if (title) return title;
    }
  }

  if (content.title) {
    const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
    const imageSlots = slots.filter((s) => isMediaImageSlot(s.id, s.role, s));
    if (imageSlots.length > 1) {
      const slotIndex = imageSlots.findIndex((s) => String(s.id) === id);
      if (slotIndex >= 0) {
        return `${content.title} — visual ${slotIndex + 1} of ${imageSlots.length}`;
      }
    }
  }

  return null;
}

function titleWordsFromBody(body, fallback) {
  const words = String(body || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length >= 2) return words.slice(0, 4).join(' ');
  return fallback;
}

function normalizeMultiColumnContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const slots = layoutSchema.slots;
  const needsColumns = slots.some((s) => /^(card|col)_\d+_(title|body)$/i.test(String(s.id || '')));
  if (!needsColumns) return content;

  const colsKey = Array.isArray(content.columns)
    ? 'columns'
    : Array.isArray(content.cards)
      ? 'cards'
      : Array.isArray(content.features)
        ? 'features'
        : null;
  if (!colsKey) return content;

  const next = { ...content, [colsKey]: [...content[colsKey]] };
  const slideTitle = String(next.title || '').trim().toLowerCase();
  const seen = new Set();

  next[colsKey] = next[colsKey].map((col, index) => {
    if (!col || typeof col !== 'object') return col;
    const copy = { ...col };
    let title = String(copy.title ?? copy.heading ?? copy.label ?? '').trim();
    const body = String(copy.body ?? copy.text ?? '').trim();
    const titleLower = title.toLowerCase();

    if (!title || titleLower === slideTitle || seen.has(titleLower)) {
      title = titleWordsFromBody(body, `Aspect ${index + 1}`);
      copy.title = title;
      if (copy.heading != null) copy.heading = title;
      if (copy.label != null) copy.label = title;
    }
    seen.add(String(copy.title ?? copy.heading ?? '').trim().toLowerCase());
    return copy;
  });

  const imageSlots = slots.filter((s) => isMediaImageSlot(s.id, s.role, s));
  if (imageSlots.length > 1) {
    const imagePrompts = {
      ...(next.imagePrompts && typeof next.imagePrompts === 'object' ? next.imagePrompts : {}),
    };
    const usedPrompts = new Set();
    imageSlots.forEach((slot, index) => {
      const slotId = String(slot.id);
      let prompt =
        imagePrompts[slotId] ||
        imagePrompts[slotId.toUpperCase()] ||
        deriveSlotImagePrompt(slotId, next, layoutSchema) ||
        '';
      prompt = String(prompt).trim();
      const col = next[colsKey][index];
      const colTitle = col ? String(col.title ?? col.heading ?? '').trim() : '';
      if (!prompt || usedPrompts.has(prompt.toLowerCase())) {
        prompt = colTitle
          ? `${colTitle} — distinct visual ${index + 1}`
          : `${next.title || 'Slide topic'} — visual ${index + 1}`;
      }
      usedPrompts.add(prompt.toLowerCase());
      imagePrompts[slotId] = prompt;
    });
    next.imagePrompts = imagePrompts;
  }

  return next;
}

async function repairSlideContentFromQa({
  ctx,
  slide,
  content,
  template,
  layoutId,
  contentType,
  resolvedTitle,
  resolvedSummary,
  slideIntent,
  generationHints,
  mergedGenerationHints,
  contentPrompt,
  neighbors = {},
}) {
  let nextContent = content;
  let qa = validateSlide({ content: nextContent, layoutSchema: template?.schema || null });
  nextContent = qa.content;

  for (let attempt = 0; attempt < 2 && qaNeedsContentRepair(qa.issues); attempt += 1) {
    logger.warn?.('presentation_slide_qa_issues', {
      slideId: slide.id,
      layoutId: template.schema.layout_id || layoutId,
      issues: qa.issues,
      attempt: attempt + 1,
    });
    try {
      const repairResult = await withTimeout(
        chatJson({
          system: contentPrompt.buildSystem(),
          user: contentPrompt.buildUser({
            deckTitle: ctx.outline?.title || ctx.projectName,
            themeTone:
              ctx.themeTokens?.brand?.voice?.tone ||
              ctx.themeTokens?.imageStyle ||
              'professional',
            density: ctx.density || 'balanced',
            slideOrder: slide.order,
            slideTotal: neighbors.length || ctx.outline?.slideCount || 1,
            title: resolvedTitle || nextContent?.title,
            summary: resolvedSummary,
            suggestedContentType: contentType,
            previousSlideTitle: neighbors.prev?.title,
            nextSlideTitle: neighbors.next?.title,
            locale: ctx.locale || 'en',
            wizardBrief: ctx.wizardBrief || '',
            intent: slideIntent,
            generationHints: mergeGenerationHints(template.schema, generationHints),
            slotConstraints: slotConstraintsFromLayout(template.schema),
            layoutContext: layoutContextFromSchema(template.schema),
            layoutId: template.schema.layout_id || layoutId,
          }),
          model: DEFAULT_SLIDE_MODEL,
        }),
        CONTENT_TIMEOUT_MS,
        'Slide content repair'
      );
      nextContent = { ...(nextContent || {}), ...repairResult.data };
      nextContent = applyGenerationHints(nextContent, mergedGenerationHints);
      nextContent = normalizeMultiColumnContent(nextContent, template.schema);
      qa = validateSlide({ content: nextContent, layoutSchema: template.schema });
      nextContent = qa.content;
    } catch (repairErr) {
      logger.warn?.('presentation_slide_qa_repair_failed', {
        slideId: slide.id,
        error: repairErr.message,
        attempt: attempt + 1,
      });
      break;
    }
  }

  return { content: nextContent, qa };
}

async function generateSlotImage({ ctx, slide, slotId, prompt, layoutSchema }) {
  const isDeviceSlot = /device_/i.test(String(slotId));
  const fullPrompt = isDeviceSlot
    ? `${prompt}. Flat UI screenshot only — no phone, laptop, tablet, or device bezel in the image.`
    : prompt;
  const slotDef = (layoutSchema?.slots || []).find((s) => String(s.id) === String(slotId));
  const canvas = ctx.canvasSize || { width: 1920, height: 1080 };
  const imageSize = slotDef ? resolveImageGenSize(slotDef, canvas) : null;
  return generateAiImageRef({
    prompt: `Professional presentation visual. ${fullPrompt}`,
    workspaceId: ctx.workspaceId,
    deckId: ctx.deckId,
    slideId: slide.id,
    brief: { subject: prompt },
    source: 'ai_gen',
    size: imageSize,
  });
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

function isBlankStarterSlide(slide) {
  if (!slide?.manuallyEdited) return false;
  if (slide.layoutId) return false;
  const elements = slide.elements?.elements || [];
  if (!elements.length) return true;
  const textEls = elements.filter((e) => e.type === 'text' || e.type === 'textbox');
  if (!textEls.length) return elements.length <= 3;
  return textEls.every((el) => {
    const t = el.content?.text;
    return !t || isPackPlaceholderText(t);
  });
}

function contentNeedsFreshGeneration(content) {
  if (!content || typeof content !== 'object') return true;
  const title = String(content.title || '').trim();
  if (!title) return true;
  if (isPackPlaceholderText(title)) return true;
  if (title === 'Untitled Presentation') return true;
  const bullets = Array.isArray(content.bullets) ? content.bullets : [];
  const hasBullets = bullets.some((b) => {
    const t = typeof b === 'string' ? b : b?.text || '';
    return t && !isPackPlaceholderText(t);
  });
  const body = String(content.body || '').trim();
  if (hasBullets || (body && !isPackPlaceholderText(body))) return false;
  return !title || isPackPlaceholderText(title);
}

async function loadPackAndBrandForGenerate({ workspaceId, deck, flowCtx }) {
  const metricsPack =
    deck.generationMetrics && typeof deck.generationMetrics === 'object'
      ? deck.generationMetrics.deckPack
      : null;

  const packId = flowCtx.packId || metricsPack?.packId || null;
  const brandKitId = flowCtx.brandKitId || metricsPack?.brandKitId || null;
  const wizardThemeTokens =
    flowCtx.themeTokens && typeof flowCtx.themeTokens === 'object' ? { ...flowCtx.themeTokens } : null;

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
      flowCtx.themeTokens = wizardThemeTokens
        ? brandKitService.mergeBrandKitWithThemeTokens(wizardThemeTokens, kitTokens)
        : kitTokens;
      const voiceBrief = brandKitService.buildBrandVoiceBrief(kitTokens);
      if (voiceBrief) {
        flowCtx.wizardBrief = [flowCtx.wizardBrief, voiceBrief].filter(Boolean).join('\n');
      }
    } catch (err) {
      logger.warn('Brand kit resolve failed during generate', { brandKitId, error: err.message });
    }
  } else if (wizardThemeTokens && !flowCtx.themeTokens) {
    flowCtx.themeTokens = wizardThemeTokens;
  }

  flowCtx.themeTokens = fontPairingService.mergeThemeTokensPreservingFonts(
    flowCtx.themeTokens?.wizardColorThemeId ? {} : deck.themeTokens,
    flowCtx.themeTokens || deck.themeTokens
  );

  try {
    flowCtx.themeTokens = await fontPairingService.ensureThemeFonts(flowCtx.themeTokens, {
      prompt: flowCtx.userPrompt || deck.outline?.sourcePrompt || null,
      wizardBrief: flowCtx.wizardBrief || '',
      tone: flowCtx.generationFlow?.selections?.voiceAndTone || null,
      audience: flowCtx.generationFlow?.selections?.audience || null,
      purpose: flowCtx.generationFlow?.selections?.purpose || null,
      style: flowCtx.generationFlow?.selections?.style || null,
      brandKitId,
    });
  } catch (err) {
    logger.warn('ensureThemeFonts failed during generate', { error: err.message });
  }

  return {
    pack,
    packId: pack?.id || null,
    brandKitId,
    layoutIdWhitelist,
    packSlides: pack?.schema?.slides || [],
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
function applyVisualPolicy({
  visualNeed,
  contentType,
  preferVisuals,
  baseTemplateBias: bias,
  respectOutlineType = false,
}) {
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
  if (['grid', 'pricing', 'device_frames'].includes(type)) {
    layoutContentType = type;
  } else if (respectOutlineType && ['comparison', 'timeline', 'diagram', 'grid', 'device_frames', 'chart'].includes(type)) {
    layoutContentType = type;
  } else if (['comparison', 'timeline', 'diagram'].includes(type)) {
    layoutContentType = respectOutlineType ? type : 'image+text';
  } else if (
    respectOutlineType &&
    ['bullet_list', 'stat', 'team', 'section_divider', 'agenda', 'quote', 'title', 'closing', 'diagram'].includes(type)
  ) {
    layoutContentType = type;
  } else if (['bullet_list', 'comparison', 'stat', 'timeline', 'team'].includes(type)) {
    layoutContentType = 'image+text';
  } else if (type === 'section_divider') {
    layoutContentType = 'section_divider';
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
    const preserveTypes = new Set(['chart', 'grid', 'device_frames', 'section_divider', 'diagram', 'timeline', 'comparison']);
    if (
      preferred.includes('image+text') &&
      !preserveTypes.has(layoutContentType) &&
      layoutContentType !== 'chart' &&
      layoutContentType !== 'section_divider'
    ) {
      layoutContentType = 'image+text';
    } else if (preferred.includes(type)) {
      layoutContentType = type;
    }
  }

  return {
    visualNeed: need,
    contentType: type === 'image+text' ? 'image+text' : type,
    layoutContentType,
    preferImageSlot:
      bias?.preferImageSlot !== false &&
      !['comparison', 'timeline', 'diagram', 'bullet_list', 'section_divider', 'chart', 'agenda', 'quote', 'closing'].includes(
        layoutContentType
      ),
  };
}

/**
 * Slide 1 only → title; slide N only → closing; never title/closing elsewhere.
 */
function guardContentTypeForSlideOrder(contentType, slideOrder, totalSlides, outlineSlide = {}) {
  const order = Number(slideOrder) > 0 ? Number(slideOrder) : 1;
  const total = Number(totalSlides) > 0 ? Number(totalSlides) : order;
  let type = String(contentType || 'bullet_list').toLowerCase();

  if (order === 1) return 'title';

  if (type === 'title') {
    const hasBody = Boolean(String(outlineSlide?.summary || '').trim());
    return hasBody ? 'image+text' : 'section_divider';
  }

  if (type === 'closing' && order !== total) {
    return 'section_divider';
  }

  return type;
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

function imageColorTreatmentForCtx(ctx) {
  if (ctx?.themeTokens?.brand?.brandKitId) return null;
  return ctx?.themeTokens?.colorTreatment || null;
}

function layoutNeedsVisual(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((s) => isMediaImageSlot(s.id, s.role, s));
}

async function loadDeckPackForOutline(deck) {
  const packId = deck.generationMetrics?.deckPack?.packId;
  if (!packId) return null;
  const pack = await presentationDao.findTemplateById(packId);
  if (!pack || pack.type !== 'DECK_PACK' || !pack.isActive) return null;
  return pack;
}

function buildPackOutlineSkeleton(pack, { density, locale, sourceText }) {
  const packSlides = Array.isArray(pack.schema?.slides) ? pack.schema.slides : [];
  return {
    title: pack.schema?.meta?.title || sanitizePresentationTitle(sourceText?.slice(0, 120)),
    slideCount: packSlides.length,
    density,
    locale,
    sourcePrompt: sourceText,
    slides: packSlides.map((ps) => ({
      order: Number(ps.order),
      title: ps.placeholder?.title || ps.intent || `Slide ${ps.order}`,
      summary: ps.placeholder?.summary || ps.intent || '',
      suggestedContentType: ps.contentType || null,
      layoutId: ps.layout_id || null,
      intent: ps.intent || null,
    })),
  };
}

function mergePackOutlineWithLlm(skeleton, llmData, { slideCount, density, locale, sourceText }) {
  const llmSlides = Array.isArray(llmData?.slides) ? llmData.slides : [];
  const byOrder = new Map(
    llmSlides.map((s, idx) => [Number(s.order) > 0 ? Number(s.order) : idx + 1, s])
  );

  const mergedSlides = skeleton.slides.map((sk) => {
    const llm = byOrder.get(Number(sk.order)) || {};
    return {
      ...sk,
      title: String(llm.title || sk.title || `Slide ${sk.order}`).trim(),
      summary: llm.summary != null ? String(llm.summary) : sk.summary,
    };
  });

  return normalizeOutline(
    {
      title: llmData?.title || skeleton.title,
      slides: mergedSlides,
      preferVisuals: skeleton.preferVisuals,
    },
    { slideCount, density, locale, sourceText }
  );
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
      layoutId: s.layoutId || s.layout_id || null,
      intent: s.intent || null,
    }))
    .slice(0, AI_SLIDE_MAX);

  if (normalizedSlides.length > 0) {
    const first = normalizedSlides.find((s) => Number(s.order) === 1) || normalizedSlides[0];
    if (first && (!first.suggestedContentType || first.suggestedContentType === 'bullet_list')) {
      first.suggestedContentType = 'title';
    }
  }

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
  size = null,
}) {
  const image = await generateImage({ prompt, quality, size: size || undefined });
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

function applyDarkExposureOverlay(content, brief, layoutSchema) {
  if (!content || !brief || String(brief.exposure_hint || '').toLowerCase() !== 'dark') return content;
  if (!layoutSchema?.slots?.length) return content;
  const hasImageSlot = layoutSchema.slots.some((slot) => {
    const id = String(slot.id || '').toUpperCase();
    const role = String(slot.role || '').toLowerCase();
    return id === 'BACKGROUND_IMAGE' || id === 'HERO_IMAGE' || role === 'image' || id.includes('IMAGE');
  });
  if (!hasImageSlot) return content;
  return {
    ...content,
    shapeDecisions: {
      ...(content.shapeDecisions || {}),
      __overlay__: { enabled: true, scrim: 0.45 },
    },
  };
}

async function enrichContentSlotImageUrls({ ctx, slide, content, layoutSchema, imageRef }) {
  if (!layoutSchema?.slots?.length) return content;

  const slotIds = templateMediaService.listLayoutImageSlots(layoutSchema);
  if (!slotIds.length) return content;

  const slotImageUrls = {
    ...(content?.slotImageUrls && typeof content.slotImageUrls === 'object' ? content.slotImageUrls : {}),
  };

  const packId = ctx.packId || null;
  if (packId) {
    const rows = await templateMediaDao.listByTemplateId(packId);
    const mediaByHint = new Map(
      (rows || []).filter((row) => row.slotHint).map((row) => [row.slotHint, row])
    );
    for (const slotId of slotIds) {
      if (slotImageUrls[slotId]) continue;
      const hint = templateMediaService.slotHintForSlideSlot(slide.order, slotId);
      const row = mediaByHint.get(hint);
      if (!row?.s3Key) continue;
      const url = await templateMediaService.resolveMediaUrl(row.s3Key);
      if (url) slotImageUrls[slotId] = url;
    }
  }

  const imagePrompts =
    content?.imagePrompts && typeof content.imagePrompts === 'object' ? content.imagePrompts : {};
  let missing = slotIds.filter((slotId) => !slotImageUrls[slotId]);

  if (
    missing.length &&
    ctx.imageSource !== 'none' &&
    ctx.imageSource !== 'placeholder'
  ) {
    for (const slotId of [...missing]) {
      const prompt =
        deriveSlotImagePrompt(slotId, content, layoutSchema) ||
        imagePrompts[slotId] ||
        imagePrompts[String(slotId).toUpperCase()] ||
        null;
      if (!prompt) continue;
      try {
        const generated = await generateSlotImage({
          ctx,
          slide,
          slotId,
          prompt,
          layoutSchema,
        });
        if (generated?.url) {
          slotImageUrls[slotId] = generated.url;
          missing = missing.filter((id) => id !== slotId);
        }
      } catch (err) {
        logger.warn?.('presentation_slot_image_failed', {
          slideId: slide.id,
          slotId,
          error: err.message,
        });
      }
    }
  }

  if (slotIds.length === 1 && missing.length === 1 && imageRef?.url && !slotIds.some((id) => slotImageUrls[id] === imageRef.url)) {
    slotImageUrls[missing[0]] = imageRef.url;
  } else if (slotIds.length === 1 && imageRef?.url && !slotImageUrls[slotIds[0]]) {
    slotImageUrls[slotIds[0]] = imageRef.url;
  }

  if (!Object.keys(slotImageUrls).length) return content;

  const urlCounts = new Map();
  for (const url of Object.values(slotImageUrls)) {
    if (!url) continue;
    urlCounts.set(url, (urlCounts.get(url) || 0) + 1);
  }
  for (const [slotId, url] of Object.entries(slotImageUrls)) {
    if (url && (urlCounts.get(url) || 0) > 1 && slotIds.length > 1) {
      delete slotImageUrls[slotId];
    }
  }

  const regenMissing = slotIds.filter((slotId) => !slotImageUrls[slotId]);
  if (
    regenMissing.length &&
    ctx.imageSource !== 'none' &&
    ctx.imageSource !== 'placeholder'
  ) {
    for (const slotId of regenMissing) {
      const prompt =
        deriveSlotImagePrompt(slotId, content, layoutSchema) ||
        imagePrompts[slotId] ||
        imagePrompts[String(slotId).toUpperCase()] ||
        `${content?.title || 'Slide'} — alternate visual for ${slotId}`;
      try {
        const generated = await generateSlotImage({
          ctx,
          slide,
          slotId,
          prompt: `${prompt} (distinct variation)`,
          layoutSchema,
        });
        if (generated?.url) slotImageUrls[slotId] = generated.url;
      } catch (err) {
        logger.warn?.('presentation_slot_image_regen_failed', {
          slideId: slide.id,
          slotId,
          error: err.message,
        });
      }
    }
  }

  return { ...content, slotImageUrls };
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

  // Prefer brand kit photos when available (before keeping template/user media)
  const searchQueryEarly =
    brief?.search_query || brief?.searchQuery || brief?.subject || content?.title || 'presentation visual';
  const brandPhotoEarly = pickBrandPhoto(ctx.themeTokens, searchQueryEarly);
  if (brandPhotoEarly && (brandPhotoEarly.url || brandPhotoEarly.s3Key)) {
    let url = brandPhotoEarly.url || null;
    if (!url && brandPhotoEarly.s3Key) {
      try {
        url = await s3Service.getPresignedGetUrl(brandPhotoEarly.s3Key, 3600);
      } catch {
        url = s3Service.buildPublicUrl(brandPhotoEarly.s3Key);
      }
    }
    if (url) {
      return {
        imageRef: withImageStatus(
          {
            source: 'brand_kit',
            url,
            s3Key: brandPhotoEarly.s3Key || null,
            mediaId: brandPhotoEarly.id || null,
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

  // Keep existing ready template/upload/stock media unless force refresh (e.g. regenerate image)
  const existing = slide?.imageRef;
  const isTemplateSeed =
    String(existing?.source || '').toLowerCase() === 'template' ||
    String(existing?.source || '').toLowerCase() === 'pack';
  if (
    !ctx.forceImageRefresh &&
    !(ctx.packBound && isTemplateSeed) &&
    existing &&
    existing.status === 'ready' &&
    (existing.url || existing.s3Key)
  ) {
    return {
      imageRef: withImageStatus(existing, 'ready'),
      chargedFeature: null,
      cacheHit: true,
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

  // photo / illustration / default → stock then Path A (brand + existing media handled above)
  const searchQuery =
    brief?.search_query || brief?.searchQuery || brief?.subject || content?.title || 'presentation visual';

  const briefHash = imageCache.hashBrief({
    searchQuery,
    imageStyle: ctx.themeTokens?.imageStyle,
    colorTreatment: imageColorTreatmentForCtx(ctx),
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
      imageColorTreatmentForCtx(ctx) || '',
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
          if (!vision.relevant) imageRef = null;
        } catch {
          // ignore vision errors — keep image only when relevance was not evaluated
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

function applyDefaultOverlayDecisions(content, layoutSchema) {
  if (!content || !layoutSchema) return content;
  const layoutCtx = layoutContextFromSchema(layoutSchema);
  if (!layoutCtx.hasImageOverlay) return content;
  return {
    ...content,
    shapeDecisions: {
      ...(content.shapeDecisions || {}),
      __overlay__: {
        enabled: true,
        scrim: content.shapeDecisions?.__overlay__?.scrim ?? 0.45,
      },
    },
  };
}

function qaNeedsContentRepair(issues) {
  if (!Array.isArray(issues) || !issues.length) return false;
  return issues.some(
    (issue) =>
      issue.repairable === true ||
      issue.rule === 'required_structured' ||
      issue.rule === 'distinct_titles' ||
      issue.rule === 'column_title_matches_slide_title' ||
      issue.rule === 'duplicate_image_prompts' ||
      issue.rule === 'required_chart_data' ||
      issue.rule === 'generic_chart_labels' ||
      issue.rule === 'placeholder_chart_subtitle' ||
      issue.rule === 'placeholder_cta' ||
      (issue.truncated === true && issue.rule === 'max_lines')
  );
}

async function planDeckLayouts(ctx, slides) {
  if (ctx.packBound || !Array.isArray(slides) || slides.length === 0) {
    return {};
  }

  const outlineSlides = (ctx.outline?.slides || []).slice().sort((a, b) => a.order - b.order);
  const orderedSlides = slides.slice().sort((a, b) => Number(a.order) - Number(b.order));
  const totalSlides = orderedSlides.length || ctx.outline?.slideCount || outlineSlides.length || 1;
  const planned = {};
  const usedLayoutIds = new Set();
  let fullBleedUsed = false;
  let previousLayoutId = null;
  const contentTypeHistory = [];

  for (const slide of orderedSlides) {
    const outlineSlide =
      outlineSlides.find((s) => Number(s.order) === Number(slide.order)) ||
      outlineSlides[Number(slide.order) - 1] ||
      {};

    let contentType = outlineSlide.suggestedContentType || slide.contentType || 'bullet_list';
    contentType = guardContentTypeForSlideOrder(contentType, slide.order, totalSlides, outlineSlide);

    const preferVisuals = ctx.preferVisuals !== false;
    const policy = applyVisualPolicy({
      visualNeed: preferVisuals ? 'photo' : 'none',
      contentType,
      preferVisuals,
      baseTemplateBias: ctx.baseTemplateBias || null,
      respectOutlineType: true,
    });

    ctx.contentTypeHistory = contentTypeHistory.slice();
    const layoutContentType = applyContentDistribution(policy.contentType, ctx);
    contentTypeHistory.push(layoutContentType);

    let templates = await resolveLayoutTemplates(layoutContentType, {
      layoutIdWhitelist: ctx.layoutIdWhitelist || null,
    });
    templates = filterTemplatesForSlideOrder(templates, slide.order, totalSlides);
    if (fullBleedUsed) {
      templates = templates.filter(
        (t) => String(t.schema?.layout_id || t.variant || '') !== 'full_bg_image_overlay_v1'
      );
    }

    const stubContent = {
      title: outlineSlide.title || slide.content?.title || '',
      summary: outlineSlide.summary || '',
      body: outlineSlide.summary || '',
      bullets: outlineSlide.summary
        ? String(outlineSlide.summary)
            .split(/[.;]\s+/)
            .map((s) => s.trim())
            .filter(Boolean)
            .slice(0, 6)
        : [],
    };

    ctx.outlineExplicitType = Boolean(outlineSlide.suggestedContentType || outlineSlide.arrangementHint);
    ctx.respectOutlineTypes = true;
    const excludeLayoutIds =
      Number(slide.order) === totalSlides && ctx.titleLayoutId
        ? layoutFamilyExcludeIds(ctx.titleLayoutId)
        : null;
    const { layoutId, template } = selectLayout({
      contentType: layoutContentType,
      content: stubContent,
      previousLayoutId,
      usedLayoutIds,
      templates,
      preferImageSlot: policy.preferImageSlot,
      preferredLayoutId: preferredLayoutForSlide(ctx, layoutContentType, usedLayoutIds, slide.order),
      slideOrder: slide.order,
      totalSlides,
      excludeLayoutIds,
    });

    if (layoutId && template) {
      planned[Number(slide.order)] = {
        layoutId,
        template,
        schema: template.schema || null,
        layoutContentType,
        policy,
      };
      usedLayoutIds.add(String(layoutId));
      if (Number(slide.order) === 1) {
        ctx.titleLayoutId = String(layoutId);
      }
      if (String(layoutId) === 'full_bg_image_overlay_v1') fullBleedUsed = true;
      previousLayoutId = layoutId;
    }
  }

  ctx.plannedLayouts = planned;
  ctx.fullBleedUsed = fullBleedUsed;
  ctx.layoutIdByOrder = Object.fromEntries(
    Object.entries(planned).map(([order, entry]) => [order, entry.layoutId])
  );
  ctx.usedLayoutIds = usedLayoutIds;
  return planned;
}

async function resolvePreGenerationLayout({
  ctx,
  slide,
  outlineSlide,
  resolvedTitle,
  resolvedSummary,
  preferVisuals,
}) {
  const plannedEntry = ctx.plannedLayouts?.[Number(slide.order)];
  if (plannedEntry?.schema) {
    return {
      layoutId: plannedEntry.layoutId,
      template: plannedEntry.template,
      schema: plannedEntry.schema,
      layoutContentType: plannedEntry.layoutContentType,
      policy: plannedEntry.policy,
    };
  }

  let contentType = outlineSlide.suggestedContentType || slide.contentType || 'bullet_list';
  const totalSlides = ctx.outline?.slideCount || ctx.slideTotal || 1;
  contentType = guardContentTypeForSlideOrder(contentType, slide.order, totalSlides, outlineSlide);

  const policy = applyVisualPolicy({
    visualNeed: preferVisuals ? 'photo' : 'none',
    contentType,
    preferVisuals,
    baseTemplateBias: ctx.baseTemplateBias || null,
    respectOutlineType: true,
  });
  const layoutContentType = applyContentDistribution(policy.contentType, ctx);

  let templates = await resolveLayoutTemplates(layoutContentType, {
    layoutIdWhitelist: ctx.layoutIdWhitelist || null,
  });
  templates = filterTemplatesForSlideOrder(templates, slide.order, totalSlides);
  if (ctx.fullBleedUsed) {
    templates = templates.filter(
      (t) => String(t.schema?.layout_id || t.variant || '') !== 'full_bg_image_overlay_v1'
    );
  }

  const previousLayoutId = ctx.layoutIdByOrder?.[Number(slide.order) - 1] || null;
  const stubContent = {
    title: resolvedTitle || outlineSlide.title || '',
    summary: resolvedSummary,
    bullets: [],
  };
  const { layoutId, template } = selectLayout({
    contentType: layoutContentType,
    content: stubContent,
    previousLayoutId,
    usedLayoutIds: ctx.usedLayoutIds || null,
    templates,
    preferImageSlot: policy.preferImageSlot,
    slideOrder: slide.order,
    totalSlides,
  });

  return {
    layoutId,
    template,
    schema: template?.schema || null,
    layoutContentType,
    policy,
  };
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

function sanitizeShapeDecisions(content, layoutSchema) {
  if (!content || typeof content !== 'object') return content;
  const decisions = content.shapeDecisions;
  if (!decisions || typeof decisions !== 'object') return content;
  const slotIds = new Set((layoutSchema?.slots || []).map((s) => s.id));
  const hasBgImage = (layoutSchema?.slots || []).some((s) => {
    const id = String(s.id || '').toUpperCase();
    return id === 'BACKGROUND_IMAGE' || id === 'HERO_IMAGE' || String(s.role || '').toLowerCase() === 'image';
  });
  const cleaned = {};
  for (const [key, val] of Object.entries(decisions)) {
    if (key === '__overlay__') {
      if (hasBgImage && val && typeof val === 'object') cleaned[key] = val;
      continue;
    }
    if (slotIds.has(key) && val && typeof val === 'object') cleaned[key] = val;
  }
  return { ...content, shapeDecisions: Object.keys(cleaned).length ? cleaned : undefined };
}

function generationHintsFromLayout(layoutSchema) {
  if (!layoutSchema) return null;
  const hints = {};
  const ct = String(layoutSchema.content_type || '').toLowerCase();
  const layoutId = String(layoutSchema.layout_id || '');
  const slots = Array.isArray(layoutSchema.slots) ? layoutSchema.slots : [];
  const imageSlots = slots.filter((s) => isMediaImageSlot(s.id, s.role, s));

  if (ct === 'chart' || /chart/i.test(layoutId)) {
    const chartSlot = slots.find((s) => String(s.role || '').toLowerCase() === 'chart');
    const slotChartType = chartSlot?.chartType || chartSlot?.chart_type || null;
    hints.chartDataStyle =
      'Provide 4-6 realistic numeric data points tied to the slide topic; labels must be topic-specific (years, categories, regions) — never Q1/Q2/Q3/Q4 unless the deck is explicitly quarterly. Values plausible integers or percentages.';
    if (slotChartType) {
      hints.chartType = slotChartType.includes('line') ? 'line' : slotChartType.includes('donut') ? 'donut' : 'bar';
    } else if (!/exponential|line/i.test(layoutId)) {
      hints.chartType = 'bar';
    }
  }
  if (imageSlots.length > 1) {
    hints.imagePromptStyle = `Fill imagePrompts with a UNIQUE concrete visual for each slot: ${imageSlots.map((s) => s.id).join(', ')}. No duplicate subjects.`;
  }
  if (/para|cards_image|card_\d|grid_.*image|intro_four|intro_three|four_para|three_para|two_para/i.test(layoutId)) {
    hints.parallelStructure =
      'Each column/card/paragraph needs a distinct title (≤4 words) and body (1-2 lines). Fill columns[] accordingly.';
  }
  if (ct === 'closing' || /closing|cta/i.test(layoutId)) {
    hints.ctaFormat =
      'Topic-specific CTA — never use generic "Book a demo" unless the deck is explicitly sales/demo.';
  }
  if (ct === 'title' || (layoutId.includes('title') && ct === 'title')) {
    hints.titleTone = 'Require titleRuns with 2-3 segments; accent on final line.';
  }
  return Object.keys(hints).length ? hints : null;
}

function mergeGenerationHints(layoutSchema, packHints) {
  const fromLayout = generationHintsFromLayout(layoutSchema) || {};
  const fromPack = packHints && typeof packHints === 'object' ? packHints : {};
  const merged = { ...fromLayout, ...fromPack };
  return Object.keys(merged).length ? merged : null;
}

function layoutContextFromSchema(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const layoutId = layoutSchema?.layout_id || null;
  const contentType = layoutSchema?.content_type || null;
  const hasImageOverlay =
    slots.some(
      (s) =>
        s.id === 'BACKGROUND_IMAGE' ||
        /OVERLAY_SCRIM/i.test(String(s.id || '')) ||
        /full.?bleed|overlay/i.test(String(s.id || ''))
    ) || /full_bg|overlay|statement_top|statement_bottom/i.test(String(layoutId || ''));
  const hasHeroImage = slots.some((s) => {
    const id = String(s.id || '').toUpperCase();
    const role = String(s.role || '').toLowerCase();
    return role === 'image' || id === 'HERO_IMAGE' || id.includes('IMAGE');
  });
  const hasTextOverImageRisk =
    hasImageOverlay ||
    (hasHeroImage &&
      slots.some((s) => {
        const role = String(s.role || '').toLowerCase();
        return ['heading', 'body', 'subheading', 'caption'].includes(role);
      }));
  const shapeHints = slots
    .filter((s) => s.shapeHint || s.aiOnly)
    .map((s) => ({
      slotId: s.id,
      role: s.role,
      pairsWithSlotId: s.shapeHint?.pairsWithSlotId || null,
      suggestedBehind: s.shapeHint?.suggestedBehind || null,
      kind: s.shapeHint?.kind || null,
    }));
  return {
    layoutId,
    hasImageOverlay,
    hasHeroImage,
    hasTextOverImageRisk,
    shapePolicy: layoutSchema?.shapePolicy || 'ai_decides',
    shapeHints,
    isSimpleSlide: ['title', 'image+text', 'bullet_list', 'section_divider', 'closing', 'quote', 'grid'].includes(
      String(contentType || '')
    ),
  };
}

function applyContentDistribution(contentType, ctx) {
  const dist = ctx.contentDistribution;
  if (!dist || typeof dist !== 'object') return contentType;
  if (ctx.respectOutlineTypes && ctx.outlineExplicitType) {
    return contentType;
  }
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
    let preSelectedTemplate = null;
    let preSelectedLayoutId = null;
    let preLayoutContentType = null;
    if (packMeta?.layout_id) {
      const early = await presentationDao.findLayoutsByLayoutIds([packMeta.layout_id]);
      earlyLayoutSchema = early[0]?.schema || null;
      preSelectedTemplate = early[0] || null;
      preSelectedLayoutId = packMeta.layout_id;
    }

    const preferVisuals = ctx.preferVisuals !== false;
    const resolvedTitle =
      outlineSlide.title ||
      (slide.content && slide.content.title) ||
      ctx.userPrompt ||
      '';
    const resolvedSummary = outlineSlide.summary || ctx.userPrompt || '';

    if (!earlyLayoutSchema && !ctx.packBound) {
      const pre = await resolvePreGenerationLayout({
        ctx,
        slide,
        outlineSlide,
        resolvedTitle,
        resolvedSummary,
        preferVisuals,
      });
      earlyLayoutSchema = pre.schema;
      preSelectedTemplate = pre.template;
      preSelectedLayoutId = pre.layoutId;
      preLayoutContentType = pre.layoutContentType;
    }

    let contentLayoutSchema = earlyLayoutSchema;
    const mergedGenerationHints = mergeGenerationHints(contentLayoutSchema, generationHints);

    // 1) Content LLM
    const contentPrompt = getSlideContentPrompt();

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
      contentLayoutSchema?.layout_id || '',
    ]);
    const contentJob = await beginJob({
      slideId: slide.id,
      jobType: 'CONTENT',
      requestHash: contentHash,
      promptVersion: PROMPT_BUNDLE_VERSION,
      model: DEFAULT_SLIDE_MODEL,
    });

    let content = slide.content && typeof slide.content === 'object' ? { ...slide.content } : null;
    const needsFreshContent = contentNeedsFreshGeneration(content);
    if (!contentJob.duplicate || (needsFreshContent && (ctx.packBound || ctx.forceTextReplace))) {
      const contentStarted = Date.now();
      try {
        const llmResult = await withTimeout(
          chatJson({
            system: contentPrompt.buildSystem(),
            user: contentPrompt.buildUser({
              deckTitle: ctx.outline?.title || ctx.projectName,
              themeTone:
                ctx.themeTokens?.brand?.voice?.tone ||
                ctx.themeTokens?.imageStyle ||
                'professional',
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
              generationHints: mergedGenerationHints,
              slotConstraints: slotConstraintsFromLayout(contentLayoutSchema),
              layoutContext: layoutContextFromSchema(contentLayoutSchema),
              layoutId: contentLayoutSchema?.layout_id || preSelectedLayoutId || null,
            }),
            model: DEFAULT_SLIDE_MODEL,
          }),
          CONTENT_TIMEOUT_MS,
          'Slide content generation'
        );
        content = { ...(content || {}), ...llmResult.data };
        content = applyGenerationHints(content, mergedGenerationHints);
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

    if (ctx.packBound && earlyLayoutSchema && layoutNeedsVisual(earlyLayoutSchema)) {
      if (!visualNeed || String(visualNeed).toLowerCase() === 'none') {
        visualNeed = 'photo';
      }
    }

    if (!ctx.packBound && Number(slide.order) === 1) {
      contentType = 'title';
      if (!visualNeed || String(visualNeed).toLowerCase() === 'none') {
        visualNeed = ctx.preferVisuals !== false ? 'photo' : 'none';
      }
    }

    const slideTotal =
      (ctx.outline?.slides || []).length ||
      ctx.outline?.slideCount ||
      ctx.slideTotal ||
      Number(slide.order);
    contentType = guardContentTypeForSlideOrder(contentType, slide.order, slideTotal, outlineSlide);

    const policy = applyVisualPolicy({
      visualNeed,
      contentType,
      preferVisuals,
      baseTemplateBias: ctx.baseTemplateBias || null,
      respectOutlineType: !ctx.packBound,
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

    // 3) Layout select + QA (skip when snapshot/role canvas will rebind)
    let layoutId = null;
    let template = null;
    const existingLayoutId = slide.layoutId || packMeta?.layout_id || null;
    const packSnapshotEarly = packMeta?.snapshot?.elements || null;
    const currentElementsEarly =
      slide.elements && typeof slide.elements === 'object' ? slide.elements : null;
    const willRebind = Boolean(
      (currentElementsEarly && elementsHaveRebindRoles(currentElementsEarly)) ||
        (packSnapshotEarly && elementsHaveRebindRoles(packSnapshotEarly))
    );

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
    if (!template && !willRebind) {
      const plannedEntry = ctx.plannedLayouts?.[Number(slide.order)];
      const plannedMatches =
        plannedEntry?.template &&
        plannedEntry?.layoutId &&
        String(plannedEntry.layoutContentType || '') === String(policy.layoutContentType);
      const preselectedMatches =
        preSelectedTemplate &&
        preSelectedLayoutId &&
        String(preSelectedTemplate.contentType || preSelectedTemplate.schema?.content_type || '') ===
          String(policy.layoutContentType);
      const canReusePreselected = plannedMatches || preselectedMatches;

      if (canReusePreselected) {
        template = plannedEntry?.template || preSelectedTemplate;
        layoutId = plannedEntry?.layoutId || preSelectedLayoutId;
      } else {
        let templates = await resolveLayoutTemplates(policy.layoutContentType, {
          layoutIdWhitelist: ctx.layoutIdWhitelist || null,
        });
        templates = filterTemplatesForSlideOrder(templates, slide.order, slideTotal);
        if (ctx.fullBleedUsed) {
          templates = templates.filter(
            (t) => String(t.schema?.layout_id || t.variant || '') !== 'full_bg_image_overlay_v1'
          );
        }
        const excludeLayoutIds =
          Number(slide.order) === slideTotal && ctx.titleLayoutId
            ? layoutFamilyExcludeIds(ctx.titleLayoutId)
            : null;
        ({ layoutId, template } = selectLayout({
          contentType: policy.layoutContentType,
          content,
          previousLayoutId: ctx.layoutIdByOrder?.[Number(slide.order) - 1] || null,
          usedLayoutIds: ctx.usedLayoutIds || null,
          templates,
          preferImageSlot: policy.preferImageSlot,
          preferredLayoutId: preferredLayoutForSlide(
            ctx,
            policy.layoutContentType,
            ctx.usedLayoutIds || new Set(),
            slide.order
          ),
          slideOrder: slide.order,
          totalSlides: slideTotal,
          excludeLayoutIds,
        }));
      }
    }
    if (!layoutId && existingLayoutId) layoutId = existingLayoutId;
    if (layoutId) {
      ctx.layoutIdByOrder = ctx.layoutIdByOrder || {};
      ctx.layoutIdByOrder[Number(slide.order)] = layoutId;
      if (Number(slide.order) === 1) {
        ctx.titleLayoutId = String(layoutId);
      }
      if (String(layoutId) === 'full_bg_image_overlay_v1') {
        ctx.fullBleedUsed = true;
      }
    }

    if (template?.schema) {
      content = normalizeMultiColumnContent(content, template.schema);
    }

    let qa = validateSlide({
      content,
      layoutSchema: template?.schema || null,
    });
    content = qa.content;

    if (qaNeedsContentRepair(qa.issues) && template?.schema) {
      const repaired = await repairSlideContentFromQa({
        ctx,
        slide,
        content,
        template,
        layoutId,
        contentType,
        resolvedTitle,
        resolvedSummary,
        slideIntent,
        generationHints,
        mergedGenerationHints,
        contentPrompt,
        neighbors: { prev, next, length: neighbors.length },
      });
      content = repaired.content;
      qa = repaired.qa;
    } else if (qa.issues?.length) {
      logger.warn?.('presentation_slide_qa_issues', {
        slideId: slide.id,
        layoutId: template?.schema?.layout_id || layoutId,
        issues: qa.issues,
      });
    }
    if (content && typeof content === 'object') {
      content.visual_need = visualNeed;
      content.content_type = contentType;
      content = applyDefaultOverlayDecisions(content, template?.schema || null);
      content = sanitizeShapeDecisions(content, template?.schema);
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
          const layoutCtx = layoutContextFromSchema(template?.schema);
          const briefResult = await chatJson({
            system: briefPrompt.buildSystem(),
            user: briefPrompt.buildUser({
              slideTitle: content?.title,
              slideContent: content,
              themeImageStyle: ctx.imageStylePhrase || ctx.themeTokens?.imageStyle,
              themeColorTreatment: imageColorTreatmentForCtx(ctx),
              wizardBrief: ctx.wizardBrief || '',
              authorImagePrompt: resolveAuthorImagePrompt(content),
              layoutContext: layoutCtx,
              layoutId: template?.schema?.layout_id || layoutId || null,
              hasImageOverlay: layoutCtx.hasImageOverlay,
              visualNeed,
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
          content = applyDarkExposureOverlay(content, brief, template?.schema || null);
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

    const layoutSchema = template?.schema || null;
    if (layoutSchema?.slots?.length) {
      try {
        content = await enrichContentSlotImageUrls({
          ctx,
          slide,
          content,
          layoutSchema,
          imageRef,
        });
      } catch (slotImgErr) {
        logger.warn?.('presentation_slot_images_enrich_failed', {
          slideId: slide.id,
          error: slotImgErr.message,
        });
      }
    }

    const canvasSize = ctx.canvasSize || {};
    const packSnapshot = packMeta?.snapshot?.elements || null;
    const currentElements =
      slide.elements && typeof slide.elements === 'object' ? slide.elements : null;
    const rebindBase =
      (ctx.packBound && packSnapshot && packSnapshot) ||
      (currentElements && elementsHaveRebindRoles(currentElements) && currentElements) ||
      (packSnapshot && elementsHaveRebindRoles(packSnapshot) && packSnapshot) ||
      null;

    const useFreshCompile =
      Boolean(layoutSchema?.slots?.length) &&
      (ctx.packBound || shouldRecompileLayout(layoutSchema, currentElements));

    let elementsDoc;
    const hasBrandKit = Boolean(ctx.themeTokens?.brand?.brandKitId);
    if (rebindBase && !useFreshCompile) {
      elementsDoc = rebindContentToElements(rebindBase, content, imageRef, {
        forceTextReplace: Boolean(ctx.forceTextReplace),
        themeTokens: ctx.themeTokens || null,
        layoutSchema,
      });
      elementsDoc = applySlideDesignTokens(elementsDoc, designTokens, ctx.themeTokens || null);
    } else if (layoutSchema?.slots?.length) {
      elementsDoc = layoutSlotsToElements(
        layoutSchema,
        content,
        imageRef,
        { width: canvasSize.width, height: canvasSize.height },
        {
          themeTokens: ctx.themeTokens || null,
          designTokens,
          applyShapes: false,
        }
      );
    } else if (rebindBase) {
      elementsDoc = rebindContentToElements(rebindBase, content, imageRef, {
        forceTextReplace: Boolean(ctx.forceTextReplace),
        themeTokens: ctx.themeTokens || null,
        layoutSchema,
      });
      elementsDoc = applySlideDesignTokens(elementsDoc, designTokens, ctx.themeTokens || null);
    } else {
      elementsDoc = layoutSlotsToElements(
        { slots: [] },
        content,
        imageRef,
        { width: canvasSize.width, height: canvasSize.height },
        {
          themeTokens: ctx.themeTokens || null,
          designTokens,
          applyShapes: false,
        }
      );
    }

    elementsDoc = finalizeElementsDoc(elementsDoc, layoutSchema, content, ctx.themeTokens || null, {
      width: canvasSize.width,
      height: canvasSize.height,
    });

    if (ctx.themeTokens?.palette?.bg) {
      elementsDoc.backgroundColor = ctx.themeTokens.palette.bg;
    }

    const logo = brandKitService.pickLogoForBackground(ctx.themeTokens);
    elementsDoc = injectBrandLogo(elementsDoc, logo, {
      contentType,
      force: Boolean(ctx.packBound || hasBrandKit),
    });

    const updated = await presentationDao.updateSlide(slide.id, {
      status: 'READY',
      contentType: contentType || null,
      layoutId: layoutId || slide.layoutId || packMeta?.layout_id || null,
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
      layoutIdByOrder: {},
      fullBleedUsed: false,
      userPrompt: resolvedFlow.userPrompt || deck.outline?.sourcePrompt || null,
      preferVisuals,
      wizardBrief: resolvedFlow.wizardBrief || '',
      imageSource: resolvedFlow.imageSource || null,
      imageStylePhrase: resolvedFlow.imageStylePhrase || null,
      canvasSize: resolvedFlow.canvas || generationFlowService.resolveCanvas(deck.aspectRatio),
      baseTemplateBias: resolvedFlow.baseTemplateBias || null,
      layoutIdWhitelist: packBrand.layoutIdWhitelist || resolvedFlow.layoutIdWhitelist || null,
      preferExistingPackLayout: Boolean(packBrand.packId || resolvedFlow.packId),
      packSlides: packBrand.packSlides || resolvedFlow.packSlides || [],
      contentDistribution: resolvedFlow.contentDistribution || null,
      packBound: Boolean(packBrand.packId || resolvedFlow.packId),
      packId: packBrand.packId || resolvedFlow.packId || null,
      forceTextReplace: true,
      forceImageRefresh: Boolean(
        packBrand.packId &&
          resolvedFlow.imageSource !== 'none' &&
          resolvedFlow.imageSource !== 'placeholder'
      ),
    };

    if (resolvedFlow.themeTokens) {
      await presentationDao.updateDeck(deckId, { themeTokens: resolvedFlow.themeTokens });
      ctx.themeTokens = resolvedFlow.themeTokens;
    }

    const pending = (deck.slides || []).filter(
      (s) => s.status === 'PENDING' || s.status === 'GENERATING'
    );

    if (!ctx.packBound && pending.length > 0) {
      await planDeckLayouts(ctx, pending);
    }

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
  voiceAndTone = null,
  audience = null,
  purpose = null,
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
  const pack = await loadDeckPackForOutline(deck);
  let effectiveSlideCount = slideCount;
  let outline;
  let chargeResult;

  const outlineBrandKitId =
    deck.generationMetrics?.deckPack?.brandKitId || null;
  let outlineVoiceAndTone = voiceAndTone || '';
  if (outlineBrandKitId) {
    try {
      const kitTokens = await brandKitService.loadKitThemeTokens(workspaceId, outlineBrandKitId);
      const brandVoice = brandKitService.buildBrandVoiceBrief(kitTokens);
      if (brandVoice) {
        outlineVoiceAndTone = [outlineVoiceAndTone, brandVoice].filter(Boolean).join('\n');
      }
    } catch {
      // optional brand context for outline
    }
  }

  if (pack) {
    const packSlides = Array.isArray(pack.schema?.slides) ? pack.schema.slides : [];
    effectiveSlideCount = packSlides.length || slideCount;
    const skeleton = buildPackOutlineSkeleton(pack, {
      density,
      locale,
      sourceText,
    });

    const llmResult = await chatJson({
      system: outlinePrompt.buildPackEnrichSystem(),
      user: outlinePrompt.buildPackEnrichUser({
        sourceText,
        density,
        locale,
        voiceAndTone: outlineVoiceAndTone,
        audience,
        purpose,
        packSlides: skeleton.slides,
        packNarrative: pack.schema?.narrative || null,
      }),
      model: DEFAULT_OUTLINE_MODEL,
    });

    outline = mergePackOutlineWithLlm(skeleton, llmResult.data, {
      slideCount: effectiveSlideCount,
      density,
      locale,
      sourceText,
    });

    chargeResult = await presentationCredit.chargeOutlineReconcile({
      workspaceId,
      userId,
      deckId: deck.id,
      usage: llmResult.usage,
      idempotencyKey: `ppt:outline:pack:${deck.id}:${hashPayload([source, sourceText.slice(0, 200), String(effectiveSlideCount), density])}`,
      metadata: { projectId: project.id, packId: pack.id },
    });
    await trackCharge(deck.id, chargeResult);
  } else {
    const llmResult = await chatJson({
      system: outlinePrompt.buildSystem(),
      user: outlinePrompt.buildUser({
        sourceText,
        slideCount: effectiveSlideCount,
        density,
        locale,
        audience: audience || '',
        voiceAndTone: outlineVoiceAndTone || '',
        purpose: purpose || '',
      }),
      model: DEFAULT_OUTLINE_MODEL,
    });

    outline = normalizeOutline(llmResult.data, {
      slideCount: effectiveSlideCount,
      density,
      locale,
      sourceText,
    });
    outline = enrichOutlineWithArrangement(outline, {
      sourceText,
      userPrompt: sourceText,
    });

    chargeResult = await presentationCredit.chargeOutlineReconcile({
      workspaceId,
      userId,
      deckId: deck.id,
      usage: llmResult.usage,
      idempotencyKey: `ppt:outline:${deck.id}:${hashPayload([source, sourceText.slice(0, 200), String(effectiveSlideCount), density])}`,
      metadata: { projectId: project.id },
    });
    await trackCharge(deck.id, chargeResult);
  }

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
    creditsCharged: chargeResult?.skipped ? 0 : chargeResult?.charged || chargeResult?.pricing?.athenaCredits || 0,
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
  flowCtx.packSlides = packBrand.packSlides || flowCtx.packSlides || [];
  flowCtx.preferExistingPackLayout = Boolean(packBrand.packId);
  const isPackMode = Boolean(packBrand.packId && packBrand.packSlides?.length);

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

  // Preserve manually edited slides unless overwrite; pack mode re-queues skeleton slides for AI fill
  const existing = deck.slides || [];
  if (overwriteManualEdits) {
    await presentationDao.deleteSlidesByDeckId(deck.id);
  } else if (isPackMode) {
    const outlineOrders = new Set(outlineSlides.map((s) => Number(s.order)));
    const toDelete = existing.filter((s) => !outlineOrders.has(Number(s.order)));
    if (toDelete.length) {
      await prisma.slide.deleteMany({ where: { id: { in: toDelete.map((s) => s.id) } } });
    }
    for (const slide of existing.filter((s) => outlineOrders.has(Number(s.order)))) {
      await presentationDao.updateSlide(slide.id, {
        status: 'PENDING',
        manuallyEdited: false,
      });
    }
    const remainingOrders = new Set(
      existing.filter((s) => outlineOrders.has(Number(s.order))).map((s) => Number(s.order))
    );
    const pendingData = outlineSlides
      .filter((s) => !remainingOrders.has(Number(s.order)))
      .map((s) => ({
        order: Number(s.order),
        contentType: s.suggestedContentType || null,
        layoutId: s.layoutId || null,
        content: null,
        imageRef: null,
        status: 'PENDING',
        manuallyEdited: false,
      }));
    if (pendingData.length) {
      await presentationDao.createSlides(deck.id, pendingData);
    }
  } else {
    const toDelete = existing.filter((s) => !s.manuallyEdited).map((s) => s.id);
    if (toDelete.length) {
      await prisma.slide.deleteMany({ where: { id: { in: toDelete } } });
    }
  }

  if (!isPackMode && !overwriteManualEdits) {
    const blankStarters = existing.filter((s) => isBlankStarterSlide(s));
    for (const slide of blankStarters) {
      await presentationDao.updateSlide(slide.id, {
        status: 'PENDING',
        manuallyEdited: false,
      });
    }

    const preserved = existing.filter((s) => s.manuallyEdited && !isBlankStarterSlide(s));
    const preservedOrders = new Set(preserved.map((s) => Number(s.order)));
    const requeuedOrders = new Set(blankStarters.map((s) => Number(s.order)));

    const pendingData = outlineSlides
      .filter(
        (s) =>
          !preservedOrders.has(Number(s.order)) && !requeuedOrders.has(Number(s.order))
      )
      .map((s) => ({
        order: Number(s.order),
        contentType: s.suggestedContentType || null,
        layoutId: s.layoutId || null,
        content: null,
        imageRef: null,
        status: 'PENDING',
        manuallyEdited: false,
      }));

    if (pendingData.length) {
      await presentationDao.createSlides(deck.id, pendingData);
    }
  } else if (overwriteManualEdits) {
    const pendingData = outlineSlides.map((s) => ({
      order: Number(s.order),
      contentType: s.suggestedContentType || null,
      layoutId: s.layoutId || null,
      content: null,
      imageRef: null,
      status: 'PENDING',
      manuallyEdited: false,
    }));
    if (pendingData.length) {
      await presentationDao.createSlides(deck.id, pendingData);
    }
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
    deckStatus: deck.status,
    message: null,
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
  const normalizedTarget =
    String(target || 'all').toLowerCase() === 'full' ? 'all' : String(target || 'all').toLowerCase();
  target = normalizedTarget;
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
    reset.elements = null;
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
    layoutIdByOrder: {},
    fullBleedUsed: false,
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
    packSlides: packBrand.packSlides || flowCtx.packSlides || [],
    contentDistribution: flowCtx.contentDistribution || null,
    packBound: Boolean(packBrand.packId),
    packId: packBrand.packId || flowCtx.packId || null,
    forceTextReplace: true,
    forceImageRefresh: target === 'image' || Boolean(packBrand.packId),
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
            let layoutSchema = null;
            if (fresh.layoutId) {
              const rows = await presentationDao.findLayoutsByLayoutIds([fresh.layoutId]);
              layoutSchema = rows[0]?.schema || null;
            }
            const layoutCtx = layoutContextFromSchema(layoutSchema);
            const briefResult = await chatJson({
              system: briefPrompt.buildSystem(),
              user: briefPrompt.buildUser({
                slideTitle: content?.title,
                slideContent: content,
                themeImageStyle: ctx.imageStylePhrase || ctx.themeTokens?.imageStyle,
                themeColorTreatment: imageColorTreatmentForCtx(ctx),
                wizardBrief: ctx.wizardBrief || '',
                authorImagePrompt: resolveAuthorImagePrompt(content),
                layoutContext: layoutCtx,
                layoutId: layoutSchema?.layout_id || fresh.layoutId || null,
                hasImageOverlay: layoutCtx.hasImageOverlay,
                visualNeed,
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

  let nextContent =
    patch.content !== undefined
      ? patch.content && typeof patch.content === 'object'
        ? { ...patch.content }
        : patch.content
      : slide.content && typeof slide.content === 'object'
        ? { ...slide.content }
        : {};

  if (patch.title !== undefined) {
    nextContent = { ...(nextContent || {}), title: patch.title };
  }
  if (patch.background !== undefined) {
    nextContent = { ...(nextContent || {}), background: patch.background };
  }

  if (
    patch.content !== undefined ||
    patch.title !== undefined ||
    patch.background !== undefined
  ) {
    data.content = nextContent;
  }
  if (patch.layoutId !== undefined) data.layoutId = patch.layoutId;
  if (patch.contentType !== undefined) data.contentType = patch.contentType;
  if (patch.imageRef !== undefined) data.imageRef = patch.imageRef;
  if (patch.elements !== undefined) {
    const { normalizeCanvasDoc } = require('./elementContent.normalize');
    data.elements = normalizeCanvasDoc(patch.elements);
  }

  const updated = await presentationDao.updateSlide(slideId, data);
  const { enrichSlideForClient } = require('./elementContent.normalize');
  return { slide: enrichSlideForClient(updated) };
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
