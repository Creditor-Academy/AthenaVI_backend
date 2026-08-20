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
const { filterTemplatesForSlideOrder, closingLayoutExcludeIds, isSplitHeroLayout } = require('./layoutSelector.service');
const { pickLayoutForGeneratedSlide } = require('./deckLayout/pickLayoutForGeneratedSlide');
const { toDeckLayout } = require('./deckLayout/toDeckLayout');
const { toSlideContentProfile } = require('./deckLayout/toSlideContentProfile');
const { rankLayouts } = require('./deckLayout/rankLayouts');
const { planDeckVisualRhythm } = require('./artDirection/deckVisualRhythm');
const {
  planDeckImageDistribution,
  applyDeckImageStrategyToVisualNeed,
} = require('./artDirection/imageDistribution');
const { buildSlideDesignPlan } = require('./artDirection/buildSlideDesignPlan');
const { buildDeckArtDirection } = require('./artDirection/buildDeckArtDirection');
const { resolveStickyBrandColors } = require('./artDirection/semanticTheme');
const themeService = require('./theme.service');
const { enforceAppearancePalette } = themeService;
const {
  enrichOutlineWithArrangement,
  preferredLayoutForSlide,
} = require('./slideArrangementPlan.service');
const { validateSlide } = require('./layoutQa.service');
const {
  analyzeChartStory,
  chartDatasetCount: countChartDatasets,
  inferChartTypeFromStory,
} = require('./chartStory.util');
const { resolveTitlePreferredLayoutId } = require('./titleLayout.util');
const imageCache = require('./imageCache.service');
const documentParse = require('./documentParse.service');
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
const { isCatalogPlaceholderText } = require('./catalogPlaceholder');
const blueprintSeed = require('./blueprintSeed');
const templateMediaService = require('../templates/templateMedia.service');
const templateMediaDao = require('../templates/templateMedia.dao');
const { AI_SLIDE_MAX } = require('./presentation.constants');
const generationFlowService = require('./generationFlow.service');
const brandKitService = require('../brandKit/brandKit.service');
const fontPairingService = require('./fontPairing.service');
const layoutCatalogPolicy = require('./layoutCatalogPolicy');

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
  const visual = typeof content.visual === 'string' ? content.visual.trim() : '';
  return visual;
}

const SINGLE_SUBJECT_NEGATIVES =
  'no triptych, no multi-panel, no split image, no collage, no diptych, no grid, no multiple cups, no comparison sheet, no split frame';

function deriveSlotImagePromptBase(slotId, content = {}, layoutSchema = null) {
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

function buildSlotImagePrompt(slotId, content = {}, layoutSchema = null) {
  const id = String(slotId || '');
  let subject = deriveSlotImagePromptBase(id, content, layoutSchema) || '';

  const imageMatch = id.match(/^IMAGE_(\d+)$/i);
  if (imageMatch) {
    const idx = Number(imageMatch[1]) - 1;
    const col =
      (content.columns || content.cards || content.features || content.items || [])[idx];
    if (col && typeof col === 'object') {
      const title = String(col.title ?? col.heading ?? col.label ?? '').trim();
      const body = String(col.body ?? col.text ?? col.description ?? '').trim();
      if (title) {
        subject = body ? `${title}: ${body.slice(0, 80)}` : title;
      }
    }
  }

  if (!subject) {
    subject = String(content?.title || 'Slide topic').trim();
  }

  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const imageSlots = slots.filter((s) => isMediaImageSlot(s.id, s.role, s));
  const slotIndex = Math.max(0, imageSlots.findIndex((s) => String(s.id) === id));
  const layoutId = String(layoutSchema?.layout_id || '').trim();

  return [
    `${id}${layoutId ? ` of ${layoutId}` : ''}: isolated single object on plain background`,
    /four_images|grid_.*images|three_cards_image/i.test(layoutId)
      ? 'Gallery slot — ONE single object fills the entire frame edge to edge'
      : null,
    `Single photograph, ONE subject only, no collage: ${subject}`,
    `(variation ${slotIndex + 1})`,
    SINGLE_SUBJECT_NEGATIVES,
  ]
    .filter(Boolean)
    .join('. ');
}

function deriveSlotImagePrompt(slotId, content = {}, layoutSchema = null) {
  return buildSlotImagePrompt(slotId, content, layoutSchema);
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
  const needsColumns =
    slots.some((s) => /^(card|col)_\d+_(title|body)$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^bullet_\d+$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^body_\d+$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^image_\d+_label$/i.test(String(s.id || ''))) ||
    slots.some((s) => /^IMAGE_\d+$/i.test(String(s.id || '')));
  if (!needsColumns) return content;

  let colsKey = Array.isArray(content.columns)
    ? 'columns'
    : Array.isArray(content.cards)
      ? 'cards'
      : Array.isArray(content.features)
        ? 'features'
        : null;

  const next = { ...content };

  if (!colsKey) {
    const bullets = Array.isArray(content.bullets) ? content.bullets : [];
    const items = Array.isArray(content.items) ? content.items : [];
    const indexedSlotCount = Math.max(
      slots.filter((s) => /^bullet_\d+$/i.test(String(s.id || ''))).length,
      slots.filter((s) => /^body_\d+$/i.test(String(s.id || ''))).length,
      slots.filter((s) => /^IMAGE_\d+$/i.test(String(s.id || ''))).length
    );
    if (items.length >= 2) {
      next.columns = items.map((item, index) => {
        if (typeof item === 'string') {
          const text = item.trim();
          const split = text.split(/[:\-—–]\s*/);
          return {
            title: split.length > 1 ? split[0].trim() : titleWordsFromBody(text, `Item ${index + 1}`),
            body: split.length > 1 ? split.slice(1).join(' ').trim() : text,
          };
        }
        return {
          title: String(item.title ?? item.heading ?? item.label ?? titleWordsFromBody(item.body ?? item.text ?? '', `Item ${index + 1}`)).trim(),
          body: String(item.body ?? item.text ?? item.description ?? '').trim(),
        };
      });
      colsKey = 'columns';
    } else if (bullets.length >= 2) {
      next.columns = bullets.map((bullet, index) => {
        const text = typeof bullet === 'string' ? bullet.trim() : String(bullet?.text ?? bullet?.label ?? '').trim();
        const split = text.split(/[:\-—–]\s*/);
        const inlineTitle = split.length > 1 ? split[0].trim() : '';
        const body = split.length > 1 ? split.slice(1).join(' ').trim() : text;
        return {
          title: inlineTitle || titleWordsFromBody(body, `Point ${index + 1}`),
          body,
        };
      });
      colsKey = 'columns';
    } else if (indexedSlotCount >= 2) {
      const summary = String(content.summary || content.body || content.subtitle || '').trim();
      const parts = summary.split(/[.;]\s+/).map((part) => part.trim()).filter(Boolean);
      if (parts.length >= 2) {
        next.columns = Array.from({ length: indexedSlotCount }, (_, index) => {
          const body = parts[index] || parts[index % parts.length] || summary.slice(0, 120);
          return {
            title: titleWordsFromBody(body, `Point ${index + 1}`),
            body,
          };
        });
        colsKey = 'columns';
      }
    }
  }

  if (!colsKey) return content;

  next[colsKey] = [...next[colsKey]];
  const slideTitle = String(next.title || '').trim().toLowerCase();
  const seen = new Set();

  next[colsKey] = next[colsKey].map((col, index) => {
    if (!col || typeof col !== 'object') return col;
    const copy = { ...col };
    let title = String(copy.title ?? copy.heading ?? copy.label ?? '').trim();
    const body = String(copy.body ?? copy.text ?? '').trim();
    const titleLower = title.toLowerCase();

    // Hard rule: never reuse the slide title (or duplicates) as every column heading.
    if (!title || titleLower === slideTitle || seen.has(titleLower)) {
      const fromBody = titleWordsFromBody(body, '');
      const fromBodyLower = String(fromBody || '').trim().toLowerCase();
      if (fromBody && fromBodyLower !== slideTitle && !seen.has(fromBodyLower)) {
        title = fromBody;
      } else {
        title = `Aspect ${index + 1}`;
      }
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
        buildSlotImagePrompt(slotId, next, layoutSchema) ||
        '';
      prompt = String(prompt).trim();
      const col = next[colsKey][index];
      const colTitle = col ? String(col.title ?? col.heading ?? '').trim() : '';
      if (!prompt || usedPrompts.has(prompt.toLowerCase())) {
        prompt = buildSlotImagePrompt(slotId, next, layoutSchema);
        if (!prompt && colTitle) {
          prompt = `Single photograph, ONE subject only: ${colTitle} (variation ${index + 1}). ${SINGLE_SUBJECT_NEGATIVES}`;
        }
      }
      usedPrompts.add(prompt.toLowerCase());
      imagePrompts[slotId] = prompt;
    });
    next.imagePrompts = imagePrompts;
  }

  return next;
}

function listGalleryImageSlots(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots
    .filter((s) => {
      const id = String(s.id || '').toUpperCase();
      return String(s.role || '').toLowerCase() === 'image' && /^IMAGE_\d+$/.test(id);
    })
    .sort(
      (a, b) =>
        Number(String(a.id).match(/\d+/)?.[0] || 0) - Number(String(b.id).match(/\d+/)?.[0] || 0)
    );
}

function layoutUsesPerSlotGalleryImages(layoutSchema) {
  const gallerySlots = listGalleryImageSlots(layoutSchema);
  if (gallerySlots.length < 2) return false;
  const slots = layoutSchema?.slots || [];
  const hasSingleHero = slots.some((s) => {
    const id = String(s.id || '').toUpperCase();
    return id === 'HERO_IMAGE' || id === 'BACKGROUND_IMAGE';
  });
  return !hasSingleHero;
}

function normalizeGalleryImageContent(content, layoutSchema) {
  const gallerySlots = listGalleryImageSlots(layoutSchema);
  if (gallerySlots.length < 2 || !content || typeof content !== 'object') return content;

  const needed = gallerySlots.length;
  const next = { ...content };
  let columns = Array.isArray(content.columns) ? [...content.columns] : [];

  if (columns.length < needed) {
    const items = Array.isArray(content.items) ? content.items : [];
    const bullets = Array.isArray(content.bullets) ? content.bullets : [];
    const summary = String(content.summary || content.body || content.subtitle || '').trim();
    const parts = summary.split(/[.;]\s+/).map((part) => part.trim()).filter(Boolean);

    if (items.length >= needed) {
      columns = items.slice(0, needed).map((item, index) => {
        if (typeof item === 'string') {
          const text = item.trim();
          const split = text.split(/[:\-—–]\s*/);
          return {
            title: split[0]?.trim() || titleWordsFromBody(text, `Item ${index + 1}`),
            body: split.slice(1).join(' ').trim() || text,
          };
        }
        return {
          title: String(item.title ?? item.label ?? item.heading ?? `Item ${index + 1}`).trim(),
          body: String(item.body ?? item.text ?? '').trim(),
        };
      });
    } else if (bullets.length >= 2) {
      columns = bullets.slice(0, needed).map((bullet, index) => {
        const text = typeof bullet === 'string' ? bullet.trim() : String(bullet?.text ?? bullet?.label ?? '').trim();
        const split = text.split(/[:\-—–]\s*/);
        return {
          title: split[0]?.trim() || titleWordsFromBody(text, `Item ${index + 1}`),
          body: split.slice(1).join(' ').trim() || text,
        };
      });
    } else if (parts.length >= 2) {
      columns = Array.from({ length: needed }, (_, index) => {
        const body = parts[index] || parts[index % parts.length] || summary.slice(0, 100);
        return {
          title: titleWordsFromBody(body, `Gallery ${index + 1}`),
          body,
        };
      });
    } else {
      const slideTitle = String(content.title || 'Topic').trim();
      columns = Array.from({ length: needed }, (_, index) => ({
        title: titleWordsFromBody(`${slideTitle} aspect ${index + 1}`, `Gallery ${index + 1}`),
        body: `Visual ${index + 1} illustrating ${slideTitle}`,
      }));
    }
  }

  const slideTitleLower = String(next.title || '').trim().toLowerCase();
  const seenTitles = new Set();
  next.columns = columns.slice(0, needed).map((col, index) => {
    const copy = col && typeof col === 'object' ? { ...col } : { title: '', body: '' };
    let title = String(copy.title ?? copy.heading ?? copy.label ?? '').trim();
    const body = String(copy.body ?? copy.text ?? '').trim();
    const titleLower = title.toLowerCase();
    if (!title || titleLower === slideTitleLower || seenTitles.has(titleLower)) {
      const fromBody = titleWordsFromBody(body, '');
      const fromBodyLower = String(fromBody || '').trim().toLowerCase();
      if (fromBody && fromBodyLower !== slideTitleLower && !seenTitles.has(fromBodyLower)) {
        title = fromBody;
      } else {
        title = `Gallery ${index + 1}`;
      }
      copy.title = title;
      if (copy.heading != null) copy.heading = title;
      if (copy.label != null) copy.label = title;
    }
    seenTitles.add(String(copy.title ?? title).trim().toLowerCase());
    if (body) copy.body = body;
    return copy;
  });

  const imagePrompts = {
    ...(next.imagePrompts && typeof next.imagePrompts === 'object' ? next.imagePrompts : {}),
  };
  const usedPrompts = new Set();
  gallerySlots.forEach((slot, index) => {
    const slotId = String(slot.id);
    const col = next.columns[index];
    const colTitle = col ? String(col.title ?? col.heading ?? col.label ?? '').trim() : '';
    let prompt = String(
      imagePrompts[slotId] || imagePrompts[slotId.toUpperCase()] || imagePrompts[slotId.toLowerCase()] || ''
    ).trim();
    if (!prompt || usedPrompts.has(prompt.toLowerCase())) {
      prompt = buildSlotImagePrompt(slotId, next, layoutSchema);
    }
    if (!prompt && colTitle) {
      prompt = [
        `${slotId}: single photograph of ONE ${colTitle} only`,
        `One isolated ${colTitle}, plain background, centered composition`,
        `(variation ${index + 1})`,
        SINGLE_SUBJECT_NEGATIVES,
      ].join('. ');
    }
    if (prompt) {
      usedPrompts.add(prompt.toLowerCase());
      imagePrompts[slotId] = prompt;
    }
  });
  next.imagePrompts = imagePrompts;

  return next;
}

function normalizeTimelineContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;

  const slots = layoutSchema.slots;
  const layoutId = String(layoutSchema.layout_id || '');
  const isTimeline =
    /timeline/i.test(layoutId) || slots.some((s) => /^milestone_/i.test(String(s.id || '')));
  if (!isTimeline) return content;

  const key = Array.isArray(content.timeline)
    ? 'timeline'
    : Array.isArray(content.milestones)
      ? 'milestones'
      : Array.isArray(content.events)
        ? 'events'
        : 'timeline';

  let items = Array.isArray(content[key]) ? [...content[key]] : [];
  if (items.length < 2 && Array.isArray(content.bullets) && content.bullets.length) {
    items = content.bullets.map((bullet) => {
      const text = typeof bullet === 'string' ? bullet : String(bullet?.text ?? bullet?.label ?? '');
      return text.trim();
    }).filter(Boolean);
  }

  const milestoneSlots = slots.filter(
    (s) => /^milestone_\d+$/i.test(String(s.id || '')) || /^milestone_\d+_label$/i.test(String(s.id || ''))
  );
  const needed = Math.max(2, milestoneSlots.length || 4);
  const summary = String(content.summary || content.body || content.subtitle || '').trim();
  const summaryParts = summary
    ? summary.split(/[.;]\s+/).map((part) => part.trim()).filter(Boolean)
    : [];

  const normalized = items.map((item, index) => {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      const yearOnly = /^\d{4}$/.test(trimmed);
      const split = trimmed.split(/[:\-—–]\s*/);
      const label = yearOnly ? trimmed : (split[0] || trimmed).trim();
      const inlineDetail = yearOnly ? '' : split.slice(1).join(' ').trim();
      const detail =
        inlineDetail ||
        summaryParts[index % Math.max(summaryParts.length, 1)] ||
        (summary ? summary.slice(0, 120) : `Key milestone ${index + 1}`);
      return { label, detail };
    }

    const copy = { ...item };
    let label = String(
      copy.label ?? copy.date ?? copy.year ?? copy.period ?? copy.title ?? copy.name ?? ''
    ).trim();
    let detail = String(copy.detail ?? copy.body ?? copy.text ?? copy.description ?? copy.summary ?? '').trim();
    if (!label) {
      label = String(copy.value ?? copy.head ?? `Phase ${index + 1}`).trim();
    }
    if (!detail) {
      detail =
        summaryParts[index % Math.max(summaryParts.length, 1)] ||
        (summary ? summary.slice(0, 120) : `Key development for ${label || `milestone ${index + 1}`}`);
    }
    return { ...copy, label, detail };
  });

  while (normalized.length < needed) {
    const n = normalized.length + 1;
    normalized.push({
      label: String(2010 + n * 3),
      detail: summaryParts[n % Math.max(summaryParts.length, 1)] || summary.slice(0, 100) || `Milestone ${n}`,
    });
  }

  const imageSlots = slots.filter((s) => {
    const id = String(s.id || '').toUpperCase();
    return String(s.role || '').toLowerCase() === 'image' || /^IMAGE_\d+$/.test(id);
  });

  const next = {
    ...content,
    [key]: normalized,
    timeline: key === 'timeline' ? normalized : content.timeline || normalized,
  };

  if (
    imageSlots.length > 1 &&
    (!Array.isArray(content.columns) || content.columns.length < imageSlots.length)
  ) {
    next.columns = normalized.slice(0, imageSlots.length).map((item) => ({
      title: String(item.label ?? item.title ?? item.period ?? '').trim(),
      body: String(item.detail ?? item.body ?? item.text ?? '').trim(),
    }));
  }

  return next;
}

function layoutNeedsDiagramCellsFromSchema(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((slot) => {
    const id = String(slot.id || '').toLowerCase();
    return /^q\d+_body$/i.test(id) || /^funnel_\d+_body$/i.test(id) || /^step_\d+_body$/i.test(id);
  });
}

function countDiagramCellSlotsFromSchema(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const quadrantBodies = slots.filter((s) => /^q\d+_body$/i.test(String(s.id || ''))).length;
  const funnelBodies = slots.filter((s) => /^funnel_\d+_body$/i.test(String(s.id || ''))).length;
  const stepBodies = slots.filter((s) => /^step_\d+_body$/i.test(String(s.id || ''))).length;
  return Math.max(quadrantBodies, funnelBodies, stepBodies, 0);
}

function schemaTitleForDiagramSlot(slots, index, kind) {
  if (kind === 'quadrant') {
    const slot = slots.find((s) => String(s.id).toUpperCase() === `Q${index + 1}_TITLE`);
    return slot?.placeholder_text ? String(slot.placeholder_text).trim() : '';
  }
  if (kind === 'funnel') {
    const slot = slots.find((s) => String(s.id).toLowerCase() === `funnel_${index + 1}_title`);
    return slot?.placeholder_text ? String(slot.placeholder_text).trim() : '';
  }
  const slot = slots.find((s) => String(s.id).toLowerCase() === `step_${index + 1}_title`);
  return slot?.placeholder_text ? String(slot.placeholder_text).trim() : '';
}

function normalizeDiagramContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const slots = layoutSchema.slots;
  if (!layoutNeedsDiagramCellsFromSchema(layoutSchema)) return content;

  const existing =
    content.diagram?.cells ||
    content.cells ||
    content.quadrants ||
    content.steps ||
    content.funnel;
  const hasValidCells =
    Array.isArray(existing) &&
    existing.some((cell) => {
      const body = String(cell?.body ?? cell?.text ?? cell?.detail ?? '').trim();
      return body && !isCatalogPlaceholderText(body);
    });
  if (hasValidCells) {
    const cells = [...existing];
    return {
      ...content,
      diagram: { ...(content.diagram || {}), type: content.diagram?.type || 'diagram', cells },
      cells,
    };
  }

  const needed = Math.max(2, countDiagramCellSlotsFromSchema(layoutSchema) || 4);
  const kind = slots.some((s) => /^q\d+_body$/i.test(String(s.id || '')))
    ? 'quadrant'
    : slots.some((s) => /^funnel_\d+_body$/i.test(String(s.id || '')))
      ? 'funnel'
      : 'step';

  const sourceCols = content.columns || content.cards || content.features || [];
  const sourceBullets = Array.isArray(content.bullets) ? content.bullets : [];
  const sourceItems = Array.isArray(content.items) ? content.items : [];
  const summaryParts = String(content.summary || content.body || content.subtitle || '')
    .split(/[.;]\s+/)
    .map((part) => part.trim())
    .filter(Boolean);

  const cells = [];
  for (let i = 0; i < needed; i += 1) {
    const schemaTitle = schemaTitleForDiagramSlot(slots, i, kind);
    let title = schemaTitle;
    let body = '';

    const col = sourceCols[i];
    if (col && typeof col === 'object') {
      title = String(col.title ?? col.heading ?? col.label ?? schemaTitle).trim() || schemaTitle;
      body = String(col.body ?? col.text ?? '').trim();
    } else if (sourceItems[i]) {
      const item = sourceItems[i];
      if (typeof item === 'string') {
        body = item.trim();
        title = titleWordsFromBody(body, schemaTitle || `Point ${i + 1}`);
      } else {
        title = String(item.title ?? item.heading ?? item.label ?? schemaTitle).trim();
        body = String(item.body ?? item.text ?? item.detail ?? '').trim();
      }
    } else if (sourceBullets[i]) {
      const bullet = sourceBullets[i];
      body = typeof bullet === 'string' ? bullet.trim() : String(bullet?.text ?? bullet?.label ?? '').trim();
      title = titleWordsFromBody(body, schemaTitle || `Point ${i + 1}`);
    }

    if (!body) {
      body = summaryParts[i % Math.max(summaryParts.length, 1)] || '';
    }
    if (!title) title = schemaTitle || `Section ${i + 1}`;

    cells.push({ title, body });
  }

  const slideTitleLower = String(content.title || '').trim().toLowerCase();
  const seen = new Set();
  for (let i = 0; i < cells.length; i += 1) {
    let title = String(cells[i].title || '').trim();
    const body = String(cells[i].body || '').trim();
    const titleLower = title.toLowerCase();
    if (!title || titleLower === slideTitleLower || seen.has(titleLower)) {
      const fromBody = titleWordsFromBody(body, '');
      const fromBodyLower = String(fromBody || '').toLowerCase();
      title =
        fromBody && fromBodyLower !== slideTitleLower && !seen.has(fromBodyLower)
          ? fromBody
          : `Section ${i + 1}`;
      cells[i] = { ...cells[i], title };
    }
    seen.add(String(cells[i].title || '').trim().toLowerCase());
  }

  return {
    ...content,
    diagram: { ...(content.diagram || {}), type: content.diagram?.type || kind, cells },
    cells,
  };
}

async function assertDistinctSlotImageUrls({ ctx, slide, content, layoutSchema, slotImageUrls }) {
  const slotIds = templateMediaService.listLayoutImageSlots(layoutSchema);
  if (slotIds.length <= 1) return slotImageUrls;

  let next = { ...(slotImageUrls || {}) };
  if (ctx.imageSource === 'none' || ctx.imageSource === 'placeholder') return next;

  const maxPasses = 3;
  for (let pass = 0; pass < maxPasses; pass += 1) {
    const urlToSlots = new Map();
    for (const slotId of slotIds) {
      const url = next[slotId];
      if (!url) continue;
      if (!urlToSlots.has(url)) urlToSlots.set(url, []);
      urlToSlots.get(url).push(slotId);
    }

    let fixedAny = false;
    for (const [url, slotsWithUrl] of urlToSlots) {
      if (slotsWithUrl.length <= 1) continue;
      for (let i = 1; i < slotsWithUrl.length; i += 1) {
        const slotId = slotsWithUrl[i];
        delete next[slotId];
        const basePrompt = buildSlotImagePrompt(slotId, content, layoutSchema);
        const prompt = `${basePrompt} (variation ${pass + i + 1}, completely different subject)`;
        try {
          const generated = await generateSlotImage({
            ctx,
            slide,
            slotId,
            prompt,
            layoutSchema,
          });
          if (generated?.url && generated.url !== url) {
            next[slotId] = generated.url;
            fixedAny = true;
          }
        } catch (err) {
          logger.warn?.('presentation_slot_image_distinct_regen_failed', {
            slideId: slide.id,
            slotId,
            pass: pass + 1,
            error: err.message,
          });
        }
      }
    }
    if (!fixedAny) break;
  }

  const remainingDupes = new Set();
  const seen = new Set();
  for (const slotId of slotIds) {
    const url = next[slotId];
    if (!url) continue;
    if (seen.has(url)) remainingDupes.add(url);
    seen.add(url);
  }
  if (remainingDupes.size) {
    logger.warn?.('presentation_slot_image_duplicates_remain', {
      slideId: slide.id,
      duplicateCount: remainingDupes.size,
    });
    const seenUrls = new Set();
    for (const slotId of slotIds) {
      const url = next[slotId];
      if (!url) continue;
      if (seenUrls.has(url)) {
        try {
          const ph = await generationFlowService.ensurePlaceholderImage({
            slotIndex: slotIds.indexOf(slotId) + 1,
            seed: `${slide.id}-${slotId}-dedupe`,
          });
          if (ph?.url && ph.url !== url) {
            next[slotId] = ph.url;
            seenUrls.add(ph.url);
          } else {
            // Keep original rather than leaving empty — compile can still show something.
            next[slotId] = `${url}${url.includes('?') ? '&' : '?'}slot=${encodeURIComponent(slotId)}`;
            seenUrls.add(next[slotId]);
          }
        } catch {
          next[slotId] = `${url}${url.includes('?') ? '&' : '?'}slot=${encodeURIComponent(slotId)}`;
          seenUrls.add(next[slotId]);
        }
      } else {
        seenUrls.add(url);
      }
    }
  }

  return next;
}

async function repairSlotImagesFromQa({ ctx, slide, content, layoutSchema, slotImageUrls }) {
  const slotIds = templateMediaService.listLayoutImageSlots(layoutSchema);
  if (slotIds.length <= 1) return slotImageUrls;

  let next = { ...(slotImageUrls || {}) };
  if (ctx.imageSource === 'none' || ctx.imageSource === 'placeholder') return next;

  const urlToSlots = new Map();
  for (const slotId of slotIds) {
    const url = next[slotId];
    if (!url) continue;
    if (!urlToSlots.has(url)) urlToSlots.set(url, []);
    urlToSlots.get(url).push(slotId);
  }

  for (const [url, slotsWithUrl] of urlToSlots) {
    if (slotsWithUrl.length <= 1) continue;
    for (let i = 1; i < slotsWithUrl.length; i += 1) {
      const slotId = slotsWithUrl[i];
      delete next[slotId];
      const prompt = `${buildSlotImagePrompt(slotId, content, layoutSchema)} (unique subject ${i + 1}, must differ from other slots)`;
      try {
        const generated = await generateSlotImage({ ctx, slide, slotId, prompt, layoutSchema });
        if (generated?.url && generated.url !== url) {
          next[slotId] = generated.url;
          continue;
        }
      } catch (err) {
        logger.warn?.('presentation_slot_image_qa_repair_failed', {
          slideId: slide.id,
          slotId,
          error: err.message,
        });
      }
      try {
        const ph = await generationFlowService.ensurePlaceholderImage({
          slotIndex: slotIds.indexOf(slotId) + 1,
          seed: `${slide.id}-${slotId}-qa`,
        });
        if (ph?.url) next[slotId] = ph.url;
      } catch {
        next[slotId] = `${url}${url.includes('?') ? '&' : '?'}slot=${encodeURIComponent(slotId)}`;
      }
    }
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
  outlineSlide = {},
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
            subtitle: outlineSlide.subtitle || nextContent?.subtitle || '',
            beats: outlineSlide.beats || [],
            visual: outlineSlide.visual || '',
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
      nextContent = normalizeGalleryImageContent(nextContent, template.schema);
      nextContent = normalizeChartContent(nextContent, template.schema);
      nextContent = normalizeTimelineContent(nextContent, template.schema);
      nextContent = normalizeDiagramContent(nextContent, template.schema);
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

async function loadAllLayoutTemplates(layoutIdWhitelist = null) {
  return resolveLayoutTemplates(null, { layoutIdWhitelist });
}

function isOutlineLayoutLocked(outlineSlide, slide) {
  const raw =
    outlineSlide?.layoutLocked ??
    outlineSlide?.layout_locked ??
    slide?.layoutLocked ??
    slide?.layout_locked ??
    false;
  if (typeof raw === 'string') {
    const t = raw.trim().toLowerCase();
    return t === 'true' || t === '1' || t === 'yes' || t === 'locked';
  }
  return Boolean(raw);
}

function outlineLayoutIdForSlide(outlineSlide, slide) {
  if (!isOutlineLayoutLocked(outlineSlide, slide)) return '';
  return String(
    outlineSlide?.layoutId || outlineSlide?.layout_id || slide?.layoutId || slide?.layout_id || ''
  ).trim();
}

function finalizeBlueprintOutline(outline, metas, policy, slideCount) {
  const target = slideCount || outline?.slideCount || outline?.slides?.length;
  let slides = layoutCatalogPolicy.enforceSlideCount(outline.slides || [], target);
  slides = layoutCatalogPolicy.coerceOutlineLayouts(slides, metas, {
    slideCount: target,
    imageType: policy?.imageType,
  });
  slides = layoutCatalogPolicy.ensureDeckMix(slides, metas, policy);
  slides = layoutCatalogPolicy.coerceOutlineLayouts(slides, metas, {
    slideCount: target,
    imageType: policy?.imageType,
  });
  slides = layoutCatalogPolicy.enforceChartDensityCap(slides);
  return {
    ...outline,
    slides,
    slideCount: slides.length,
    layoutChoices: layoutCatalogPolicy.layoutChoicesForUi(metas),
  };
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

function contentNeedsFreshGeneration(content, layoutSchema = null) {
  if (!content || typeof content !== 'object') return true;
  const title = String(content.title || '').trim();
  if (!title) return true;
  if (isPackPlaceholderText(title)) return true;
  if (title === 'Untitled Presentation') return true;
  if (blueprintSeed.contentMissingRequiredCopy(content, layoutSchema)) return true;

  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];

  if (slots.some((s) => /^(card|col)_\d+_(title|body)$/i.test(String(s.id || '')))) {
    const cols = content.columns || content.cards || content.features || [];
    const minCols =
      slots.filter((s) => /^card_\d+_title$/i.test(String(s.id || ''))).length || 2;
    const validCols = cols.filter((col) => {
      const body = String(col?.body ?? col?.text ?? '').trim();
      return body && !isCatalogPlaceholderText(body);
    });
    if (validCols.length < minCols) return true;
  }

  if (layoutNeedsDiagramCellsFromSchema(layoutSchema)) {
    const cells = content.diagram?.cells || content.cells || content.quadrants || [];
    const minCells = countDiagramCellSlotsFromSchema(layoutSchema) || 2;
    const validCells = cells.filter((cell) => {
      const body = String(cell?.body ?? cell?.text ?? cell?.detail ?? '').trim();
      return body && !isCatalogPlaceholderText(body);
    });
    if (validCells.length < minCells) return true;
  }

  if (slots.some((s) => /^bullet_\d+$/i.test(String(s.id || '')) || /^body_\d+$/i.test(String(s.id || '')))) {
    const cols = content.columns || [];
    const minSlots = slots.filter(
      (s) => /^bullet_\d+$/i.test(String(s.id || '')) || /^body_\d+$/i.test(String(s.id || ''))
    ).length;
    if (cols.length < minSlots) {
      const bullets = Array.isArray(content.bullets) ? content.bullets : [];
      const validBullets = bullets.filter((b) => {
        const t = typeof b === 'string' ? b : b?.text || '';
        return t && !isCatalogPlaceholderText(t);
      });
      if (validBullets.length < Math.min(minSlots, 2)) return true;
    }
  }

  if (slots.some((s) => /^item_\d+$/i.test(String(s.id || '')))) {
    const items = content.items || [];
    const minItems = slots.filter((s) => /^item_\d+$/i.test(String(s.id || ''))).length;
    const validItems = items.filter((item) => {
      const t = typeof item === 'string' ? item : String(item?.title ?? item?.text ?? item?.body ?? '');
      return t && !isCatalogPlaceholderText(t);
    });
    if (validItems.length < minItems) return true;
  }

  const gallerySlots = slots.filter(
    (s) => String(s.role || '').toLowerCase() === 'image' && /^IMAGE_\d+$/i.test(String(s.id || ''))
  );
  if (gallerySlots.length >= 2) {
    const cols = content.columns || [];
    if (cols.length < gallerySlots.length) return true;
    const validCols = cols.filter((col) => {
      const title = String(col?.title ?? col?.heading ?? col?.label ?? '').trim();
      return title && !isCatalogPlaceholderText(title);
    });
    if (validCols.length < gallerySlots.length) return true;
  }

  const bullets = Array.isArray(content.bullets) ? content.bullets : [];
  const hasBullets = bullets.some((b) => {
    const t = typeof b === 'string' ? b : b?.text || '';
    return t && !isPackPlaceholderText(t);
  });
  const body = String(content.body || '').trim();
  if (hasBullets || (body && !isPackPlaceholderText(body))) return false;

  if (
    slots.some((s) =>
      /^(card|col)_\d+|^q\d+_body|^funnel_\d+_body|^step_\d+_body|^bullet_\d+|^item_\d+/i.test(
        String(s.id || '')
      )
    )
  ) {
    return true;
  }

  return !title || isPackPlaceholderText(title);
}

async function loadPackAndBrandForGenerate({ workspaceId, deck, flowCtx }) {
  const metricsPack =
    deck.generationMetrics && typeof deck.generationMetrics === 'object'
      ? deck.generationMetrics.deckPack
      : null;

  const packId = flowCtx.packId || metricsPack?.packId || null;
  const brandKitId = flowCtx.brandKitId || metricsPack?.brandKitId || null;
  const themeMode = String(
    flowCtx.themeMode || flowCtx.generationFlow?.selections?.themeMode || ''
  ).toLowerCase();
  const paletteMode = themeMode === 'palette' || (!themeMode && !packId && !brandKitId);
  const wizardThemeTokens =
    paletteMode && flowCtx.themeTokens && typeof flowCtx.themeTokens === 'object'
      ? { ...flowCtx.themeTokens }
      : null;

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
  } else if (wizardThemeTokens) {
    flowCtx.themeTokens = wizardThemeTokens;
  } else if (!flowCtx.themeTokens && deck.themeTokens) {
    flowCtx.themeTokens = deck.themeTokens;
  }

  flowCtx.themeTokens = fontPairingService.mergeThemeTokensPreservingFonts(
    deck.themeTokens,
    flowCtx.themeTokens || deck.themeTokens
  );

  const paletteSource = flowCtx.userPrompt || deck.outline?.sourcePrompt || '';
  flowCtx.themeTokens = layoutCatalogPolicy.biasPaletteFromSourceText(
    flowCtx.themeTokens || deck.themeTokens,
    paletteSource
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

  if (flowCtx.themeTokens?.palette) {
    flowCtx.themeTokens = enforceAppearancePalette(flowCtx.themeTokens);
    const brand = resolveStickyBrandColors(flowCtx.themeTokens);
    flowCtx.stickyBrandColors = brand;
    flowCtx.themeTokens = {
      ...flowCtx.themeTokens,
      appearance: brand.appearance,
      palette: {
        ...flowCtx.themeTokens.palette,
        primary: brand.primary,
        secondary: brand.secondary,
        accent: brand.accent,
      },
    };
  }

  return {
    pack,
    packId: pack?.id || null,
    brandKitId,
    layoutIdWhitelist,
    packSlides: pack?.schema?.slides || [],
  };
}

async function reconcileStaleGeneratingDeck(deck) {
  if (!deck || deck.status !== 'GENERATING') return deck;

  const slides = deck.slides || [];
  if (!slides.length) {
    const updated = await presentationDao.updateDeck(deck.id, { status: 'DRAFT' });
    return { ...deck, ...updated, status: 'DRAFT' };
  }

  const hasActive = slides.some(
    (s) => s.status === 'PENDING' || s.status === 'GENERATING'
  );
  if (hasActive) return deck;

  const failedCount = slides.filter((s) => s.status === 'FAILED').length;
  const status = failedCount === slides.length ? 'FAILED' : 'READY';
  const updated = await presentationDao.updateDeck(deck.id, { status });
  return { ...deck, ...updated, status };
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
  lockContentType = false,
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

  if (lockContentType) {
    return {
      visualNeed: preferVisuals === false ? need || 'none' : need === 'none' ? 'none' : need || 'photo',
      contentType: type,
      layoutContentType: type,
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

function templateHasImageSlot(template) {
  const slots = Array.isArray(template?.schema?.slots) ? template.schema.slots : [];
  return slots.some((slot) => {
    const id = String(slot?.id || '').toUpperCase();
    const role = String(slot?.role || '').toLowerCase();
    return role === 'image' || id.includes('IMAGE') || id === 'HERO_IMAGE' || id === 'BACKGROUND_IMAGE';
  });
}

const OUTLINE_TYPES_USUALLY_WITHOUT_IMAGES = new Set([
  'bullet_list',
  'comparison',
  'timeline',
  'stat',
  'chart',
  'diagram',
  'table',
  'pricing',
  'agenda',
]);

function neighborLikelyWithoutImages(outlineSlide, plannedEntry) {
  if (plannedEntry?.template) return !templateHasImageSlot(plannedEntry.template);
  const type = String(outlineSlide?.suggestedContentType || '').toLowerCase();
  if (OUTLINE_TYPES_USUALLY_WITHOUT_IMAGES.has(type)) return true;
  return (
    type !== 'image+text' &&
    type !== 'grid' &&
    type !== 'device_frames' &&
    type !== 'title' &&
    type !== 'closing' &&
    type !== 'section_divider'
  );
}

function resolveTimelinePreferredLayoutId(slide, outlineSlides, planned, layoutContentType) {
  if (String(layoutContentType || '').toLowerCase() !== 'timeline') return null;

  const order = Number(slide.order);
  const prev = outlineSlides.find((s) => Number(s.order) === order - 1);
  const next = outlineSlides.find((s) => Number(s.order) === order + 1);
  if (!prev && !next) return null;

  const prevPlanned = prev ? planned[Number(prev.order)] : null;
  const nextPlanned = next ? planned[Number(next.order)] : null;

  const prevNoImage = prev ? neighborLikelyWithoutImages(prev, prevPlanned) : true;
  const nextNoImage = next ? neighborLikelyWithoutImages(next, nextPlanned) : true;

  if (prevNoImage && nextNoImage) {
    return 'timeline_milestones_image_v1';
  }
  return null;
}

function chartInsightBody(content = {}, chart = {}) {
  const labels = Array.isArray(chart.labels) ? chart.labels : [];
  const values = chart.series?.[0]?.values || chart.data || chart.values || [];
  const lead = labels[0] ? String(labels[0]) : 'The leading category';
  const topValue = values[0] != null ? String(values[0]) : '';
  const topic = String(content.title || 'this topic').trim();
  if (lead && topValue) {
    return `${lead} leads ${topic.toLowerCase()} at ${topValue}, with the remaining categories spread across the chart. Use this split to highlight concentration and opportunity.`;
  }
  return `This chart summarizes the key quantitative story behind ${topic}. Keep the insight scannable in three to four lines.`;
}

function normalizeChartContent(content, layoutSchema) {
  if (!content || typeof content !== 'object' || !layoutSchema?.slots?.length) return content;
  const slots = layoutSchema.slots;
  const chartSlots = slots.filter((slot) => String(slot.role || '').toLowerCase() === 'chart');
  if (!chartSlots.length || !content.chart || typeof content.chart !== 'object') return content;

  const next = { ...content };
  const chart = { ...next.chart };
  chart.type = inferChartTypeFromStory(chart, next, layoutSchema);
  next.chart = chart;

  const hasBodySlot = slots.some((slot) => String(slot.role || '').toLowerCase() === 'body');
  const analysis = analyzeChartStory(next);
  if (hasBodySlot && chartSlots.length === 1 && analysis.needsBody && !String(next.body || '').trim()) {
    next.body = chartInsightBody(next, chart);
  }

  return next;
}

function resolveChartPreferredLayoutId(content, layoutContentType) {
  if (String(layoutContentType || '').toLowerCase() !== 'chart') return null;
  return analyzeChartStory(content).layoutId;
}

const FULL_BLEED_LAYOUT_IDS = new Set(['full_bg_image_overlay_v1', 'title_fullbleed_v1']);

function isFullBleedLayoutId(layoutId) {
  return FULL_BLEED_LAYOUT_IDS.has(String(layoutId || '').trim());
}

function resolvePreferredLayoutIdForSlide({
  ctx,
  slide,
  outlineSlides,
  planned,
  layoutContentType,
  content,
  usedLayoutIds,
  preferVisuals,
  slideOrder,
}) {
  const chart = resolveChartPreferredLayoutId(content, layoutContentType);
  if (chart) return chart;

  const timeline = resolveTimelinePreferredLayoutId(
    slide,
    outlineSlides,
    planned,
    layoutContentType
  );
  if (timeline) return timeline;

  const order = Number(slideOrder) > 0 ? Number(slideOrder) : Number(slide?.order) || 1;
  if (order === 1 && String(layoutContentType || '').toLowerCase() === 'title') {
    return resolveTitlePreferredLayoutId(ctx, preferVisuals !== false, usedLayoutIds);
  }

  return preferredLayoutForSlide(ctx, layoutContentType, usedLayoutIds, order);
}

/**
 * Slide 1 only → title; slide N only → closing; never title/closing elsewhere.
 */
function guardContentTypeForSlideOrder(contentType, slideOrder, totalSlides, outlineSlide = {}) {
  const order = Number(slideOrder) > 0 ? Number(slideOrder) : 1;
  const total = Number(totalSlides) > 0 ? Number(totalSlides) : order;
  let type = String(contentType || 'bullet_list').toLowerCase();

  if (order === 1) return 'title';

  // Last slide always closes the deck (unless user locked a non-closing layout elsewhere).
  if (order === total) {
    const locked =
      outlineSlide?.layoutLocked === true ||
      outlineSlide?.layout_locked === true;
    if (!locked) return 'closing';
  }

  if (type === 'title') {
    const hasBody = Boolean(String(outlineSlide?.summary || '').trim());
    return hasBody ? 'image+text' : 'section_divider';
  }

  if (type === 'closing' && order !== total) {
    return 'section_divider';
  }

  return type;
}

function outlineSuggestsContactIntent(outlineSlide = {}, content = {}) {
  const hay = [
    outlineSlide?.purpose,
    outlineSlide?.title,
    outlineSlide?.summary,
    outlineSlide?.contentIntent,
    content?.title,
    content?.cta,
    content?.contact?.email,
    content?.contact?.name,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return /contact|connect|team|cta|invite|booking|viewing|reach|email|phone|schedule/.test(hay);
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
      subtitle: llm.subtitle != null ? String(llm.subtitle) : sk.subtitle || '',
      summary: llm.summary != null ? String(llm.summary) : sk.summary,
      beats: Array.isArray(llm.beats) ? llm.beats : sk.beats || [],
      visual: llm.visual != null ? String(llm.visual) : sk.visual || '',
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

function toBool(value, fallback = false) {
  if (value == null) return fallback;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  const t = String(value).trim().toLowerCase();
  if (!t) return fallback;
  if (['true', '1', 'yes', 'y', 'locked'].includes(t)) return true;
  if (['false', '0', 'no', 'n', 'unlocked'].includes(t)) return false;
  return fallback;
}

function normalizeOutline(data, { slideCount, density, locale, sourceText } = {}) {
  const slides = Array.isArray(data?.slides) ? data.slides : [];
  let normalizedSlides = slides
    .map((s, idx) => ({
      order: Number(s.order) > 0 ? Number(s.order) : idx + 1,
      title: String(s.title || `Slide ${idx + 1}`).trim(),
      subtitle: s.subtitle != null ? String(s.subtitle).trim() : '',
      summary: s.summary != null ? String(s.summary) : (s.description != null ? String(s.description) : ''),
      beats: Array.isArray(s.beats) ? s.beats : [],
      visual: s.visual != null ? String(s.visual).trim() : '',
      purpose: s.purpose != null ? String(s.purpose).trim() : (s.intent != null ? String(s.intent).trim() : ''),
      contentIntent:
        s.contentIntent != null
          ? String(s.contentIntent).trim()
          : (s.summary != null ? String(s.summary).trim() : ''),
      contentType: Array.isArray(s.contentType)
        ? s.contentType.map((v) => String(v).trim().toLowerCase()).filter(Boolean)
        : [],
      visualIntent: Array.isArray(s.visualIntent)
        ? s.visualIntent.map((v) => String(v).trim()).filter(Boolean)
        : [],
      suggestedContentType: s.suggestedContentType || s.content_type || null,
      layoutId: s.layoutId || s.layout_id || null,
      layoutLocked:
        s.layoutLocked != null
          ? toBool(s.layoutLocked, false)
          : s.layout_locked != null
            ? toBool(s.layout_locked, false)
            : false,
      layoutWhy: s.layoutWhy || s.layout_why || null,
      visual_need: s.visual_need || s.visualNeed || null,
      intent: s.intent || null,
    }))
    .slice(0, AI_SLIDE_MAX);

  const requested =
    slideCount != null ? Math.min(AI_SLIDE_MAX, Math.max(1, Number(slideCount) || 12)) : null;

  if (requested) {
    normalizedSlides = layoutCatalogPolicy.enforceSlideCount(normalizedSlides, requested);
  }

  if (normalizedSlides.length > 0) {
    const first = normalizedSlides.find((s) => Number(s.order) === 1) || normalizedSlides[0];
    if (first && (!first.suggestedContentType || first.suggestedContentType === 'bullet_list')) {
      first.suggestedContentType = 'title';
    }
  }

  normalizedSlides = normalizedSlides.map((s) => ({
    ...s,
    layoutId: s.layoutLocked ? s.layoutId || null : null,
  }));

  const sourcePrompt = sourceText != null ? String(sourceText).trim().slice(0, 8000) : data?.sourcePrompt || null;

  return {
    title: sanitizePresentationTitle(data?.title),
    slideCount: requested || Math.min(AI_SLIDE_MAX, normalizedSlides.length || 12),
    density: density || 'balanced',
    locale: locale || 'en',
    slides: normalizedSlides,
    sourcePrompt: sourcePrompt || null,
    layoutChoices: Array.isArray(data?.layoutChoices) ? data.layoutChoices : undefined,
    fontPairing: data?.fontPairing || null,
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

  if (slotIds.length > 1) {
    const assigned = slotIds.map((id) => slotImageUrls[id]).filter(Boolean);
    // Same URL on every slot → clear duplicates so we regenerate/stock/placeholder per slot.
    // Keep the first assignment; clear the rest (do not wipe all).
    if (assigned.length === slotIds.length && new Set(assigned).size === 1) {
      slotIds.slice(1).forEach((id) => {
        delete slotImageUrls[id];
      });
    } else if (imageRef?.url) {
      const sharedRef = slotIds.filter((id) => slotImageUrls[id] === imageRef.url);
      if (sharedRef.length > 1) {
        sharedRef.slice(1).forEach((id) => {
          delete slotImageUrls[id];
        });
      }
    }
  }

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
    const usedUrls = new Set(Object.values(slotImageUrls).filter(Boolean));
    for (const slotId of [...missing]) {
      const prompt =
        buildSlotImagePrompt(slotId, content, layoutSchema) ||
        imagePrompts[slotId] ||
        imagePrompts[String(slotId).toUpperCase()] ||
        `Professional presentation visual for ${content?.title || 'slide topic'} (${slotId})` ||
        null;
      if (!prompt) continue;

      let assigned = false;
      for (let attempt = 0; attempt < 3 && !assigned; attempt += 1) {
        try {
          const variationPrompt =
            attempt === 0
              ? prompt
              : `${prompt} (variation ${attempt + 1}, completely different subject)`;
          const generated = await generateSlotImage({
            ctx,
            slide,
            slotId,
            prompt: variationPrompt,
            layoutSchema,
          });
          if (generated?.url && !usedUrls.has(generated.url)) {
            slotImageUrls[slotId] = generated.url;
            usedUrls.add(generated.url);
            missing = missing.filter((id) => id !== slotId);
            assigned = true;
          }
        } catch (err) {
          logger.warn?.('presentation_slot_image_failed', {
            slideId: slide.id,
            slotId,
            attempt: attempt + 1,
            error: err.message,
          });
        }
      }

      // Stock fallback when AI generation failed for this slot.
      if (!assigned) {
        try {
          const stock = await tryStockImage({
            query: String(prompt).slice(0, 120),
            workspaceId: ctx.workspaceId,
            deckId: ctx.deckId,
            slideId: slide.id,
            brief: { subject: prompt },
          });
          if (stock?.url && !usedUrls.has(stock.url)) {
            slotImageUrls[slotId] = stock.url;
            usedUrls.add(stock.url);
            missing = missing.filter((id) => id !== slotId);
            assigned = true;
          }
        } catch (stockErr) {
          logger.warn?.('presentation_slot_image_stock_fallback_failed', {
            slideId: slide.id,
            slotId,
            error: stockErr.message,
          });
        }
      }
    }
  }

  // Hero backfill: single-slot layouts, or primary BACKGROUND/HERO in multi-slot layouts.
  if (imageRef?.url) {
    const primary = slotIds.find((id) =>
      /^(BACKGROUND_IMAGE|HERO_IMAGE)$/i.test(String(id))
    );
    if (slotIds.length === 1 && !slotImageUrls[slotIds[0]]) {
      slotImageUrls[slotIds[0]] = imageRef.url;
    } else if (primary && !slotImageUrls[primary]) {
      slotImageUrls[primary] = imageRef.url;
    }
  }

  // Last-resort placeholder so gallery slots never render as broken <img> icons.
  // Use per-slot placeholders so distinct-URL logic does not wipe siblings.
  missing = slotIds.filter((slotId) => !slotImageUrls[slotId]);
  if (missing.length && ctx.imageSource !== 'none') {
    for (let i = 0; i < missing.length; i += 1) {
      const slotId = missing[i];
      try {
        const ph = await generationFlowService.ensurePlaceholderImage({
          slotIndex: slotIds.indexOf(slotId) + 1,
          seed: `${slide.id}-${slotId}`,
        });
        if (ph?.url && !slotImageUrls[slotId]) {
          slotImageUrls[slotId] = ph.url;
        }
      } catch (phErr) {
        logger.warn?.('presentation_slot_image_placeholder_failed', {
          slideId: slide.id,
          slotId,
          error: phErr.message,
        });
      }
    }
  }

  if (!Object.keys(slotImageUrls).length) return content;

  const distinctUrls = await assertDistinctSlotImageUrls({
    ctx,
    slide,
    content,
    layoutSchema,
    slotImageUrls,
  });

  const repairedUrls = await repairSlotImagesFromQa({
    ctx,
    slide,
    content,
    layoutSchema,
    slotImageUrls: distinctUrls,
  });

  return { ...content, slotImageUrls: repairedUrls };
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
      issue.rule === 'distinct_gallery_labels' ||
      issue.rule === 'gallery_label_matches_slide_title' ||
      issue.rule === 'duplicate_image_prompts' ||
      issue.rule === 'duplicate_slot_image_urls' ||
      issue.rule === 'required_chart_data' ||
      issue.rule === 'generic_chart_labels' ||
      issue.rule === 'placeholder_chart_subtitle' ||
      issue.rule === 'placeholder_cta' ||
      issue.rule === 'placeholder_body' ||
      issue.rule === 'placeholder_heading' ||
      issue.rule === 'empty_required_slot' ||
      issue.rule === 'placeholder_diagram_body' ||
      issue.rule === 'timeline_missing_details' ||
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
  const contentTypeHistory = [];
  const aiTopN = Math.min(
    10,
    Math.max(5, Number(process.env.PPT_LAYOUT_AI_TOP_N || 8) || 8)
  );

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

    ctx.outlineExplicitType = Boolean(outlineSlide.suggestedContentType);
    ctx.respectOutlineTypes = true;
    let excludeLayoutIds =
      Number(slide.order) === totalSlides && ctx.titleLayoutId
        ? closingLayoutExcludeIds(ctx.titleLayoutId)
        : null;
    let preferredLayoutId = resolvePreferredLayoutIdForSlide({
      ctx,
      slide,
      outlineSlides,
      planned,
      layoutContentType,
      content: stubContent,
      usedLayoutIds,
      preferVisuals,
      slideOrder: slide.order,
    });
    if (Number(slide.order) === totalSlides && isSplitHeroLayout(ctx.titleLayoutId)) {
      // Prefer contact CTA when the outline/content signals contact intent.
      preferredLayoutId = outlineSuggestsContactIntent(outlineSlide, stubContent)
        ? 'closing_contact_cta_v1'
        : 'closing_thank_you_fullbleed_v1';
    }
    let ranked = [];
    try {
      const profile = toSlideContentProfile({
        ...stubContent,
        purpose: outlineSlide.purpose || outlineSlide.intent || null,
        suggestedContentType: layoutContentType,
        slideNumber: Number(slide.order),
      });
      const deckLayouts = templates.map((t) => toDeckLayout(t));
      ranked = rankLayouts(profile, deckLayouts, {
        topN: aiTopN,
        previousLayoutIds: [...usedLayoutIds],
        debug: false,
      });
      if (preferredLayoutId) {
        const idx = ranked.findIndex((r) => String(r.layoutId) === String(preferredLayoutId));
        if (idx > 0) {
          const hit = ranked.splice(idx, 1)[0];
          ranked.unshift(hit);
        }
      }
    } catch {
      ranked = [];
    }

    planned[Number(slide.order)] = {
      slideNumber: Number(slide.order),
      layoutContentType,
      policy,
      candidateIds: ranked.map((r) => r.layoutId),
      scores: ranked.map((r) => ({ layoutId: r.layoutId, score: r.score })),
      diagnosticsOnly: true,
    };

    const topLayoutId = ranked[0]?.layoutId || null;
    if (topLayoutId) {
      usedLayoutIds.add(String(topLayoutId));
      if (Number(slide.order) === 1) ctx.titleLayoutId = String(topLayoutId);
      if (isFullBleedLayoutId(topLayoutId)) fullBleedUsed = true;
    }
  }

  ctx.plannedLayouts = planned;
  ctx.fullBleedUsed = fullBleedUsed;
  ctx.layoutIdByOrder = ctx.layoutIdByOrder || {};
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
  const layoutDebug = String(process.env.PPT_LAYOUT_DEBUG || '').trim() === '1';
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

  const outlineSlides = (ctx.outline?.slides || []).slice().sort((a, b) => a.order - b.order);
  const previousLayoutId = ctx.layoutIdByOrder?.[Number(slide.order) - 1] || null;
  const stubContent = {
    title: resolvedTitle || outlineSlide.title || '',
    summary: resolvedSummary,
    bullets: [],
  };
  let preferredLayoutId = resolvePreferredLayoutIdForSlide({
    ctx,
    slide,
    outlineSlides,
    planned: ctx.plannedLayouts || {},
    layoutContentType,
    content: stubContent,
    usedLayoutIds: ctx.usedLayoutIds || new Set(),
    preferVisuals,
    slideOrder: slide.order,
  });
  const { layoutId, template } = await pickLayoutForGeneratedSlide({
    content: stubContent,
    templates,
    previousLayoutId,
    usedLayoutIds: ctx.usedLayoutIds || null,
    preferredLayoutId,
    preferImageSlot: preferVisuals && Number(slide.order) === 1,
    ctx,
    slide,
    outlineSlide,
    totalSlides,
    phase: 'pre_content',
    debug: layoutDebug,
    theme: ctx.themeTokens || ctx.theme || null,
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
    hints.chartLayoutStyle =
      'Analyze the data story first, then pick chart.type and layout: line/area for time series; donut/pie only when values represent parts of a whole (~100% total); bar for rankings or absolute comparisons; dual-chart only for two distinct metrics. One dataset per chart slot — never duplicate identical data.';
    if (slotChartType) {
      hints.chartType = slotChartType.includes('line') ? 'line' : slotChartType.includes('donut') ? 'donut' : 'bar';
    } else if (!/exponential|line/i.test(layoutId)) {
      hints.chartType = 'bar';
    }
  }
  if (imageSlots.length > 1) {
    hints.imagePromptStyle = `Fill imagePrompts with a UNIQUE concrete visual for each slot: ${imageSlots.map((s) => s.id).join(', ')}. No duplicate subjects.`;
  }
  if (/para|cards_image|card_\d|grid_.*image|intro_four|intro_three|four_para|three_para|two_para|four_images|timeline_milestones_image/i.test(layoutId)) {
    hints.parallelStructure =
      'Each column/card/gallery image needs a distinct title (≤4 words) and optional body. Fill columns[] accordingly — titles map to IMAGE_n_LABEL captions.';
  }
  if (/diagram_|swot|matrix|funnel|process_step/i.test(layoutId) || layoutNeedsDiagramCellsFromSchema(layoutSchema)) {
    hints.parallelStructure =
      'Fill diagram.cells[] with one { title, body } per quadrant/step/tier. Replace all template placeholder text with original topic-specific copy.';
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
    const layoutDebug = String(process.env.PPT_LAYOUT_DEBUG || '').trim() === '1';
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
    let designTokens =
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
      outlineSlide.subtitle || '',
      JSON.stringify(outlineSlide.beats || []),
      outlineSlide.visual || '',
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
    const needsFreshContent = contentNeedsFreshGeneration(content, contentLayoutSchema);
    if (!contentJob.duplicate || needsFreshContent || ctx.forceTextReplace) {
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
              subtitle: outlineSlide.subtitle || '',
              beats: outlineSlide.beats || [],
              visual: outlineSlide.visual || '',
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
        if (contentLayoutSchema) {
          content = normalizeMultiColumnContent(content, contentLayoutSchema);
          content = normalizeGalleryImageContent(content, contentLayoutSchema);
          content = normalizeTimelineContent(content, contentLayoutSchema);
          content = normalizeDiagramContent(content, contentLayoutSchema);
        }
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

    content = blueprintSeed.mergeSeedIntoContent(
      content,
      blueprintSeed.seedFromOutlineSlide(outlineSlide),
      contentLayoutSchema || earlyLayoutSchema
    );

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
        const classifiedType = String(classified.data?.content_type || '').toLowerCase();
        const outlineType = String(outlineSlide.suggestedContentType || '').toLowerCase();
        const outlineExplicit = Boolean(outlineSlide.suggestedContentType);
        const hasBullets =
          Array.isArray(content?.bullets) && content.bullets.filter(Boolean).length >= 2;

        if (
          outlineExplicit &&
          outlineType === 'bullet_list' &&
          classifiedType === 'section_divider' &&
          hasBullets
        ) {
          contentType = 'bullet_list';
        } else {
          contentType = classified.data?.content_type || contentType || 'bullet_list';
        }
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

    if (!ctx.packBound && Number(slide.order) === 1 && !outlineLayoutIdForSlide(outlineSlide, slide)) {
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

    const blueprintLayoutIdEarly = outlineLayoutIdForSlide(outlineSlide, slide);
    if (blueprintLayoutIdEarly && outlineSlide.suggestedContentType) {
      contentType = String(outlineSlide.suggestedContentType).toLowerCase();
    }

    const policy = applyVisualPolicy({
      visualNeed,
      contentType,
      preferVisuals,
      baseTemplateBias: ctx.baseTemplateBias || null,
      respectOutlineType: !ctx.packBound,
      lockContentType: Boolean(outlineLayoutIdForSlide(outlineSlide, slide)),
    });
    visualNeed = policy.visualNeed;
    contentType = blueprintLayoutIdEarly
      ? policy.contentType
      : applyContentDistribution(policy.contentType, ctx);
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
    const existingLayoutId =
      outlineLayoutIdForSlide(outlineSlide, slide) || slide.layoutId || packMeta?.layout_id || null;
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
    if (!template && existingLayoutId) {
      const blueprintLayouts = await presentationDao.findLayoutsByLayoutIds([existingLayoutId]);
      template =
        blueprintLayouts[0] ||
        loadSeedTemplates(null).find(
          (t) => String(t.schema?.layout_id || t.variant || '') === String(existingLayoutId)
        ) ||
        null;
      if (template) {
        layoutId = existingLayoutId;
        const lockedType = String(template.contentType || template.schema?.content_type || '').toLowerCase();
        if (lockedType) {
          contentType = lockedType;
          policy.layoutContentType = lockedType;
          if (content && typeof content === 'object') content.content_type = lockedType;
        }
      }
    }
    if (!template && !willRebind) {
      const plannedEntry = ctx.plannedLayouts?.[Number(slide.order)];
      const outlineType = String(outlineSlide.suggestedContentType || '').toLowerCase();
      const outlineExplicit = Boolean(outlineSlide.suggestedContentType);
      const plannedMatches =
        plannedEntry?.template &&
        plannedEntry?.layoutId &&
        String(plannedEntry.layoutContentType || '') === String(policy.layoutContentType);
      const plannedMatchesOutline =
        outlineExplicit &&
        plannedEntry?.template &&
        plannedEntry?.layoutId &&
        String(plannedEntry.layoutContentType || '').toLowerCase() === outlineType;
      const preselectedMatches =
        preSelectedTemplate &&
        preSelectedLayoutId &&
        String(preSelectedTemplate.contentType || preSelectedTemplate.schema?.content_type || '') ===
          String(policy.layoutContentType);
      const canReusePreselected = plannedMatches || plannedMatchesOutline || preselectedMatches;

      if (canReusePreselected) {
        template = plannedEntry?.template || preSelectedTemplate;
        layoutId = plannedEntry?.layoutId || preSelectedLayoutId;
        if (plannedMatchesOutline && !plannedMatches && plannedEntry?.layoutContentType) {
          policy.layoutContentType = plannedEntry.layoutContentType;
          contentType = plannedEntry.layoutContentType;
          if (content && typeof content === 'object') {
            content.content_type = contentType;
          }
        }
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
            ? closingLayoutExcludeIds(ctx.titleLayoutId)
            : null;
        let preferredLayoutId = resolvePreferredLayoutIdForSlide({
          ctx,
          slide,
          outlineSlides: neighbors,
          planned: ctx.plannedLayouts || {},
          layoutContentType: policy.layoutContentType,
          content,
          usedLayoutIds: ctx.usedLayoutIds || new Set(),
          preferVisuals,
          slideOrder: slide.order,
        });
        if (Number(slide.order) === slideTotal && isSplitHeroLayout(ctx.titleLayoutId)) {
          preferredLayoutId = outlineSuggestsContactIntent(outlineSlide, content)
            ? 'closing_contact_cta_v1'
            : 'closing_thank_you_fullbleed_v1';
        } else if (
          Number(slide.order) === slideTotal &&
          outlineSuggestsContactIntent(outlineSlide, content)
        ) {
          preferredLayoutId = preferredLayoutId || 'closing_contact_cta_v1';
        }
        ({ layoutId, template } = await pickLayoutForGeneratedSlide({
          content,
          templates,
          previousLayoutId: ctx.layoutIdByOrder?.[Number(slide.order) - 1] || null,
          usedLayoutIds: ctx.usedLayoutIds || null,
          preferredLayoutId,
          excludeLayoutIds,
          preferImageSlot:
            preferVisuals &&
            (Number(slide.order) === 1 ||
              String(visualNeed || '').toLowerCase() === 'photo' ||
              String(visualNeed || '').toLowerCase() === 'illustration'),
          ctx,
          slide,
          outlineSlide,
          totalSlides: slideTotal,
          phase: 'final',
          debug: layoutDebug,
          theme: ctx.themeTokens || ctx.theme || null,
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
      if (isFullBleedLayoutId(layoutId)) {
        ctx.fullBleedUsed = true;
      }
    }

    // Deck art direction: apply deterministic slide-level design tokens
    // AFTER layoutId is finalized and BEFORE layout compilation.
    try {
      const slidePlan = buildSlideDesignPlan({ ctx, slide, outlineSlide });
      if (slidePlan?.designTokens) {
        designTokens = { ...(designTokens || {}), ...slidePlan.designTokens };
      }
      ctx.slideDesignPlans = ctx.slideDesignPlans || {};
      ctx.slideDesignPlans[Number(slide.order)] = slidePlan;
    } catch {
      // Never block slide generation for art direction failures.
    }

    if (template?.schema) {
      content = normalizeMultiColumnContent(content, template.schema);
      content = normalizeGalleryImageContent(content, template.schema);
      content = normalizeChartContent(content, template.schema);
      content = normalizeTimelineContent(content, template.schema);
      content = normalizeDiagramContent(content, template.schema);
    }

    let qa = validateSlide({
      content,
      layoutSchema: template?.schema || null,
    });
    content = qa.content;

    if (
      (qaNeedsContentRepair(qa.issues) ||
        blueprintSeed.contentMissingRequiredCopy(content, template?.schema)) &&
      template?.schema
    ) {
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
        outlineSlide,
      });
      content = blueprintSeed.mergeSeedIntoContent(
        repaired.content,
        blueprintSeed.seedFromOutlineSlide(outlineSlide),
        template.schema
      );
      qa = repaired.qa;
    } else if (qa.issues?.length) {
      logger.warn?.('presentation_slide_qa_issues', {
        slideId: slide.id,
        layoutId: template?.schema?.layout_id || layoutId,
        issues: qa.issues,
      });
    }
    // Apply deck-level image strategy (does not affect layoutId selection).
    // This runs before the visualNeed-driven image brief pipeline starts.
    const strat = ctx.imageStrategyByOrder?.[Number(slide.order)];
    if (strat?.usage) {
      visualNeed = applyDeckImageStrategyToVisualNeed({
        currentVisualNeed: visualNeed,
        usage: strat.usage,
        preferVisuals: ctx.preferVisuals,
      });
    }

    if (content && typeof content === 'object') {
      content.visual_need = visualNeed;
      content.content_type = contentType;
      content = applyDefaultOverlayDecisions(content, template?.schema || null);
      content = sanitizeShapeDecisions(content, template?.schema);
    }

    const layoutSchemaForImages = template?.schema || null;
    if (layoutUsesPerSlotGalleryImages(layoutSchemaForImages)) {
      visualNeed = 'none';
      if (content && typeof content === 'object') {
        content.visual_need = 'none';
        content = normalizeGalleryImageContent(content, layoutSchemaForImages);
      }
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
        outlineSlide.visual || '',
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
              authorImagePrompt: resolveAuthorImagePrompt(content) || outlineSlide.visual || '',
              layoutContext: layoutCtx,
              layoutId: template?.schema?.layout_id || layoutId || null,
              hasImageOverlay: layoutCtx.hasImageOverlay,
              visualNeed,
              visual: outlineSlide.visual || content?.visual || '',
              suggestedContentType: contentType,
              previousVisuals: ctx.usedImageSubjects || [],
            }),
            model: DEFAULT_SLIDE_MODEL,
            temperature: 0.3,
          });
          brief = briefResult.data;
          ctx.usedImageSubjects = ctx.usedImageSubjects || [];
          if (brief?.subject) ctx.usedImageSubjects.push(String(brief.subject).slice(0, 180));
          await finishJob(briefJob.job.id, {
            status: 'SUCCEEDED',
            usage: briefResult.usage,
            latencyMs: briefResult.latencyMs,
            creditCharged: false,
          });
          content = applyDarkExposureOverlay(content, brief, template?.schema || null);
        } catch (err) {
          await finishJob(briefJob.job.id, { status: 'FAILED', error: err.message });
          const authorBrief = resolveAuthorImagePrompt(content) || outlineSlide.visual;
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
      content = normalizeMultiColumnContent(content, layoutSchema);
      content = normalizeGalleryImageContent(content, layoutSchema);
      content = normalizeChartContent(content, layoutSchema);
      content = normalizeTimelineContent(content, layoutSchema);
      content = normalizeDiagramContent(content, layoutSchema);
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
    }, ctx.slideDesignPlans?.[Number(slide.order)] || null);

    const compiledHasEmpty = (elementsDoc?.elements || []).some((el) => {
      if (el.type !== 'text' && el.type !== 'textbox') return false;
      const role = String(el.role || '').toLowerCase();
      if (!['heading', 'title', 'subheading', 'subtitle', 'body', 'bullet'].includes(role)) return false;
      return blueprintSeed.isWeakText(el.content?.text);
    });
    if (compiledHasEmpty && layoutSchema?.slots?.length) {
      content = blueprintSeed.mergeSeedIntoContent(
        content,
        blueprintSeed.seedFromOutlineSlide(outlineSlide),
        layoutSchema
      );
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
      elementsDoc = finalizeElementsDoc(elementsDoc, layoutSchema, content, ctx.themeTokens || null, {
        width: canvasSize.width,
        height: canvasSize.height,
      }, ctx.slideDesignPlans?.[Number(slide.order)] || null);
    }

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

    // Deck-level visual rhythm + image usage schedule.
    // Used later inside `processSlide` to influence `visualNeed` before image briefs.
    const slideCount = Array.isArray(ctx.outline?.slides) ? ctx.outline.slides.length : 1;
    ctx.visualRhythm = planDeckVisualRhythm({ slideCount });
    ctx.imageStrategyByOrder = planDeckImageDistribution({ visualRhythm: ctx.visualRhythm });

    // Optional deck-level art direction (semantic-only). v1 is deterministic/no-network.
    ctx.deckArtDirection = await buildDeckArtDirection({ ctx, themeTokens: ctx.themeTokens });

    const pending = (deck.slides || []).filter(
      (s) => s.status === 'PENDING' || s.status === 'GENERATING'
    );

    if (!ctx.packBound && pending.length > 0) {
      const outlineHasLockedLayouts = (ctx.outline?.slides || []).some(
        (s) => (s.layoutId || s.layout_id) && toBool(s.layoutLocked ?? s.layout_locked, false)
      );
      ctx.lockBlueprintLayouts = outlineHasLockedLayouts;
      if (!outlineHasLockedLayouts) {
        await planDeckLayouts(ctx, pending);
      }
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
  imageType = null,
  imageStyle = null,
  imageStyleFilter = null,
  colorTheme = null,
  optionalOutline = null,
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

  const packWhitelist = pack
    ? (pack.schema?.generationDefaults?.layoutWhitelist ||
        (pack.schema?.slides || []).map((s) => s.layout_id).filter(Boolean))
    : null;
  const allTemplates = await loadAllLayoutTemplates(packWhitelist);
  const catalogPolicy = layoutCatalogPolicy.buildPolicyFromWizard({
    density,
    imageType: imageType || (detectPreferVisuals(sourceText) ? 'ai' : 'none'),
    imageStyle,
    imageStyleFilter,
    sourceText,
    tone: voiceAndTone,
    purpose,
    themeTokens: deck.themeTokens,
    packBound: Boolean(pack),
  });
  const filteredMetas = layoutCatalogPolicy.filterLayoutTemplates(allTemplates, catalogPolicy);
  const layoutDigest = layoutCatalogPolicy.buildLayoutDigest(filteredMetas);
  const themeAppearance = catalogPolicy.themeAppearance || '';

  if (pack) {
    const packSlides = Array.isArray(pack.schema?.slides) ? pack.schema.slides : [];
    effectiveSlideCount = packSlides.length || slideCount;
    const skeleton = buildPackOutlineSkeleton(pack, {
      density,
      locale,
      sourceText,
    });
    skeleton.slides = layoutCatalogPolicy.coerceOutlineLayouts(
      skeleton.slides,
      filteredMetas,
      { slideCount: skeleton.slides.length, imageType: catalogPolicy.imageType }
    );

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
        imageType: catalogPolicy.imageType,
        imageStyle: imageStyle || '',
        imageStyleFilter: imageStyleFilter || '',
        themeAppearance,
        layoutDigest,
        optionalOutline: optionalOutline || outlineText || '',
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

  outline = finalizeBlueprintOutline(outline, filteredMetas, catalogPolicy, effectiveSlideCount);
  if (catalogPolicy.imageType === 'none') {
    outline.preferVisuals = false;
  }

  try {
    const biasedTheme = layoutCatalogPolicy.biasPaletteFromSourceText(deck.themeTokens || {}, sourceText);
    const themedFonts = await fontPairingService.ensureThemeFonts(biasedTheme, {
      prompt: sourceText,
      wizardBrief: [outlineVoiceAndTone, audience, purpose].filter(Boolean).join('\n'),
      tone: voiceAndTone,
      audience,
      purpose,
      brandKitId: outlineBrandKitId,
    });
    await presentationDao.updateDeck(deck.id, { themeTokens: themedFonts });
    outline.fontPairing = {
      heading: themedFonts?.fonts?.heading || null,
      body: themedFonts?.fonts?.body || null,
      fontPairingId: themedFonts?.fontPairingId || null,
    };
  } catch (err) {
    logger.warn('ensureThemeFonts failed during outline', { error: err.message });
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
  let { deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  deck = await reconcileStaleGeneratingDeck(deck);
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
      layoutChoices: outline.layoutChoices || deck.outline?.layoutChoices,
      fontPairing: outline.fontPairing || deck.outline?.fontPairing,
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
  const merged = fontPairingService.mergeThemeTokensPreservingFonts(deck.themeTokens, resolved);
  const updated = await presentationDao.updateDeck(deck.id, {
    themeTokens: merged,
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
  let { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  deck = await reconcileStaleGeneratingDeck(deck);
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
