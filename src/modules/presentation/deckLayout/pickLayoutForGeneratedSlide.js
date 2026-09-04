const { toDeckLayout } = require('./toDeckLayout');
const { toSlideContentProfile } = require('./toSlideContentProfile');
const { rankLayouts } = require('./rankLayouts');
const { selectBestLayoutWithAI } = require('./selectBestLayoutWithAI');
const { getLayoutAiSelectionConfig } = require('./layoutAiSelection.config');
const { layoutFamilyExcludeIds } = require('../layoutSelector.service');

function templateLayoutId(template) {
  return String(template?.schema?.layout_id || template?.variant || template?.id || '').trim();
}

function previousIdsFrom(value) {
  if (!value) return [];
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.map((id) => String(id)).filter(Boolean);
  if (typeof value.has === 'function') return [...value].map((id) => String(id));
  if (typeof value === 'object') return Object.values(value).map((id) => String(id)).filter(Boolean);
  return [];
}

/**
 * Prefer a different layout than the immediately previous slide (exact id or family).
 */
function avoidAdjacentSameFormat(selectedId, previousLayoutId, ranked, locked) {
  if (locked) return selectedId;
  const prev = String(previousLayoutId || '').trim();
  const selected = String(selectedId || '').trim();
  if (!prev || !selected) return selectedId;
  const banned = new Set(layoutFamilyExcludeIds(prev).map(String));
  banned.add(prev);
  if (!banned.has(selected)) return selectedId;
  const alt = (ranked || []).find((r) => {
    const id = String(r?.layoutId || '').trim();
    return id && !banned.has(id);
  });
  return alt?.layoutId || selectedId;
}

function buildPresentationContext({ ctx, slide, outlineSlide, totalSlides }) {
  const wizard = ctx?.wizard || ctx?.request || {};
  const outline = ctx?.outline || {};
  const outlineSlides = (outline.slides || []).slice().sort((a, b) => a.order - b.order);
  const order = Number(slide?.order) || 1;
  const prevOutline = outlineSlides.filter((s) => Number(s.order) < order);
  const nextOutline = outlineSlides.find((s) => Number(s.order) === order + 1);
  const layoutByOrder = ctx?.layoutIdByOrder || {};

  return {
    title: outline.title || ctx?.presentation?.title || ctx?.title || '',
    purpose: wizard.purpose || outline.purpose || ctx?.purpose || '',
    audience: wizard.audience || ctx?.audience || '',
    industry: wizard.industry || ctx?.industry || '',
    tone: wizard.tone || wizard.mood || ctx?.tone || '',
    slideNumber: order,
    totalSlides: totalSlides || outline.slideCount || outlineSlides.length || 1,
    previousSlides: prevOutline.map((s) => ({
      slideNumber: Number(s.order),
      purpose: s.intent || s.purpose || s.suggestedContentType || '',
      layoutId: layoutByOrder[Number(s.order)] || s.layoutId || undefined,
    })),
    nextSlide: nextOutline
      ? { purpose: nextOutline.intent || nextOutline.purpose || nextOutline.suggestedContentType || '' }
      : undefined,
  };
}

const {
  galleryProfileOverrides,
  isPureImageGridLayoutId,
  isTextImageGridLayout,
  looksLikeImageLedGallery,
} = require('../galleryGridPolicy.util');

function profileFromContent({ content, outlineSlide, ctx, slide, presentationContext }) {
  const wizard = ctx?.wizard || {};
  const preferVisuals = ctx?.preferVisuals !== false;
  const order = Number(presentationContext?.slideNumber || slide?.order || 0);
  const outlineContentTypes = Array.isArray(outlineSlide?.contentType)
    ? outlineSlide.contentType
    : Array.isArray(outlineSlide?.contentTypes)
      ? outlineSlide.contentTypes
      : [];
  const outlineVisualNeed = String(
    outlineSlide?.visual_need || outlineSlide?.visualNeed || content?.visual_need || ''
  ).toLowerCase();
  const wantsImage =
    preferVisuals &&
    (order === 1 ||
      outlineVisualNeed === 'photo' ||
      outlineVisualNeed === 'illustration' ||
      outlineContentTypes.map((t) => String(t).toLowerCase()).includes('image') ||
      Boolean(outlineSlide?.visual));

  let imageCount =
    typeof content?.imageCount === 'number'
      ? content.imageCount
      : content?.imageUrl || content?.image || content?.imageRef?.url
        ? 1
        : 0;
  if (wantsImage && imageCount < 1) imageCount = 1;

  const contentTypes = [
    ...outlineContentTypes.map((t) => String(t).toLowerCase()),
    ...(Array.isArray(content?.contentTypes) ? content.contentTypes : []),
  ];
  if (wantsImage && !contentTypes.includes('image')) contentTypes.push('image');

  const layoutContentType =
    outlineSlide?.suggestedContentType || content?.content_type || content?.contentType || '';
  const gallerySignals = {
    title: content?.title || outlineSlide?.title,
    summary: content?.summary || content?.body || outlineSlide?.summary,
    beats: outlineSlide?.beats || content?.beats,
    bullets: content?.bullets,
    columns: content?.columns,
    visual: outlineSlide?.visual,
    intent: outlineSlide?.intent || outlineSlide?.purpose || content?.intent,
    contentType: layoutContentType,
    imageStylePhrase: ctx?.imageStylePhrase || ctx?.themeTokens?.imageStyle || '',
    visualIntent: outlineSlide?.visualIntent || outlineSlide?.visual_intent,
  };
  const galleryOverrides = galleryProfileOverrides(gallerySignals);
  if (galleryOverrides?.imageCount) {
    imageCount = galleryOverrides.imageCount;
  }

  return toSlideContentProfile({
    ...(content && typeof content === 'object' ? content : {}),
    title: content?.title || outlineSlide?.title || '',
    subtitle: content?.subtitle || '',
    // For cover slides, keep bodyLength from summary but do not let it alone force text-only.
    body: galleryOverrides
      ? ''
      : content?.body || (order === 1 ? '' : outlineSlide?.summary || content?.summary || ''),
    summary: galleryOverrides ? '' : outlineSlide?.summary || content?.summary || '',
    beats: outlineSlide?.beats || content?.beats || [],
    purpose:
      outlineSlide?.intent ||
      outlineSlide?.purpose ||
      content?.purpose ||
      presentationContext?.purpose,
    suggestedContentType: outlineSlide?.suggestedContentType || content?.content_type,
    slideNumber: presentationContext?.slideNumber || slide?.order,
    industry: presentationContext?.industry || wizard.industry,
    preferredStyles: wizard.designStyles || wizard.styles || ctx?.preferredStyles,
    preferredMoods: wizard.moods || (wizard.tone ? [wizard.tone] : ctx?.preferredMoods),
    imageCount,
    contentTypes: contentTypes.length ? contentTypes : undefined,
    visual_need: outlineVisualNeed || (wantsImage ? 'photo' : undefined),
    wizardDensity: ctx?.density || null,
    allowPureImageGrid: Boolean(galleryOverrides),
  });
}

function promotePreferred(ranked, preferredLayoutId) {
  const id = String(preferredLayoutId || '').trim();
  if (!id || !Array.isArray(ranked) || !ranked.length) return ranked;
  const idx = ranked.findIndex((r) => r.layoutId === id);
  if (idx <= 0) return ranked;
  const copy = ranked.slice();
  const [hit] = copy.splice(idx, 1);
  copy.unshift(hit);
  return copy;
}

function resolveTemplate(templates, layoutId) {
  const id = String(layoutId || '').trim();
  return (
    (Array.isArray(templates) ? templates : []).find((t) => templateLayoutId(t) === id) || null
  );
}

/**
 * Rank DeckLayouts then let OpenAI pick among the top N.
 * @returns {Promise<{ layoutId: string|null, template: object|null, selection?: object }>}
 */
async function pickLayoutForGeneratedSlide({
  content,
  templates,
  previousLayoutIds,
  previousLayoutId,
  usedLayoutIds,
  preferredLayoutId = null,
  preferImageSlot = false,
  excludeLayoutIds = null,
  phase = 'final',
  presentationContext,
  theme = null,
  outlineSlide = {},
  ctx = {},
  slide = {},
  totalSlides,
  debug = false,
  chatJson,
} = {}) {
  let list = Array.isArray(templates) ? templates.filter(Boolean) : [];
  const excluded = new Set(
    (Array.isArray(excludeLayoutIds) ? excludeLayoutIds : [])
      .map((id) => String(id || '').trim())
      .filter(Boolean)
  );
  if (excluded.size) {
    list = list.filter((t) => !excluded.has(templateLayoutId(t)));
  }
  if (!list.length) {
    return { layoutId: null, template: null };
  }

  const lockedLayoutId = outlineSlide?.layoutLocked
    ? String(outlineSlide?.layoutId || outlineSlide?.layout_id || '').trim()
    : '';
  if (lockedLayoutId) {
    const lockedTemplate = resolveTemplate(list, lockedLayoutId);
    if (lockedTemplate) {
      if (ctx && typeof ctx === 'object') {
        if (!Array.isArray(ctx.layoutSelectionLog)) ctx.layoutSelectionLog = [];
        ctx.layoutSelectionLog.push({
          slideNumber: Number(slide?.order || outlineSlide?.order || 0) || null,
          phase,
          source: 'locked',
          selectedLayoutId: templateLayoutId(lockedTemplate) || lockedLayoutId,
          candidateCount: list.length,
        });
      }
      return {
        layoutId: templateLayoutId(lockedTemplate) || lockedLayoutId,
        template: lockedTemplate,
        selection: {
          selectedLayoutId: templateLayoutId(lockedTemplate) || lockedLayoutId,
          confidence: 100,
          reason: 'Layout locked by outline',
          source: 'locked',
          usedFallback: false,
        },
      };
    }
  }

  const forcedGalleryId = String(preferredLayoutId || '').trim();
  if (forcedGalleryId && isPureImageGridLayoutId(forcedGalleryId)) {
    const gallerySignals = {
      title: content?.title || outlineSlide?.title,
      summary: content?.summary || content?.body || outlineSlide?.summary,
      beats: outlineSlide?.beats || content?.beats,
      bullets: content?.bullets,
      columns: content?.columns,
      visual: outlineSlide?.visual,
      intent: outlineSlide?.intent || outlineSlide?.purpose || content?.intent,
      contentType:
        outlineSlide?.suggestedContentType || content?.content_type || content?.contentType || '',
      suggestedContentType: outlineSlide?.suggestedContentType,
      arrangementHint: outlineSlide?.arrangementHint,
      imageStylePhrase: ctx?.imageStylePhrase || ctx?.themeTokens?.imageStyle || '',
      visualIntent: outlineSlide?.visualIntent || outlineSlide?.visual_intent,
      wizardBrief: ctx?.wizardBrief || ctx?.sourceText || ctx?.outline?.sourcePrompt || '',
    };
    if (looksLikeImageLedGallery(gallerySignals)) {
      list = list.filter((t) => !isTextImageGridLayout(templateLayoutId(t)));
      const forcedTemplate = resolveTemplate(list, forcedGalleryId);
      if (forcedTemplate) {
        if (ctx && typeof ctx === 'object') {
          if (!Array.isArray(ctx.layoutSelectionLog)) ctx.layoutSelectionLog = [];
          ctx.layoutSelectionLog.push({
            slideNumber: Number(slide?.order || outlineSlide?.order || 0) || null,
            phase,
            source: 'gallery_policy',
            selectedLayoutId: forcedGalleryId,
            candidateCount: list.length,
          });
        }
        return {
          layoutId: forcedGalleryId,
          template: forcedTemplate,
          selection: {
            selectedLayoutId: forcedGalleryId,
            confidence: 100,
            reason: 'Image-led gallery — pure bento layout',
            source: 'gallery_policy',
            usedFallback: false,
          },
        };
      }
    }
  }

  const config = getLayoutAiSelectionConfig();
  const ctxPresentation = presentationContext || buildPresentationContext({ ctx, slide, outlineSlide, totalSlides });
  const profile = profileFromContent({
    content,
    outlineSlide,
    ctx,
    slide,
    presentationContext: ctxPresentation,
  });
  if (ctxPresentation.slideNumber && profile.slideNumber == null) {
    profile.slideNumber = ctxPresentation.slideNumber;
  }

  if (preferImageSlot) {
    const hasImageCapable = list.some((t) => {
      const schema = t?.schema || {};
      const slots = Array.isArray(schema.slots) ? schema.slots : [];
      return slots.some((s) => {
        const role = String(s?.role || '').toLowerCase();
        const id = String(s?.id || '').toLowerCase();
        return role === 'image' || role === 'background' || id.includes('image') || id.includes('hero');
      });
    });
    if (!hasImageCapable) {
      const widened = list.filter((t) => {
        const ct = String(t?.contentType || t?.schema?.content_type || '').toLowerCase();
        return ct === 'image+text' || ct === 'device_frames' || ct === 'grid';
      });
      if (widened.length) {
        list = widened;
      }
    }
  }

  const deckLayouts = list.map((t) => toDeckLayout(t));
  const layoutsById = {};
  for (const layout of deckLayouts) {
    if (layout?.id) layoutsById[layout.id] = layout;
  }

  const prev = previousIdsFrom(previousLayoutIds)
    .concat(previousIdsFrom(previousLayoutId))
    .concat(previousIdsFrom(usedLayoutIds));
  const adjacentLayoutId =
    String(previousLayoutId || '').trim() ||
    String(ctx?.layoutIdByOrder?.[Number(slide?.order) - 1] || '').trim() ||
    null;
  let ranked = rankLayouts(profile, deckLayouts, {
    topN: config.topN,
    previousLayoutIds: prev,
    adjacentLayoutId,
    debug,
  });
  ranked = promotePreferred(ranked, preferredLayoutId);

  if (!ranked.length) {
    const fallback = list[0];
    return { layoutId: templateLayoutId(fallback) || null, template: fallback };
  }

  const layoutLocked = Boolean(outlineSlide?.layoutLocked);
  const selection = await selectBestLayoutWithAI({
    slide: profile,
    candidates: ranked,
    presentationContext: ctxPresentation,
    theme,
    previousLayoutIds: prev,
    layoutsById,
    slideCopy: {
      title: content?.title || outlineSlide?.title,
      subtitle: content?.subtitle,
      body: content?.body || outlineSlide?.summary,
    },
    layoutLocked,
    lockedLayoutId,
    phase,
    debug,
    chatJson,
  });

  const preferredId = avoidAdjacentSameFormat(
    selection.selectedLayoutId,
    adjacentLayoutId,
    ranked,
    layoutLocked
  );
  const layoutId = preferredId;
  const template = resolveTemplate(list, layoutId) || resolveTemplate(list, ranked[0].layoutId) || list[0];
  if (ctx && typeof ctx === 'object') {
    if (!Array.isArray(ctx.layoutSelectionLog)) ctx.layoutSelectionLog = [];
    ctx.layoutSelectionLog.push({
      slideNumber: Number(slide?.order || outlineSlide?.order || profile?.slideNumber || 0) || null,
      phase,
      purpose: profile?.purpose || null,
      candidateCount: ranked.length,
      topCandidates: ranked.slice(0, 5).map((r) => ({ layoutId: r.layoutId, score: r.score })),
      aiSelectedLayoutId: selection?.selectedLayoutId || null,
      aiConfidence: selection?.confidence ?? null,
      selectedLayoutId: templateLayoutId(template) || layoutId || null,
      adjacentAvoided: Boolean(
        adjacentLayoutId &&
          selection?.selectedLayoutId &&
          String(selection.selectedLayoutId) !== String(layoutId)
      ),
      source: selection?.source || 'deterministic',
    });
  }
  return {
    layoutId: templateLayoutId(template) || layoutId || null,
    template,
    selection,
  };
}

module.exports = {
  pickLayoutForGeneratedSlide,
  buildPresentationContext,
  templateLayoutId,
};
