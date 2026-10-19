const AI_LAYOUT_SELECTOR_SYSTEM_PROMPT = `You are an expert presentation art director and information designer.

Your job is to select the BEST EXISTING slide layout for the current slide.

You are NOT designing a new layout.

You may ONLY select one layout from the provided candidates.

Evaluate layouts based on:

1. Semantic fit
2. Content structure
3. Storytelling purpose
4. Information hierarchy
5. Content density
6. Visual composition
7. Presentation flow
8. Audience expectations
9. Existing deterministic score

Do not select a layout simply because it looks attractive.

The layout must make the current content easier to understand.

Never invent:
- layout IDs
- layouts
- colors
- fonts
- Canvas elements
- positions
- unsupported components

You MUST return exactly one layoutId from the supplied candidates.

If two layouts are similar, prefer the one that creates stronger visual variety compared with previous slides.

Avoid unnecessary layout repetition.

The deterministic score represents structural compatibility. Use it as a strong signal.

However, evaluate semantic suitability before making the final decision.

You may override a slightly lower deterministic score when the semantic/content fit is clearly better.

Do not override a layout with a significantly worse compatibility score unless there is a strong semantic reason.

Choose a layout that supports the narrative role of this slide.

Do not evaluate the slide in isolation.

Consider how the current slide visually and structurally follows the previous slide and leads into the next slide.

Content fit always takes priority over repetition avoidance. Do not reject a layout solely because it was previously used.

Return JSON only. No chain-of-thought.`;

function truncate(text, max = 240) {
  const s = String(text || '').trim();
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function compactLayout(layout) {
  if (!layout || typeof layout !== 'object') return {};
  return {
    name: layout.name,
    category: layout.category,
    slidePurposes: layout.slidePurposes,
    contentTypes: layout.contentTypes,
    composition: layout.composition
      ? {
          structure: layout.composition.structure,
          visualWeight: layout.composition.visualWeight,
          imagePosition: layout.composition.imagePosition,
          textPosition: layout.composition.textPosition,
        }
      : undefined,
    contentCapacity: layout.contentCapacity
      ? { density: layout.contentCapacity.density }
      : undefined,
    supportedElements: layout.supportedElements,
    style: layout.style
      ? {
          designStyles: layout.style.designStyles,
          moods: layout.style.moods,
          industries: layout.style.industries,
        }
      : undefined,
  };
}

function compactCandidates(candidates, layoutsById = {}) {
  return (Array.isArray(candidates) ? candidates : []).map((row) => {
    const layout = layoutsById[row.layoutId] || row.layout || {};
    return {
      layoutId: row.layoutId,
      score: row.score,
      breakdown: row.breakdown,
      reasons: row.reasons,
      layout: compactLayout(layout),
    };
  });
}

function formatScoreDump(candidates) {
  return (Array.isArray(candidates) ? candidates : [])
    .map((row) => {
      const b = row.breakdown || {};
      return [
        row.layoutId,
        `Deterministic score: ${row.score}`,
        '',
        `Purpose: ${b.purposeMatch ?? 0}/25`,
        `Content: ${b.contentTypeMatch ?? 0}/25`,
        `Capacity: ${b.capacityMatch ?? 0}/15`,
        `Composition: ${b.compositionMatch ?? 0}/10`,
        `Style: ${b.styleMatch ?? 0}/10`,
        `Industry: ${b.industryMatch ?? 0}/5`,
        `Penalty: ${b.repetitionPenalty ?? 0}`,
      ].join('\n');
    })
    .join('\n\n');
}

function buildLayoutAiUserPrompt({
  slide,
  candidates,
  presentationContext = {},
  previousLayoutIds = [],
  slideCopy = {},
  layoutsById = {},
  theme = null,
}) {
  const ctx = presentationContext || {};
  const compact = compactCandidates(candidates, layoutsById);
  const allowedIds = compact.map((c) => c.layoutId);

  const prev = Array.isArray(ctx.previousSlides) ? ctx.previousSlides : [];
  const lastPrev = prev[prev.length - 1];
  const previousPurpose = lastPrev?.purpose || '';
  const nextPurpose = ctx.nextSlide?.purpose || '';

  const copy = {
    purpose: slide?.purpose,
    contentTypes: slide?.contentTypes,
    density: slide?.density,
    titleLength: slide?.titleLength,
    subtitleLength: slide?.subtitleLength,
    bodyLength: slide?.bodyLength,
    bulletCount: slide?.bulletCount,
    cardCount: slide?.cardCount,
    imageCount: slide?.imageCount,
    metricCount: slide?.metricCount,
    hasChart: slide?.hasChart,
    hasTable: slide?.hasTable,
    hasQuote: slide?.hasQuote,
  };
  if (slideCopy.title) copy.title = truncate(slideCopy.title);
  if (slideCopy.subtitle) copy.subtitle = truncate(slideCopy.subtitle);
  if (slideCopy.body) copy.body = truncate(slideCopy.body);

  const themeTone = theme?.tone || theme?.name || '';

  const lines = [
    'Presentation context',
    `Title: ${ctx.title || ''}`,
    `Purpose: ${ctx.purpose || ''}`,
    `Audience: ${ctx.audience || ''}`,
    `Industry: ${ctx.industry || ''}`,
    `Tone: ${ctx.tone || themeTone || ''}`,
    `Current slide: ${ctx.slideNumber || slide?.slideNumber || ''} of ${ctx.totalSlides || ''}`,
    '',
    `Previous slide purpose: ${previousPurpose || '(none)'}`,
    `Current slide purpose: ${slide?.purpose || ''}`,
    `Next slide purpose: ${nextPurpose || '(none)'}`,
    '',
    'Previous layout IDs:',
    previousLayoutIds.length ? previousLayoutIds.join('\n') : '(none)',
    '',
    'Current slide content (normalized):',
    JSON.stringify(copy, null, 2),
    '',
    'Allowed layout IDs (you MUST pick one of these):',
    allowedIds.join('\n'),
    '',
    'Candidate layouts (semantic metadata only):',
    JSON.stringify(compact, null, 2),
    '',
    'Deterministic compatibility scores:',
    formatScoreDump(candidates),
  ];

  return lines.join('\n');
}

module.exports = {
  AI_LAYOUT_SELECTOR_SYSTEM_PROMPT,
  compactCandidates,
  compactLayout,
  formatScoreDump,
  buildLayoutAiUserPrompt,
};
