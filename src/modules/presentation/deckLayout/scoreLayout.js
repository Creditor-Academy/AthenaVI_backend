const {
  DEFAULT_LAYOUT_SCORING_WEIGHTS,
  RELATED_PURPOSES,
  PURPOSE_CATEGORY_WEAK,
  RELATED_INDUSTRY_GROUPS,
  CONTENT_TYPE_TO_SUPPORTED,
  REPETITION_PENALTIES,
  ADJACENT_LAYOUT_PENALTY,
} = require('./layoutScoring.weights');
const { evaluateLayoutCompatibility } = require('./layoutCompatibility');

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function round1(n) {
  return Math.round(n * 10) / 10;
}

function mergeWeights(override) {
  return { ...DEFAULT_LAYOUT_SCORING_WEIGHTS, ...(override || {}) };
}

function confidenceFromScore(score) {
  if (score >= 90) return 'excellent';
  if (score >= 80) return 'strong';
  if (score >= 70) return 'good';
  if (score >= 60) return 'acceptable';
  return 'weak';
}

function repetitionPenaltyFor(layoutId, previousLayoutIds) {
  const prev = Array.isArray(previousLayoutIds) ? previousLayoutIds : [];
  const count = prev.filter((id) => String(id) === String(layoutId)).length;
  if (count >= 3) return REPETITION_PENALTIES[3];
  if (count === 2) return REPETITION_PENALTIES[2];
  if (count === 1) return REPETITION_PENALTIES[1];
  return 0;
}

function adjacentPenaltyFor(layoutId, adjacentLayoutId) {
  const adj = String(adjacentLayoutId || '').trim();
  if (!adj) return 0;
  return String(layoutId) === adj ? ADJACENT_LAYOUT_PENALTY : 0;
}

function scorePurpose(slide, layout, max) {
  const purposes = Array.isArray(layout?.slidePurposes) ? layout.slidePurposes : [];
  const purpose = String(slide.purpose || '').toLowerCase();
  if (!purpose) {
    return { points: null, skipped: true, reason: null };
  }
  if (!purposes.length) {
    return { points: null, skipped: true, reason: null };
  }
  if (purposes.includes(purpose)) {
    return { points: max, skipped: false, reason: `Exact match for ${purpose} slide purpose` };
  }
  const related = RELATED_PURPOSES[purpose] || [];
  if (purposes.some((p) => related.includes(p))) {
    return { points: Math.round(max * (18 / 25)), skipped: false, reason: `Related purpose match for ${purpose}` };
  }
  const weakCats = PURPOSE_CATEGORY_WEAK[purpose] || [];
  if (layout.category && weakCats.includes(layout.category)) {
    return { points: Math.round(max * (8 / 25)), skipped: false, reason: `Weak category alignment (${layout.category})` };
  }
  return { points: 0, skipped: false, reason: null };
}

function scoreContentTypes(slide, layout, max) {
  const needed = Array.isArray(slide.contentTypes) ? slide.contentTypes.filter(Boolean) : [];
  const offered = Array.isArray(layout?.contentTypes) ? layout.contentTypes.filter(Boolean) : [];
  const supported = layout?.supportedElements;

  if (!needed.length) {
    return { points: null, skipped: true, reason: null };
  }

  const needSet = new Set(needed);
  const offerSet = new Set(offered);
  let overlap = 0;
  for (const t of needSet) {
    if (offerSet.has(t)) overlap += 1;
  }
  const union = new Set([...needSet, ...offerSet]);
  const jaccard = union.size ? overlap / union.size : 0;

  let supportHits = 0;
  let supportTotal = 0;
  for (const t of needSet) {
    const key = CONTENT_TYPE_TO_SUPPORTED[t];
    if (!key || !supported || typeof supported[key] !== 'boolean') continue;
    supportTotal += 1;
    if (supported[key] === true) supportHits += 1;
  }
  const supportRatio = supportTotal ? supportHits / supportTotal : 1;
  const blended = jaccard * 0.7 + supportRatio * 0.3;
  const points = round1(blended * max);

  let reason = null;
  if (overlap === needSet.size && needSet.size > 0) {
    reason = `Supports all requested content types (${[...needSet].join(', ')})`;
  } else if (overlap > 0) {
    reason = `Partial content-type overlap (${overlap}/${needSet.size})`;
  }

  return { points, skipped: false, reason };
}

function dimensionScore(need, maxCap) {
  if (!need) return null;
  if (maxCap == null) return null;
  if (maxCap <= 0) return 0;
  const ratio = need / maxCap;
  if (ratio > 1) {
    const overflow = Math.min(1, (ratio - 1) / 1.5);
    return clamp(0.45 - overflow * 0.45, 0, 0.45);
  }
  if (ratio >= 0.45 && ratio <= 0.9) return 1;
  if (ratio > 0.9) return 0.82;
  return 0.62 + ratio * 0.5;
}

function scoreCapacity(slide, layout, max, warnings) {
  const cap = layout?.contentCapacity;
  if (!cap || typeof cap !== 'object') {
    return { points: null, skipped: true, reason: null };
  }

  const dims = [
    ['title', slide.titleLength, cap.maxTitleCharacters],
    ['subtitle', slide.subtitleLength, cap.maxSubtitleCharacters],
    ['body', slide.bodyLength, cap.maxBodyCharacters],
    ['bullets', slide.bulletCount, cap.maxBullets],
    ['cards', slide.cardCount, cap.maxCards],
    ['images', slide.imageCount, cap.maxImages],
    ['metrics', slide.metricCount, cap.maxMetrics],
    ['columns', slide.columnCount || 0, cap.maxColumns],
  ];

  const parts = [];
  for (const [name, need, maxCap] of dims) {
    const piece = dimensionScore(need, maxCap == null ? null : Number(maxCap));
    if (piece == null) continue;
    parts.push(piece);
    if (need && maxCap > 0 && need > maxCap) {
      warnings.push(`${name} ${need} exceeds layout max ${maxCap}`);
    }
  }

  if (!parts.length) {
    return { points: null, skipped: true, reason: null };
  }

  const avg = parts.reduce((a, b) => a + b, 0) / parts.length;
  const overflow = dims.some(([, need, maxCap]) => need && maxCap > 0 && need > maxCap);
  const adjusted = overflow ? Math.min(avg, 0.28) : avg;
  const points = round1(adjusted * max);
  let reason = null;
  if (!overflow && avg >= 0.9) reason = 'Content density fits the layout';
  else if (!overflow && avg >= 0.7) reason = 'Content mostly fits layout capacity';
  return { points, skipped: false, reason };
}

function inferredVisualNeed(slide) {
  if (slide.hasChart || slide.hasTable || slide.metricCount >= 2) return 'data-heavy';
  // Cover / title slides with image intent should prefer hero/split compositions
  // even when the outline summary is long.
  const purpose = String(slide.purpose || '').toLowerCase();
  const isCover =
    Number(slide.slideNumber) === 1 || purpose === 'cover' || purpose === 'title';
  if (isCover && slide.imageCount > 0) return 'image-heavy';
  if (slide.imageCount > 0 && slide.bodyLength < 120 && slide.bulletCount <= 2 && slide.cardCount <= 1) {
    return 'image-heavy';
  }
  if ((slide.bodyLength >= 160 || slide.bulletCount >= 4) && slide.imageCount === 0) return 'text-heavy';
  return 'balanced';
}

function scoreComposition(slide, layout, max) {
  const composition = layout?.composition;
  if (!composition || typeof composition !== 'object') {
    return { points: null, skipped: true, reason: null };
  }
  const need = inferredVisualNeed(slide);
  const weight = String(composition.visualWeight || '');
  const structure = String(composition.structure || '');

  let ratio = 0.4;
  if (need === 'image-heavy') {
    if (weight === 'image-heavy') ratio = 1;
    else if (['split', 'full-image', 'image-heavy'].includes(structure)) ratio = 0.88;
    else if (weight === 'balanced') ratio = 0.55;
    else ratio = 0.25;
  } else if (need === 'text-heavy') {
    if (weight === 'text-heavy') ratio = 1;
    else if (['text-heavy', 'centered', 'two-column'].includes(structure)) ratio = 0.88;
    else if (weight === 'balanced') ratio = 0.55;
    else ratio = 0.25;
  } else if (need === 'data-heavy') {
    if (weight === 'data-heavy') ratio = 1;
    else if (layout.category === 'chart' || layout.category === 'data' || layout.supportedElements?.metrics) {
      ratio = 0.9;
    } else if (weight === 'balanced') ratio = 0.5;
    else ratio = 0.2;
  } else if (weight === 'balanced' || !weight) {
    ratio = 0.85;
  }

  const points = round1(ratio * max);
  let reason = null;
  if (ratio >= 0.85) reason = `Composition matches ${need} content`;
  return { points, skipped: false, reason };
}

function scoreDomainIntent(slide, layout, reasons) {
  let boost = 0;
  const contentTypes = Array.isArray(layout?.contentTypes) ? layout.contentTypes : [];
  const purposes = Array.isArray(layout?.slidePurposes) ? layout.slidePurposes : [];
  const tags = Array.isArray(layout?.tags) ? layout.tags.map((t) => String(t).toLowerCase()) : [];
  const id = String(layout?.id || '').toLowerCase();

  if (slide.hasDeviceMockup && (id.includes('device') || contentTypes.includes('image'))) {
    boost += 3;
    reasons.push('Supports device/mockup storytelling');
  }
  if (slide.hasTimeline && (contentTypes.includes('timeline') || id.includes('timeline') || purposes.includes('roadmap'))) {
    boost += 3;
    reasons.push('Good fit for timeline/roadmap narrative');
  }
  if (slide.hasPricing && (purposes.includes('pricing') || layout?.category === 'pricing' || tags.includes('pricing'))) {
    boost += 4;
    reasons.push('Layout aligns with pricing comparison content');
  }
  if (slide.hasTeam && (purposes.includes('team') || layout?.category === 'team' || id.includes('team'))) {
    boost += 3;
    reasons.push('Layout aligns with team introduction content');
  }
  if (
    slide.hasContact &&
    (id.includes('contact') ||
      id.includes('closing_contact') ||
      purposes.includes('conclusion') ||
      tags.includes('contact') ||
      tags.includes('cta'))
  ) {
    boost += 5;
    reasons.push('Layout aligns with contact/CTA closing intent');
  }
  // Title / cover: boost split-hero and image-capable layouts when image intent is set.
  const isCover =
    Number(slide.slideNumber) === 1 ||
    String(slide.purpose || '').toLowerCase() === 'cover';
  if (isCover && slide.imageCount > 0) {
    const structure = String(layout?.composition?.structure || '').toLowerCase();
    const weight = String(layout?.composition?.visualWeight || '').toLowerCase();
    if (
      id.includes('hero') ||
      id.includes('fullbleed') ||
      structure === 'split' ||
      structure === 'full-image' ||
      weight === 'image-heavy'
    ) {
      boost += 4;
      reasons.push('Cover slide prefers image-forward hero layout');
    }
  }
  if (slide.hasChart && slide.chartType && (id.includes(slide.chartType) || tags.includes(slide.chartType))) {
    boost += 2;
    reasons.push(`Chart-oriented fit (${slide.chartType})`);
  }
  return boost;
}

function scoreStyle(slide, layout, max) {
  const prefs = [
    ...((slide.preferredStyles || []).map((s) => String(s).toLowerCase())),
    ...((slide.preferredMoods || []).map((s) => String(s).toLowerCase())),
  ];
  if (!prefs.length) {
    return { points: null, skipped: true, reason: null };
  }
  const style = layout?.style;
  const offered = [
    ...((style?.designStyles || []).map((s) => String(s).toLowerCase())),
    ...((style?.moods || []).map((s) => String(s).toLowerCase())),
  ];
  if (!offered.length) {
    return { points: null, skipped: true, reason: null };
  }
  const hits = prefs.filter((p) => offered.includes(p)).length;
  const ratio = hits / prefs.length;
  const points = round1(ratio * max);
  const reason = hits ? `Compatible with ${hits === prefs.length ? 'preferred' : 'some'} presentation styles` : null;
  return { points, skipped: false, reason };
}

function industriesRelated(a, b) {
  const left = String(a).toLowerCase();
  const right = String(b).toLowerCase();
  if (left === right) return 'exact';
  for (const group of RELATED_INDUSTRY_GROUPS) {
    if (group.includes(left) && group.includes(right)) return 'related';
  }
  return 'none';
}

function scoreIndustry(slide, layout, max) {
  const industry = slide.industry ? String(slide.industry).toLowerCase() : '';
  if (!industry) {
    return { points: null, skipped: true, reason: null };
  }
  const list = Array.isArray(layout?.style?.industries) ? layout.style.industries : [];
  if (!list.length) {
    return { points: null, skipped: true, reason: null };
  }
  let best = 'none';
  for (const item of list) {
    const rel = industriesRelated(industry, item);
    if (rel === 'exact') {
      best = 'exact';
      break;
    }
    if (rel === 'related') best = 'related';
  }
  if (best === 'exact') {
    return { points: max, skipped: false, reason: `Industry match (${industry})` };
  }
  if (best === 'related') {
    return { points: Math.round(max * 0.6), skipped: false, reason: `Related industry (${industry})` };
  }
  return { points: Math.max(1, Math.round(max * 0.2)), skipped: false, reason: null };
}

/**
 * Score one DeckLayout against a SlideContentProfile (0–100).
 */
function scoreLayout(slide, layout, options = {}) {
  const weights = mergeWeights(options.weights);
  const warnings = [];
  const reasons = [];
  const layoutId = String(layout?.id || layout?.schema?.layout_id || '');

  const compat = evaluateLayoutCompatibility(slide, layout);
  for (const p of compat.penalties || []) {
    if (p.message) warnings.push(p.message);
  }

  const parts = {
    purposeMatch: scorePurpose(slide, layout, weights.purposeMatch),
    contentTypeMatch: scoreContentTypes(slide, layout, weights.contentTypeMatch),
    capacityMatch: scoreCapacity(slide, layout, weights.capacityMatch, warnings),
    compositionMatch: scoreComposition(slide, layout, weights.compositionMatch),
    styleMatch: scoreStyle(slide, layout, weights.styleMatch),
    industryMatch: scoreIndustry(slide, layout, weights.industryMatch),
  };

  let earned = 0;
  let available = 0;
  for (const [key, result] of Object.entries(parts)) {
    if (result.skipped) continue;
    available += weights[key];
    earned += Number(result.points) || 0;
    if (result.reason) reasons.push(result.reason);
  }

  let scaled = available > 0 ? Math.round((earned / available) * 100) : 0;
  const repetitionPenalty = repetitionPenaltyFor(layoutId, options.previousLayoutIds);
  if (repetitionPenalty) {
    warnings.push(
      `Layout already used ${Array.isArray(options.previousLayoutIds) ? options.previousLayoutIds.filter((id) => String(id) === layoutId).length : 0} time(s)`
    );
  }
  const adjacentPenalty = adjacentPenaltyFor(layoutId, options.adjacentLayoutId);
  if (adjacentPenalty) {
    warnings.push('Same layout as previous slide');
  }
  const uniqueWarnings = [...new Set(warnings)];
  const domainBoost = scoreDomainIntent(slide, layout, reasons);
  const score = clamp(scaled + repetitionPenalty + adjacentPenalty + domainBoost, 0, 100);

  if (!reasons.length) reasons.push('Scored from available layout metadata');

  const breakdown = {
    purposeMatch: parts.purposeMatch.skipped ? 0 : Number(parts.purposeMatch.points) || 0,
    contentTypeMatch: parts.contentTypeMatch.skipped ? 0 : Number(parts.contentTypeMatch.points) || 0,
    capacityMatch: parts.capacityMatch.skipped ? 0 : Number(parts.capacityMatch.points) || 0,
    compositionMatch: parts.compositionMatch.skipped ? 0 : Number(parts.compositionMatch.points) || 0,
    styleMatch: parts.styleMatch.skipped ? 0 : Number(parts.styleMatch.points) || 0,
    industryMatch: parts.industryMatch.skipped ? 0 : Number(parts.industryMatch.points) || 0,
    repetitionPenalty,
    adjacentPenalty,
  };

  return {
    layoutId,
    score,
    confidence: confidenceFromScore(score),
    breakdown,
    reasons,
    warnings: uniqueWarnings,
    _debugParts: parts,
    _available: available,
    _earned: earned,
    _scaled: scaled,
  };
}

function formatDebugLine(slide, result, weights) {
  const b = result.breakdown;
  const w = mergeWeights(weights);
  const slideLabel = slide.slideNumber != null ? `Slide ${slide.slideNumber}` : 'Slide';
  return [
    `${slideLabel}`,
    `Purpose: ${slide.purpose || 'n/a'}`,
    '',
    result.layoutId,
    `Purpose: ${b.purposeMatch}/${w.purposeMatch}`,
    `Content: ${b.contentTypeMatch}/${w.contentTypeMatch}`,
    `Capacity: ${b.capacityMatch}/${w.capacityMatch}`,
    `Composition: ${b.compositionMatch}/${w.compositionMatch}`,
    `Style: ${b.styleMatch}/${w.styleMatch}`,
    `Industry: ${b.industryMatch}/${w.industryMatch}`,
    `Penalty: ${b.repetitionPenalty}`,
    '',
    `FINAL: ${result.score}`,
  ].join('\n');
}

module.exports = {
  scoreLayout,
  confidenceFromScore,
  mergeWeights,
  formatDebugLine,
  inferredVisualNeed,
};
