const { evaluateLayoutCompatibility } = require('./layoutCompatibility');
const { scoreLayout, formatDebugLine, mergeWeights } = require('./scoreLayout');
const { toSlideContentProfile } = require('./toSlideContentProfile');

function stripInternal(result) {
  const { _debugParts, _available, _earned, _scaled, ...rest } = result;
  return rest;
}

function asProfile(slide) {
  if (!slide || typeof slide !== 'object') return toSlideContentProfile({});
  if (
    typeof slide.purpose === 'string' &&
    Array.isArray(slide.contentTypes) &&
    typeof slide.titleLength === 'number'
  ) {
    return slide;
  }
  return toSlideContentProfile(slide);
}

/**
 * Rank DeckLayout[] for a slide profile. Hard-filters first, then scores.
 * @returns {import('./layoutScoring.types').LayoutScore[]}
 */
function rankLayouts(slide, layouts, options = {}) {
  const profile = asProfile(slide);
  const topN = options.topN == null ? 10 : Math.max(0, Number(options.topN) || 0);
  const list = Array.isArray(layouts) ? layouts.filter((l) => l && l.id) : [];

  const accepted = [];
  const rejected = [];
  for (const layout of list) {
    const compat = evaluateLayoutCompatibility(profile, layout);
    if (compat.status === 'hardReject') rejected.push(layout);
    else accepted.push(layout);
  }

  const pool = accepted.length ? accepted : list;
  const unconstrained = accepted.length === 0 && list.length > 0;

  const scored = pool.map((layout) => {
    const result = scoreLayout(profile, layout, options);
    if (unconstrained) {
      result.warnings = [
        'No layouts passed hard filters; ranking unconstrained',
        ...(result.warnings || []),
      ];
    }
    return result;
  });

  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return String(a.layoutId).localeCompare(String(b.layoutId));
  });

  const sliced = scored.slice(0, topN || scored.length).map(stripInternal);

  if (options.debug) {
    const weights = mergeWeights(options.weights);
    for (const row of sliced) {
      console.log(formatDebugLine(profile, row, weights));
      console.log('---');
    }
  }

  return sliced;
}

module.exports = {
  rankLayouts,
};
