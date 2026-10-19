'use strict';

const { evaluateLayoutCompatibility } = require('./layoutCompatibility');
const { rankLayouts } = require('./rankLayouts');

/**
 * Pick the best layout that passes hard compatibility when ranked pools are empty.
 * @param {import('./layoutScoring.types').SlideContentProfile} profile
 * @param {import('./deckLayout.types').DeckLayout[]} deckLayouts
 * @returns {import('./deckLayout.types').DeckLayout|null}
 */
function pickSafeLayoutFallback(profile, deckLayouts, options = {}) {
  const excluded = new Set(
    (Array.isArray(options.excludeLayoutIds) ? options.excludeLayoutIds : [])
      .map((id) => String(id || '').trim())
      .filter(Boolean)
  );
  const list = Array.isArray(deckLayouts) ? deckLayouts.filter((l) => l && l.id) : [];
  const compatible = list.filter(
    (layout) =>
      !excluded.has(String(layout.id)) &&
      evaluateLayoutCompatibility(profile, layout).status !== 'hardReject'
  );
  if (!compatible.length) return null;
  const ranked = rankLayouts(profile, compatible, { topN: 1 });
  if (ranked.length && ranked[0].layoutId) {
    return compatible.find((l) => l.id === ranked[0].layoutId) || compatible[0];
  }
  return compatible[0];
}

module.exports = {
  pickSafeLayoutFallback,
};
