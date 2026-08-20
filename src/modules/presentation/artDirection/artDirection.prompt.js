/**
 * Deck-level art-direction prompt wrapper.
 *
 * v1 implementation is intentionally minimal. We keep the shape here so we can
 * add a single `chatJson` call later without changing the integration points.
 */
function buildDeckArtDirectionPrompt() {
  return {
    buildSystem() {
      return 'You are an art direction assistant for slide decks. Return semantic-only directions (no hex colors, no fonts, no JSON of slide elements).';
    },
    buildUser() {
      return 'Return semantic directions for themeId and visual strategies.';
    },
  };
}

module.exports = {
  buildDeckArtDirectionPrompt,
};

