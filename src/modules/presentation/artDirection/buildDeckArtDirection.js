const { buildDeckArtDirectionPrompt } = require('./artDirection.prompt');

function parseEnabledFlag(value) {
  if (value == null) return true;
  const v = String(value).trim().toLowerCase();
  if (v === '') return true;
  if (['0', 'false', 'off', 'no', 'disabled'].includes(v)) return false;
  return true;
}

/**
 * Build deck-level semantic art direction.
 *
 * v1 (this implementation) is deterministic and safe to run in unit tests:
 * it does not call OpenAI. It also keeps the prompt wrapper in place so we
 * can later upgrade to a single semantic-only `chatJson` call.
 */
async function buildDeckArtDirection({ ctx } = {}) {
  const enabled = parseEnabledFlag(process.env.PPT_ART_DIRECTION_AI_ENABLED);
  if (!enabled) {
    return {
      aiEnabled: false,
      deckArtDirection: null,
    };
  }

  // Deterministic fallback (no network):
  const themeTokens = ctx?.themeTokens || null;
  const mood = ctx?.outline?.mood || ctx?.outline?.visualMoods || 'cohesive';
  const imageStyle = ctx?.imageStylePhrase || themeTokens?.imageStyle || null;

  // Keep the prompt function referenced so future AI wiring is localized.
  buildDeckArtDirectionPrompt();

  return {
    aiEnabled: true,
    deckArtDirection: {
      themeId: themeTokens?.id || null,
      mood,
      imageStyle,
      visualDensity: ctx?.density || null,
      accentUsage: 'consistent',
      backgroundStrategy: 'deck_cohesive',
      coverStyle: 'hero_split',
      closingStyle: 'clean_finish',
    },
  };
}

module.exports = {
  buildDeckArtDirection,
};

