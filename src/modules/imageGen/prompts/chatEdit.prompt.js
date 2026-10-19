const IMAGE_GEN_TWEAK_INSTRUCTION_MAX = 4_000;
const MAX_HISTORY_TURNS = 12;

/**
 * Compose an images.edit instruction from saved chat history + the latest user line.
 * Persist the raw user line in ImageGenMessage; send this composed string to OpenAI.
 */
function buildChatEditInstruction({
  originalPrompt = '',
  styleId = null,
  priorUserTurns = [],
  latestInstruction = '',
} = {}) {
  const original = String(originalPrompt || '').trim();
  const latest = String(latestInstruction || '').trim();
  const history = (Array.isArray(priorUserTurns) ? priorUserTurns : [])
    .map((turn) => String(turn || '').trim())
    .filter(Boolean)
    .slice(-MAX_HISTORY_TURNS);

  const parts = [];
  if (original) {
    parts.push(`Original: ${original}`);
  }
  if (styleId) {
    parts.push(`Style: ${styleId}`);
  }
  if (history.length) {
    parts.push('Prior user directions (oldest to newest):');
    history.forEach((line, index) => {
      parts.push(`${index + 1}. ${line}`);
    });
  }
  parts.push(
    'Apply this to the attached image; keep everything not mentioned:',
    latest || original
  );

  let composed = parts.filter(Boolean).join('\n');
  if (composed.length > IMAGE_GEN_TWEAK_INSTRUCTION_MAX) {
    composed = composed.slice(composed.length - IMAGE_GEN_TWEAK_INSTRUCTION_MAX);
  }
  return composed;
}

module.exports = {
  buildChatEditInstruction,
  MAX_HISTORY_TURNS,
  IMAGE_GEN_TWEAK_INSTRUCTION_MAX,
};
