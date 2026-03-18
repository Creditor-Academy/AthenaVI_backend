/**
 * Estimate speech duration for a script (seconds).
 * Used for TTS-driven timeline when no external TTS duration API is called.
 * Approximate: ~0.4 seconds per word (replace with HeyGen TTS duration when available).
 */
const SECONDS_PER_WORD = 0.4;

function estimateDuration(scriptText) {
  if (!scriptText || typeof scriptText !== 'string') return 0;
  const trimmed = scriptText.trim();
  if (!trimmed) return 0;
  const wordCount = trimmed.split(/\s+/).filter(Boolean).length;
  return Math.max(0, Math.round((wordCount * SECONDS_PER_WORD) * 10) / 10);
}

module.exports = { estimateDuration };
