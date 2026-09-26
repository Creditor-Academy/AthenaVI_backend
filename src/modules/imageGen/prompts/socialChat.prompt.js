const { describeLimits } = require('./socialSpec.prompt');

function buildRouterSystem() {
  return [
    'Classify a social media graphic edit instruction as either "spec" or "pixel".',
    'Return JSON only: { "editMode": "spec" | "pixel", "reason": "short" }.',
    '',
    'Use "spec" when the ask changes on-image text, the call to action, the subject,',
    'the layout, or the design language (e.g. "change the headline", "add a CTA",',
    '"use a laptop instead of a phone", "make it more minimal").',
    '',
    'Use "pixel" ONLY for pure visual tweaks that keep the text and subject',
    '(e.g. "make the background darker", "increase contrast", "slightly brighter").',
    '',
    'When unsure, choose "spec".',
  ].join('\n');
}

function buildRouterUser(instruction) {
  return `Instruction:\n${String(instruction || '').trim()}`;
}

function buildSpecPatchSystem() {
  return [
    'You patch an existing SocialPostSpec JSON based on a user edit instruction.',
    'Return the FULL revised SocialPostSpec as JSON (not a diff).',
    '',
    'Rules:',
    '- The destination (size and platform) never changes.',
    '- Preserve prior visualStyle and palette UNLESS the user explicitly asks to change the look.',
    '- Keep unchanged copy verbatim.',
    '- Do not invent prices, dates, statistics, or company metrics.',
    '- Respect the copy limits; use an empty string when a limit is 0.',
    '- Return ONLY valid JSON.',
  ].join('\n');
}

function buildSpecPatchUser({ spec, instruction, format }) {
  return [
    `Destination: ${format.name}, ${format.width}x${format.height} px`,
    `Copy limits: ${describeLimits(format.textLimits)}`,
    '',
    'Current SocialPostSpec JSON:',
    JSON.stringify(spec || {}, null, 2),
    '',
    'User edit instruction:',
    String(instruction || '').trim(),
    '',
    'Return the full revised SocialPostSpec JSON.',
  ].join('\n');
}

/**
 * Fast heuristic router before calling the LLM.
 * @returns {'spec'|'pixel'|null} null = inconclusive
 */
function classifyEditHeuristic(instruction) {
  const text = String(instruction || '')
    .trim()
    .toLowerCase();
  if (!text) return null;

  const pixelRe =
    /\b(darker|brighter|lighter|contrast|saturation|blur|sharpen|noise|grain|background\s+colou?r|make\s+the\s+background|slightly\s+(more\s+)?(dark|bright|light))\b/;
  const specContentRe =
    /\b(add|remove|delete|rename|change|replace|rewrite|reword|move|headline|title|text|copy|caption|cta|button|price|date|subject|logo|layout|font|word|wording|say|spell)\b/;
  const specDesignRe =
    /\b(minimal|minimalist|corporate|playful|hand[- ]?drawn|flat|isometric|neon|watercolor|photo(real)?|3d|look\s+more|make\s+it\s+(more\s+)?(minimal|corporate|playful|serious|fun|bold|soft))\b/;

  const pixelHit = pixelRe.test(text);
  const specHit = specContentRe.test(text) || specDesignRe.test(text);

  if (specHit) return 'spec';
  if (pixelHit) return 'pixel';
  return null;
}

module.exports = {
  buildRouterSystem,
  buildRouterUser,
  buildSpecPatchSystem,
  buildSpecPatchUser,
  classifyEditHeuristic,
};
