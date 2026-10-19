function buildRouterSystem() {
  return [
    'Classify an infographic edit instruction as either "spec" or "pixel".',
    'Return JSON only: { "editMode": "spec" | "pixel", "reason": "short" }.',
    '',
    'Use "spec" when the ask changes content, structure, labels, numbers, order, title,',
    'sections, archetype, or design language / look (e.g. "more minimal", "make it corporate",',
    '"add a step", "swap step 2 and 3", "change the title").',
    '',
    'Use "pixel" ONLY for pure visual tweaks that do not change typed content',
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
    'You patch an existing InfographicSpec JSON based on a user edit instruction.',
    'Return the FULL revised InfographicSpec as JSON (not a diff).',
    '',
    'Rules:',
    '- Preserve prior visualStyle and palette UNLESS the user explicitly asks to change the look.',
    '- Preserve orientation and archetype unless the user asks to change structure type.',
    '- Keep all unchanged labels/metrics verbatim.',
    '- Still obey data honesty: do not invent private company metrics; public knowledge fills OK when needed.',
    '- Provide either sections OR flows, never both.',
    '- Return ONLY valid JSON.',
  ].join('\n');
}

function buildSpecPatchUser({ spec, instruction }) {
  return [
    'Current InfographicSpec JSON:',
    JSON.stringify(spec || {}, null, 2),
    '',
    'User edit instruction:',
    String(instruction || '').trim(),
    '',
    'Return the full revised InfographicSpec JSON.',
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
    /\b(add|remove|delete|swap|reorder|rename|change|replace|insert|move|title|subtitle|step|stage|section|label|metric|number|stat|compare|comparison|timeline|process|cycle|hierarchy|list|column|lane|flow)\b/;
  const specDesignRe =
    /\b(minimal|minimalist|corporate|playful|hand[- ]?drawn|flat|isometric|neon|watercolor|more\s+\w+\s+style|look\s+more|make\s+it\s+(more\s+)?(minimal|corporate|playful|serious|fun|bold|soft))\b/;

  const pixelHit = pixelRe.test(text);
  const specHit = specContentRe.test(text) || specDesignRe.test(text);

  if (specHit && !pixelHit) return 'spec';
  if (pixelHit && !specHit) return 'pixel';
  if (specHit && pixelHit) return 'spec';
  return null;
}

module.exports = {
  buildRouterSystem,
  buildRouterUser,
  buildSpecPatchSystem,
  buildSpecPatchUser,
  classifyEditHeuristic,
};
