const { describeLimits, describeSize } = require('./printSpec.prompt');
const { classifyEditHeuristic: socialHeuristic } = require('./socialChat.prompt');

function buildRouterSystem() {
  return [
    'Classify an edit instruction for a printed design (poster, business card, invitation) as either "spec" or "pixel".',
    'Return JSON only: { "editMode": "spec" | "pixel", "reason": "short" }.',
    '',
    'Use "spec" when the ask changes printed text (name, title, date, venue, phone, email, headline),',
    'adds or removes a line, changes the subject or layout, or changes the design language.',
    '',
    'Use "pixel" ONLY for pure visual tweaks that keep every word and the layout',
    '(e.g. "make the background darker", "increase contrast", "warmer colors").',
    '',
    'When unsure, choose "spec".',
  ].join('\n');
}

function buildRouterUser(instruction) {
  return `Instruction:\n${String(instruction || '').trim()}`;
}

function buildSpecPatchSystem() {
  return [
    'You patch an existing PrintSpec JSON based on a user edit instruction.',
    'Return the FULL revised PrintSpec as JSON (not a diff).',
    '',
    'Rules:',
    '- The print size never changes.',
    '- Preserve prior visualStyle and palette UNLESS the user explicitly asks to change the look.',
    '- Keep unchanged copy and detail lines verbatim.',
    '- Never invent phone numbers, emails, websites, addresses, dates, prices, or statistics.',
    '- Respect the copy limits; use an empty string when a limit is 0.',
    '- Return ONLY valid JSON.',
  ].join('\n');
}

function buildSpecPatchUser({ spec, instruction, format }) {
  return [
    `Print size: ${describeSize(format)}`,
    `Copy limits: ${describeLimits(format.textLimits)}`,
    '',
    'Current PrintSpec JSON:',
    JSON.stringify(spec || {}, null, 2),
    '',
    'User edit instruction:',
    String(instruction || '').trim(),
    '',
    'Return the full revised PrintSpec JSON.',
  ].join('\n');
}

const PRINT_SPEC_RE =
  /\b(name|job\s+title|phone|mobile|email|e-mail|website|address|venue|rsvp|date|time|dress\s+code|tagline|line|details?)\b/;

/**
 * Fast heuristic router before calling the LLM.
 * @returns {'spec'|'pixel'|null} null = inconclusive
 */
function classifyEditHeuristic(instruction) {
  const text = String(instruction || '')
    .trim()
    .toLowerCase();
  if (!text) return null;
  if (PRINT_SPEC_RE.test(text)) return 'spec';
  return socialHeuristic(text);
}

module.exports = {
  buildRouterSystem,
  buildRouterUser,
  buildSpecPatchSystem,
  buildSpecPatchUser,
  classifyEditHeuristic,
};
