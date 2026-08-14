const DENSITY_CAPS = {
  concise: { maxBullets: 3, maxWordsBody: 40, maxTitleLines: 1 },
  balanced: { maxBullets: 5, maxWordsBody: 60, maxTitleLines: 2 },
  detailed: { maxBullets: 7, maxWordsBody: 100, maxTitleLines: 2 },
};

function buildSystem() {
  return [
    'You are a presentation strategist. Build a clear, executive-grade outline for a slide deck.',
    'Each slide should work as a designed layout slide (title + visual), not a wall of bullets.',
    'Do NOT write full slide body copy. Do NOT invent layout or design.',
    'Also invent a concise presentation title from the source meaning — not a truncated copy of the prompt.',
    'Return JSON only matching the schema.',
  ].join(' ');
}

function buildPackEnrichSystem() {
  return [
    'You enrich a fixed deck-pack outline with original titles and summaries.',
    'The slide order, layoutId, suggestedContentType, and intent are FIXED — do not change them.',
    'Replace template placeholder wording with meaningful content derived from the user source.',
    'Do NOT echo placeholders like "Your Title", "Your subtitle", or "Lorem ipsum".',
    'Invent a concise deck title from the source meaning — not a truncated copy of the prompt.',
    'Return JSON only matching the schema.',
  ].join(' ');
}

/**
 * @param {{
 *   sourceText: string,
 *   slideCount?: number,
 *   density?: 'concise'|'balanced'|'detailed',
 *   audience?: string,
 *   voiceAndTone?: string,
 *   purpose?: string,
 *   locale?: string,
 * }} vars
 */
function buildUser(vars = {}) {
  const {
    sourceText = '',
    slideCount = 10,
    density = 'balanced',
    audience = '',
    voiceAndTone = '',
    purpose = '',
    locale = 'en',
  } = vars;

  return [
    voiceAndTone ? `Voice & tone: ${voiceAndTone}` : null,
    audience ? `Audience: ${audience}` : `Audience/use case: ${audience || 'inferred from source'}`,
    purpose ? `Purpose: ${purpose}` : null,
    `Locale: ${locale}`,
    `Slide count target: ${slideCount}`,
    `Density: ${density}`,
    '',
    'Source:',
    String(sourceText),
    '',
    'Rules:',
    '- Strong narrative arc: Opening (title) → Agenda/hook → 3–5 proof slides (image+text, stat, quote) → Section dividers between acts → Closing CTA',
    '- Slide order 1 MUST use suggestedContentType: title',
    '- Last slide should prefer closing or strong CTA',
    '- One idea per slide',
    '- Slide titles ≤ 8 words; summary ≤ 25 words',
    '- Cap consecutive bullet_list slides at 2; alternate with image+text, stat, quote, section_divider',
    '- Prefer image+text for body slides (maps to para/card/image layouts with pre-built shapes)',
    '- Deck `title`: concise natural title (prefer 3–10 words, max 255 chars).',
    '  Derive it from the meaning of the full source. Do NOT paste or truncate the prompt.',
    '  Example good: "AI in Modern Healthcare". Example bad: "Create a presentation about…"',
    '- suggestedContentType from:',
    '  title|agenda|bullet_list|comparison|stat|quote|image+text|',
    '  timeline|team|chart|diagram|closing|section_divider',
    '- Use diagram for SWOT, funnel, matrix/quadrant, process steps, cycle, pyramid — not path_b unless truly bespoke.',
    '- The system picks a deck arrangement archetype (pitch, educational, product, corporate) from your source —',
    '  use comparison for before/after or option contrasts; timeline for dated milestones or historical sequence;',
    '  use diagram for SWOT analysis, funnel, 2×2 matrix, or numbered process;',
    '  avoid repeating the same suggestedContentType on consecutive slides unless the narrative requires it.',
    '- Prefer image+text (or title/agenda/closing variants with imagery) for most slides so each slide can carry a visual.',
    '- Use chart only when the slide is primarily quantitative.',
    '',
    'Output JSON schema:',
    JSON.stringify(
      {
        title: 'AI in Modern Healthcare',
        slides: [
          {
            order: 1,
            title: '...',
            summary: '...',
            suggestedContentType: 'title',
          },
        ],
      },
      null,
      2
    ),
  ]
    .filter(Boolean)
    .join('\n');
}

/**
 * @param {{
 *   sourceText: string,
 *   density?: string,
 *   locale?: string,
 *   voiceAndTone?: string,
 *   audience?: string,
 *   purpose?: string,
 *   packSlides?: Array<object>,
 *   packNarrative?: object|null,
 * }} vars
 */
function buildPackEnrichUser(vars = {}) {
  const {
    sourceText = '',
    density = 'balanced',
    locale = 'en',
    voiceAndTone = '',
    audience = '',
    purpose = '',
    packSlides = [],
    packNarrative = null,
  } = vars;

  const narrativeLines = [];
  if (packNarrative?.arc) narrativeLines.push(`Pack narrative arc: ${packNarrative.arc}`);
  if (packNarrative?.summary) narrativeLines.push(`Pack narrative: ${packNarrative.summary}`);

  return [
    'Fixed pack slide blueprint (preserve order, layoutId, suggestedContentType, intent):',
    JSON.stringify(packSlides, null, 2),
    '',
    voiceAndTone ? `Voice & tone: ${voiceAndTone}` : null,
    audience ? `Audience: ${audience}` : null,
    purpose ? `Purpose: ${purpose}` : null,
    `Locale: ${locale}`,
    `Density: ${density}`,
    narrativeLines.length ? narrativeLines.join('\n') : null,
    '',
    'User source / prompt:',
    String(sourceText),
    '',
    'Rules:',
    '- Return exactly one slide entry per pack slide (same order values).',
    '- Provide fresh title + summary per slide aligned with pack intent and user source.',
    '- Do NOT change layoutId, suggestedContentType, or intent fields.',
    '- Deck title: concise natural title from source meaning (3–10 words).',
    '',
    'Output JSON schema:',
    JSON.stringify(
      {
        title: 'Concise Deck Title',
        slides: packSlides.map((s) => ({
          order: s.order,
          title: 'Fresh slide title',
          summary: 'Fresh slide summary',
        })),
      },
      null,
      2
    ),
  ]
    .filter(Boolean)
    .join('\n');
}

module.exports = {
  buildSystem,
  buildUser,
  buildPackEnrichSystem,
  buildPackEnrichUser,
  DENSITY_CAPS,
};
