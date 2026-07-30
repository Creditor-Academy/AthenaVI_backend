const DENSITY_CAPS = {
  concise: { maxBullets: 3, maxWordsBody: 40, maxTitleLines: 1 },
  balanced: { maxBullets: 5, maxWordsBody: 60, maxTitleLines: 2 },
  detailed: { maxBullets: 7, maxWordsBody: 100, maxTitleLines: 2 },
};

function buildSystem() {
  return [
    'You are a presentation strategist. Build a clear narrative outline for a slide deck.',
    'Do NOT write full slide body copy. Do NOT invent layout or design.',
    'Also invent a concise presentation title from the source meaning — not a truncated copy of the prompt.',
    'Return JSON only matching the schema.',
  ].join(' ');
}

/**
 * @param {{
 *   sourceText: string,
 *   slideCount?: number,
 *   density?: 'concise'|'balanced'|'detailed',
 *   audience?: string,
 *   locale?: string,
 * }} vars
 */
function buildUser(vars = {}) {
  const {
    sourceText = '',
    slideCount = 10,
    density = 'balanced',
    audience = '',
    locale = 'en',
  } = vars;

  return [
    `Audience/use case: ${audience || 'inferred from source'}`,
    `Locale: ${locale}`,
    `Slide count target: ${slideCount}`,
    `Density: ${density}`,
    '',
    'Source:',
    String(sourceText),
    '',
    'Rules:',
    '- Strong narrative arc (hook → problem → solution → proof → close)',
    '- One idea per slide',
    '- Slide titles ≤ 8 words; summary ≤ 25 words',
    '- Deck `title`: concise natural title (prefer 3–10 words, max 255 chars).',
    '  Derive it from the meaning of the full source. Do NOT paste or truncate the prompt.',
    '  Example good: "AI in Modern Healthcare". Example bad: "Create a presentation about…"',
    '- suggestedContentType from:',
    '  title|agenda|bullet_list|comparison|stat|quote|image+text|',
    '  timeline|team|chart|closing|section_divider',
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
  ].join('\n');
}

module.exports = {
  buildSystem,
  buildUser,
  DENSITY_CAPS,
};
