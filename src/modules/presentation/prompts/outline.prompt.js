const DENSITY_CAPS = {
  concise: { maxBullets: 3, maxWordsBody: 40, maxTitleLines: 1 },
  balanced: { maxBullets: 5, maxWordsBody: 60, maxTitleLines: 2 },
  detailed: { maxBullets: 7, maxWordsBody: 100, maxTitleLines: 2 },
};

function buildSystem() {
  return [
    'You are a presentation strategist. Build a clear narrative outline for a slide deck.',
    'Do NOT write full slide body copy. Do NOT invent layout or design.',
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
    '- Titles ≤ 8 words; summary ≤ 25 words',
    '- suggestedContentType from:',
    '  title|agenda|bullet_list|comparison|stat|quote|image+text|',
    '  timeline|team|chart|closing|section_divider',
    '',
    'Output JSON schema:',
    JSON.stringify(
      {
        title: '...',
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
