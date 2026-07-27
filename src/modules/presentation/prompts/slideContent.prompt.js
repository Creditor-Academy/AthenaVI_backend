const DENSITY_CAPS = {
  concise: { maxBullets: 3, maxWordsBody: 40, maxTitleLines: 1 },
  balanced: { maxBullets: 5, maxWordsBody: 60, maxTitleLines: 2 },
  detailed: { maxBullets: 7, maxWordsBody: 100, maxTitleLines: 2 },
};

function resolveCaps(density = 'balanced') {
  return DENSITY_CAPS[density] || DENSITY_CAPS.balanced;
}

function buildSystem() {
  return [
    'You write slide copy for a design-system renderer.',
    'Fill content slots only. No layout, colors, fonts, or coordinates.',
    'Enforce hard density limits. Prefer short bullets over paragraphs.',
    'Always include speaker notes in "notes".',
    'If the slide needs a bespoke multi-panel diagram, fill pathBSpec with exact panel titles, labels, and legend — copy is decided here; the image model only typesets later.',
    'Return JSON only.',
  ].join(' ');
}

/**
 * @param {{
 *   deckTitle?: string,
 *   themeTone?: string,
 *   density?: 'concise'|'balanced'|'detailed',
 *   slideOrder?: number,
 *   slideTotal?: number,
 *   title?: string,
 *   summary?: string,
 *   suggestedContentType?: string,
 *   previousSlideTitle?: string,
 *   nextSlideTitle?: string,
 *   locale?: string,
 * }} vars
 */
function buildUser(vars = {}) {
  const density = vars.density || 'balanced';
  const caps = resolveCaps(density);

  return [
    `Deck title: ${vars.deckTitle || ''}`,
    `Theme tone: ${vars.themeTone || 'professional'}`,
    `Density: ${density}`,
    `Locale: ${vars.locale || 'en'}`,
    `Max bullets: ${caps.maxBullets} | Max words body: ${caps.maxWordsBody} | Max title lines: ${caps.maxTitleLines}`,
    `Slide order: ${vars.slideOrder || 1}/${vars.slideTotal || 1}`,
    `Title: ${vars.title || ''}`,
    `Summary: ${vars.summary || ''}`,
    `Suggested type: ${vars.suggestedContentType || 'bullet_list'}`,
    `Previous slide title: ${vars.previousSlideTitle || '(none)'}`,
    `Next slide title: ${vars.nextSlideTitle || '(none)'}`,
    '',
    'Output JSON schema (fill relevant slots; unused fields null or empty):',
    JSON.stringify(
      {
        title: '...',
        subtitle: null,
        body: null,
        bullets: ['...'],
        stats: [{ label: '...', value: '...' }],
        quote: null,
        chart: {
          type: 'bar',
          labels: [],
          series: [],
          isIllustrative: true,
        },
        comparison: { left: {}, right: {} },
        timeline: [{ label: '...', detail: '...' }],
        notes: '...',
        pathBSpec: null,
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
  resolveCaps,
};
