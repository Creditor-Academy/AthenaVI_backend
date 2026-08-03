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
    'Enforce hard density limits and any slide intent / generation hints provided.',
    'Prefer short bullets over paragraphs. Titles must fit the stated max lines/words.',
    'Always include speaker notes in "notes".',
    'If the slide needs a bespoke multi-panel diagram, fill pathBSpec with exact panel titles, labels, and legend — copy is decided here; the image model only typesets later.',
    'Return JSON only.',
  ].join(' ');
}

/**
 * @param {object} vars
 */
function buildUser(vars = {}) {
  const density = vars.density || 'balanced';
  const caps = resolveCaps(density);
  const hints = vars.generationHints && typeof vars.generationHints === 'object' ? vars.generationHints : null;
  const slotLines = Array.isArray(vars.slotConstraints)
    ? vars.slotConstraints
        .map((s) => {
          const bits = [`${s.id}${s.role ? ` (${s.role})` : ''}`];
          if (s.max_lines) bits.push(`max ${s.max_lines} lines`);
          if (s.max_words) bits.push(`max ${s.max_words} words`);
          if (s.fontHint) bits.push(s.fontHint);
          return `- ${bits.join(', ')}`;
        })
        .join('\n')
    : '';

  const hintLines = [];
  if (hints) {
    if (hints.maxTitleWords) hintLines.push(`Max title words: ${hints.maxTitleWords}`);
    if (hints.maxBodyWords) hintLines.push(`Max body words: ${hints.maxBodyWords}`);
    if (hints.maxLines) hintLines.push(`Max lines: ${hints.maxLines}`);
    if (hints.itemCountMin || hints.itemCountMax) {
      hintLines.push(
        `Item count: ${hints.itemCountMin || 1}-${hints.itemCountMax || hints.itemCountMin || 7}`
      );
    }
    for (const key of [
      'titleLength',
      'subtitleLength',
      'bodyLength',
      'itemCount',
      'itemLength',
      'statFormat',
      'labelLength',
      'calloutLength',
      'titleTone',
      'ctaFormat',
      'imagePromptStyle',
      'parallelStructure',
      'pointCount',
      'pointLength',
      'bioLength',
      'nameFormat',
      'chartDataStyle',
      'sourceNote',
    ]) {
      if (hints[key]) hintLines.push(`${key}: ${hints[key]}`);
    }
    const avoid = hints.avoidClichés || hints.avoidCliches;
    if (Array.isArray(avoid) && avoid.length) {
      hintLines.push(`Avoid clichés: ${avoid.join(', ')}`);
    }
  }

  return [
    `Deck title: ${vars.deckTitle || ''}`,
    `Theme tone: ${vars.themeTone || 'professional'}`,
    `Density: ${density}`,
    `Locale: ${vars.locale || 'en'}`,
    `Max bullets: ${caps.maxBullets} | Max words body: ${hints?.maxBodyWords || caps.maxWordsBody} | Max title lines: ${caps.maxTitleLines}`,
    `Slide order: ${vars.slideOrder || 1}/${vars.slideTotal || 1}`,
    `Title: ${vars.title || ''}`,
    `Summary: ${vars.summary || ''}`,
    `Suggested type: ${vars.suggestedContentType || 'bullet_list'}`,
    vars.intent ? `Slide intent (follow closely): ${vars.intent}` : '',
    `Previous slide title: ${vars.previousSlideTitle || '(none)'}`,
    `Next slide title: ${vars.nextSlideTitle || '(none)'}`,
    vars.wizardBrief ? `\nWizard brief (honor voice, audience, purpose, narrative):\n${vars.wizardBrief}` : '',
    hintLines.length ? `\nGeneration hints:\n${hintLines.join('\n')}` : '',
    slotLines ? `\nLayout slot constraints (fit the visual container):\n${slotLines}` : '',
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
  ]
    .filter((line) => line !== '')
    .join('\n');
}

module.exports = {
  buildSystem,
  buildUser,
  DENSITY_CAPS,
  resolveCaps,
};
