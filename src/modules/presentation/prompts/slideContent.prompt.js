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
    'You write slide copy for a polished slide renderer with fixed layout slots.',
    'Copy must be scannable at a glance — headline + bullets, not essay paragraphs.',
    'You also decide optional shape treatment per slot (card behind image, pill behind CTA, image mask) — shapes are NOT visible in the layout catalog; you choose at generation time.',
    'Fill content slots only. No layout coordinates or color hex values.',
    'Enforce hard density limits and any slide intent / generation hints provided.',
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
    vars.layoutContext?.hasImageOverlay || vars.layoutContext?.hasTextOverImageRisk
      ? '\nImage-heavy slide: text renders over a photo with an automatic dark scrim and light text. Keep titles ≤6 words; body ≤2 short lines. Set shapeDecisions.__overlay__.enabled to true.'
      : '',
    String(vars.layoutId || '').includes('grid_metrics_masonry')
      ? '\nGrid metrics layout (grid_metrics_masonry_v1): HEADING → title only (≤6 words). Fill columns[] with { title, body } for METRIC_TITLE_n / METRIC_BODY_n cards (1–2 short lines each). Fill stats[] with { value, label } for STAT_n_VALUE / STAT_n_LABEL. Do NOT put bullets or long body copy into metric or stat slots.'
      : '',
    vars.layoutId ? `Layout id: ${vars.layoutId}` : '',
    Array.isArray(vars.layoutContext?.shapeHints) && vars.layoutContext.shapeHints.length
      ? `\nShape hints (suggestions only — you decide in shapeDecisions):\n${vars.layoutContext.shapeHints
          .map(
            (h) =>
              `- ${h.pairsWithSlotId || h.slotId}: ${h.kind || 'shape'} → suggested ${h.suggestedBehind || 'none'}`
          )
          .join('\n')}`
      : '',
    slotLines ? `\nLayout slot constraints (fit the visual container):\n${slotLines}` : '',
    '',
    'Rules:',
    '- Replace any template placeholder wording with original content from the brief.',
    '- Do NOT echo placeholders like "Your Title", "Your subtitle", or "Lorem ipsum".',
    '- Match slot constraints exactly; prefer headline + 3 bullets over long paragraphs unless BODY allows more.',
    '- title → title+subtitle only; closing → headline + CTA + contact; quote → one quote ≤25 words; stat → 1–6 metrics max; chart → fill chart.labels + chart.series; table → fill table.headers + table.rows; pricing → fill plans[] with label, price, items[]; team → fill members[] with name, role, email; agenda → fill agenda.columns[] with heading + items[]; grid metrics → fill columns[] with { title, body } plus stats[] with { value, label }; contact slides → fill contact { address, phone, email } + title.',
    '- When layout has multiple columns/cards, use parallel grammar across bullets/items.',
    '- shapeDecisions: for each image/CTA slot, set behind ("none"|"card"|"pill"|"surface") and optional mask ("none"|"rect"). For multi-column/timeline/card layouts set behind:"card" on each column text group. Use "none" only for clean/minimal slides.',
    '- Never overlap text on text; only overlay text on photos when __overlay__ scrim is enabled.',
    '- titleRuns: on title/quote/closing/statement slides, split the headline into 2-3 styled segments in one block — e.g. lead lines use textOnImage or text, final line uses accent colorRole with fontWeight 700. Set title to the full concatenated string too.',
    '',
    'Output JSON schema (fill relevant slots; unused fields null or empty):',
    JSON.stringify(
      {
        title: '...',
        titleRuns: [
          { text: 'Lead line one.\n', colorRole: 'textOnImage' },
          { text: 'Accent closing line.', colorRole: 'accent', fontWeight: 700 },
        ],
        subtitle: null,
        body: null,
        bullets: ['...'],
        stats: [{ label: '...', value: '...' }],
        columns: [{ title: '...', body: '...' }],
        quote: null,
        chart: {
          type: 'bar',
          labels: [],
          series: [],
          isIllustrative: true,
        },
        table: {
          headers: ['Column A', 'Column B'],
          rows: [['Row 1', 'Value'], ['Row 2', 'Value']],
        },
        members: [{ name: '...', role: '...', email: '...' }],
        plans: [{ label: '...', price: '...', items: ['...'], highlighted: false }],
        contact: { address: '...', phone: '...', email: '...' },
        agenda: {
          columns: [{ heading: '...', items: ['...'] }],
        },
        comparison: {
          left: { title: 'Option A', body: '...', bullets: ['...'] },
          right: { title: 'Option B', body: '...', bullets: ['...'] },
        },
        pros: ['Advantage one', 'Advantage two'],
        cons: ['Risk one', 'Risk two'],
        timeline: [
          { label: '2020', detail: 'Key event summary' },
          { label: '2022', detail: 'Next milestone' },
        ],
        columns: [{ title: 'Card title', body: 'Card body' }],
        diagram: {
          type: 'swot',
          cells: [
            { title: 'Strengths', body: '...' },
            { title: 'Weaknesses', body: '...' },
          ],
        },
        notes: '...',
        pathBSpec: null,
        shapeDecisions: {
          HERO_IMAGE: { behind: 'none', mask: 'none', borderRadius: 10 },
          CTA: { behind: 'pill', mask: 'none' },
          __overlay__: { enabled: true, scrim: 0.45 },
        },
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
