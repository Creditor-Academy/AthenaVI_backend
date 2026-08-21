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

function layoutSpecificRules(layoutId = '', slideOrder = 1, suggestedType = '') {
  const id = String(layoutId || '').toLowerCase();
  const type = String(suggestedType || '').toLowerCase();
  const lines = [];

  if (slideOrder === 1 || type === 'title') {
    lines.push(
      'Title slide: REQUIRED titleRuns (2-3 segments, accent on final line). Set shapeDecisions.HERO_IMAGE with behind:"card" or mask:"rect" when hero image present.'
    );
  }

  if (type === 'closing' || /closing|cta/.test(id)) {
    lines.push(
      'Closing slide: REQUIRED subtitle (1 line), cta (short action phrase), and contact when layout has CONTACT slot. CTA must be topic-specific (e.g. "Explore the archive", "Start learning"). NEVER use generic "Book a demo" unless the deck is explicitly a sales/demo pitch.'
    );
  }

  if (type === 'chart' || /chart/.test(id)) {
    lines.push(
      'Chart slide: analyze the data story FIRST, then pick chart.type and fill data. Never duplicate the same chart twice on one slide.'
    );
    lines.push(
      'Story → type: time-series labels or trend narrative → "line"; values that sum to ~100% or part-of-whole share → "donut"/"pie"; ranked categories or absolute volumes → "bar". Only use chart2/charts[] when comparing two distinct metrics.'
    );
    lines.push(
      'REQUIRED chart.labels (4-6 topic-specific labels) and chart.series[{ name, values }] with numeric values matching labels length. Set isIllustrative:true. Add body (3-4 lines) only when the layout has a BODY slot and insight adds value.'
    );
  }

  if (/chart_with_description|chart_donut_context|donut|chart_split/.test(id)) {
    lines.push(
      'Chart + paragraph layout: fill body with a 3-4 line insight explaining the chart takeaway — do not repeat the title or raw numbers verbatim.'
    );
  }

  if (/chart_two|chart_three|chart_dual/.test(id)) {
    lines.push(
      'Dual/triple chart layout: ONLY when comparing two or three distinct datasets. Provide chart + chart2 (or charts[]) with different labels/metrics — never the same data in both charts.'
    );
  }

  if (type === 'timeline' || /timeline/.test(id)) {
    lines.push(
      'Timeline slide: REQUIRED timeline[] (or milestones[]) with at least 2 entries. Each entry MUST have label (year/phase) AND detail (1-2 lines describing the milestone). Never output year-only entries without detail.'
    );
  }

  if (/bullet_split_image|split.*bullet/i.test(id)) {
    lines.push(
      'Split bullet slide: bullets must use "**Topic:** description" format (bold topic + colon + detail). 4-6 points max.'
    );
  }

  if (/closing_thank_you_fullbleed|fullbleed.*thank/i.test(id)) {
    lines.push(
      'Full-bleed thank-you slide: REQUIRED quote (≤25 words, attribution optional), titleRuns for "Thank you" bottom-left, shapeDecisions.__overlay__.enabled true.'
    );
  }

  if (/three_cards|four_images|cards_image|grid_.*image|device|timeline_milestones_image/.test(id)) {
    lines.push(
      'Multi-image layout: REQUIRED imagePrompts object with a UNIQUE concrete visual subject per image slot (IMAGE_1, IMAGE_2, COL_1_IMAGE, etc.). Each prompt must describe ONE isolated subject matching columns[n].title + body — explicitly forbid collages, triptychs, and multi-panel images.'
    );
    lines.push(
      'Multi-card/gallery layout: REQUIRED columns[] with one entry per image — each { title, body } must have a DISTINCT title (≤4 words) naming a single visual subject that matches that card’s text (e.g. tins vs robes vs candles). Titles map to IMAGE_n / COL_n_IMAGE captions.'
    );
  }

  if (/^title_hero_|^title_fullbleed|^title_image_logo/.test(id)) {
    lines.push(
      'Title hero layout: concise title (≤8 words) + short subtitle/tagline. One strong hero imagePrompt from the overall deck prompt + slide summary (not title alone) — no collage. Shaped/fade/full-bleed variants use the same copy rules.'
    );
  }

  if (/section_with_image|two_para_right|three_para_image|section_left_image|para_split/.test(id)) {
    lines.push(
      'Split text|image layout: text on one half, hero photo on the other. Only title slides get an automatic edge fade on the photo — keep copy concise on the text side.'
    );
  }

  if (/two_para|three_para|four_para|intro_four_para|intro_three_para/.test(id)) {
    lines.push(
      'Multi-paragraph layout: REQUIRED columns[] with distinct { title, body } per paragraph/column. Titles are subheadings (≤4 words); bodies are 1-3 lines each.'
    );
    lines.push(
      'Four-paragraph + image layouts (four_para_image_v1): fill columns[0..3] — each entry maps to BULLET_1..BULLET_4. Never leave paragraph slots empty.'
    );
  }

  if (/diagram_|swot|matrix|funnel|process_step/.test(id)) {
    lines.push(
      'Diagram layout: REQUIRED diagram.cells[] (or quadrants[]) with one { title, body } entry per quadrant/step/funnel tier. Each body must be 1-3 original lines about the slide topic. Replace ALL template placeholder wording — never echo "Two to three lines explaining this section."'
    );
  }

  return lines.length ? `\n${lines.join('\n')}` : '';
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
    `Title (required seed — use as the slide headline / brand name): ${vars.title || ''}`,
    vars.subtitle ? `Subtitle / tagline (required seed): ${vars.subtitle}` : '',
    `Summary (this is the argument to place in body slots, not a topic label): ${vars.summary || ''}`,
    Array.isArray(vars.beats) && vars.beats.length
      ? `Beats (map into columns[] / bullets[] to match slot count):\n${vars.beats
          .map((b, i) => {
            if (typeof b === 'string') return `- ${i + 1}. ${b}`;
            const label = b.label || b.title || '';
            const text = b.text || b.body || '';
            return `- ${i + 1}. ${label}${text && text !== label ? `: ${text}` : ''}`;
          })
          .join('\n')}`
      : '',
    vars.visual ? `Visual direction for this slide only: ${vars.visual}` : '',
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
    layoutSpecificRules(vars.layoutId, vars.slideOrder, vars.suggestedContentType),
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
    '- Fill every text slot from the required seed (title, subtitle, beats). Do NOT invent a 25-word recap and leave heading/body empty.',
    '- Title slides: title = brand or deck name, subtitle = tagline, titleRuns required (2–3 segments).',
    '- Replace any template placeholder wording with original content from the brief.',
    '- Do NOT echo placeholders like "Your Title", "Your subtitle", or "Lorem ipsum".',
    '- Match slot constraints exactly; prefer headline + 3 bullets over long paragraphs unless BODY allows more.',
    '- title → title+subtitle only; closing → headline + CTA + contact; quote → one quote ≤25 words; stat → 1–6 metrics max; chart → fill chart.labels + chart.series[{ name, values }] with 4-6 numeric data points; table → fill table.headers + table.rows; pricing → fill plans[] with label, price, items[]; team → fill members[] with name, role, email; agenda → fill agenda.columns[] with heading + items[]; grid metrics → fill columns[] with { title, body } plus stats[] with { value, label }; contact slides → fill contact { address, phone, email } + title.',
    '- Multi-column/card/para layouts: fill columns[] with DISTINCT title per column (never repeat titles; CARD_n_TITLE must never equal slide title/HEADING). Map CARD_n_TITLE/BODY_n and BODY_n/BULLET_n slots from columns[n-1].',
    '- Multi-image layouts: fill imagePrompts { SLOT_ID: "unique visual description" } — one isolated single-subject prompt per IMAGE_n / COL_n_IMAGE / DEVICE_IMAGE_n slot matching that column’s title+body (no collages or triptychs).',
    '- Chart slides: analyze the data story first — line for trends, donut/pie only for true part-of-whole (~100% total), bar for rankings; dual-chart only for two distinct metrics. Never duplicate identical chart data.',
    '- Split bullet slides: bullets as "**Topic:** description" (bold topic prefix) or { topic, text } objects.',
    '- When layout has multiple columns/cards, use parallel grammar across bullets/items.',
    '- shapeDecisions: for each image/CTA slot, set behind ("none"|"card"|"pill"|"surface") and optional mask ("none"|"rect"). For multi-column/timeline/card layouts set behind:"card" on each column text group. Use "none" only for clean/minimal slides.',
    '- Never overlap text on text; only overlay text on photos when __overlay__ scrim is enabled.',
    '- titleRuns: on title/quote/closing/statement slides, split the headline into 2-3 styled segments in one block — lead lines use textOnImage or text, final line uses accent colorRole with fontWeight 700. Do NOT set fontFamily on runs; the deck heading font applies. Set title to the full concatenated string too.',
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
        bullets: ['**Topic one:** Supporting detail.', '**Topic two:** Supporting detail.'],
        stats: [{ label: '...', value: '...' }],
        columns: [
          { title: 'Distinct card title A', body: 'Body for column A.' },
          { title: 'Distinct card title B', body: 'Body for column B.' },
        ],
        imagePrompts: {
          IMAGE_1: 'Concrete unique visual for first card',
          IMAGE_2: 'Different concrete visual for second card',
        },
        quote: null,
        chart: {
          type: 'bar',
          labels: ['2022', '2023', '2024', '2025'],
          series: [{ name: 'Growth', values: [12, 19, 24, 31] }],
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
