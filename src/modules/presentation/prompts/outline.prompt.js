const DENSITY_CAPS = {
  concise: { maxBullets: 3, maxWordsBody: 40, maxTitleLines: 1 },
  balanced: { maxBullets: 5, maxWordsBody: 60, maxTitleLines: 2 },
  detailed: { maxBullets: 7, maxWordsBody: 100, maxTitleLines: 2 },
};

function buildSystem() {
  return [
    'You are a presentation strategist writing a pitch-deck blueprint.',
    'Each slide is a spec: headline, tagline, argument, labeled beats, unique visual, purpose, content intent, content type hints, and visual intent.',
    'Write real copy the generator will place into slots — not a topic list.',
    'Do not select a final layout for normal slides. Focus on what each slide should communicate.',
    'Do not invent charts, funnels, or device mockups unless the source is quantitative or about an app/product UI.',
    'Invent a concise presentation title from the source meaning — not a truncated copy of the prompt.',
    'Return JSON only matching the schema.',
  ].join(' ');
}

function buildPackEnrichSystem() {
  return [
    'You enrich a fixed deck-pack outline with original headlines, taglines, beats, and visuals.',
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
    imageType = '',
    imageStyle = '',
    imageStyleFilter = '',
    themeAppearance = '',
    layoutDigest = [],
    optionalOutline = '',
  } = vars;

  const digestLines = Array.isArray(layoutDigest) && layoutDigest.length
    ? layoutDigest
        .map(
          (row) =>
            `- ${row.layoutId} [${row.contentType}] heading:${row.hasHeadingSlot ? 'yes' : 'no'} images:${row.imageSlotCount} families:${(row.families || []).join('|')} — ${row.name || row.layoutId}`
        )
        .join('\n')
    : '(no catalog provided — still return suggestedContentType)';

  return [
    voiceAndTone ? `Voice & tone: ${voiceAndTone} (this affects layout vibe AND wording)` : null,
    audience ? `Audience: ${audience}` : `Audience/use case: ${audience || 'inferred from source'}`,
    purpose ? `Purpose: ${purpose}` : null,
    `Locale: ${locale}`,
    `Slide count: return EXACTLY ${slideCount} slides`,
    `Density: ${density} — concise/minimal = one text block, never two_para/three_para/four_para; detailed/extensive may use multi-para only when the slide has that many distinct points`,
    imageType ? `Image type: ${imageType}` : null,
    imageStyle ? `Image style: ${imageStyle}` : null,
    imageStyleFilter && imageStyleFilter !== 'Suggested' ? `Image filter: ${imageStyleFilter}` : null,
    themeAppearance ? `Theme appearance: ${themeAppearance} (dark → overlay/full-bleed; light → cards/solid surfaces)` : null,
    `Chart density budget: at most ${
      Number(slideCount) <= 10 ? 2 : Number(slideCount) <= 16 ? 3 : 4
    } chart slides for this ${slideCount}-slide deck (≤10 → 2; ≤16 → 3; else 4). Prefer image+text / gallery / comparison for brand storytelling; reserve chart only for true quantitative proof.`,
    '',
    'Source:',
    String(sourceText),
    optionalOutline ? `\nUser-provided outline (keep these topics; write full spec):\n${optionalOutline}` : null,
    '',
    'Allowed layout catalog context (for capability awareness only — do not choose final layouts for unlocked slides):',
    digestLines,
    '',
    'Narrative job map (describe intent, not layout ids):',
    '- Cover / brand name: strong title + tagline + visual atmosphere',
    '- Big idea / split: concise argument + supporting visual',
    '- Story / named moments: 2-4 distinct points with labels',
    '- Vision / atmosphere: emotional positioning and brand feel',
    '- Mission / beliefs: clear principle blocks',
    '- Audience / personas: distinct audience segments',
    '- Positioning: explicit comparison dimensions',
    '- Journey: sequence of stages and progression',
    '- Closing: clear wrap-up and next step',
    '',
    'Rules:',
    '- Strong narrative: title → optional agenda → one idea per body slide → closing',
    '- Slide 1 MUST be contentType title. Headline = brand or deck name from source. Subtitle = tagline. layoutId MUST be a title layout with heading:yes. Never large_image_v1.',
    '- Honor slide count, but prefer one story beat per slide (concept, vision, mission, audience…) rather than stuffing two arguments into one two-column slide.',
    '- title: headline that will appear on the slide (≤ 8 words)',
    '- subtitle: tagline / kicker (1 line)',
    '- summary: 1–3 sentences of argument (this is the body, not a 25-word topic blurb)',
    '- beats[]: short labeled points (Wake Slowly / Brew Better / personas / menu items) that map to bullets or columns',
    '- visual: one-line photo direction UNIQUE to this slide (establishing café vs people vs landscape vs food). Do not repeat the same product close-up.',
    '- Include purpose and contentIntent per slide',
    '- Include contentType[] hints and visualIntent[] hints for downstream layout selection',
    '- layoutId is optional and advisory unless layoutLocked=true',
    '- layoutLocked should be true only when user explicitly requests a fixed layout',
    '- imageType none → text-only / no image slots',
    '- watercolor/gouache/modern-art → include at least one gallery layout in decks of 5+',
    '- infographic/flat-line/isometric → include at least one diagram or icon-grid layout in decks of 5+',
    '- photo/scene/cinematic → at most one multi-image gallery',
    '- Use chart/device_frames only when the source is quantitative or about an app/product UI',
    '- Chart density: N≤10 slides → max 2 charts; N≤16 → max 3; else max 4. Do not stack three chart slides in a short deck.',
    '- Deck title: concise natural title (3–10 words). Do NOT paste the prompt.',
    '- suggestedContentType should align with expected content structure',
    '- visual_need: none|photo|illustration|chart — none when the layout has no image slots',
    '',
    'Output JSON schema:',
    JSON.stringify(
      {
        title: 'Mist & Mug',
        slides: [
          {
            order: 1,
            title: 'MIST & MUG',
            subtitle: 'Coffee above the ordinary.',
            summary: 'A hill café for guests who want slow mornings above the valley.',
            beats: ['Brand name on the cover', 'Tagline under the name'],
            visual: 'Wide café terrace facing misty mountains, space for type on the left',
            purpose: 'cover',
            contentIntent: 'Introduce the brand and atmosphere with a clean opening statement.',
            contentType: ['title', 'subtitle', 'image'],
            visualIntent: ['brand-led', 'premium', 'warm'],
            suggestedContentType: 'title',
            visual_need: 'photo',
            layoutId: null,
            layoutLocked: false,
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
    '- Provide title, subtitle, summary, beats[], and visual per slide aligned with pack intent and user source.',
    '- Slide 1: brand name + tagline from source when present.',
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
          subtitle: 'Tagline or kicker',
          summary: 'Fresh slide argument in 1–3 sentences.',
          beats: ['Labeled point one', 'Labeled point two'],
          visual: 'Unique photo direction for this slide',
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
