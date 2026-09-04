const DENSITY_CAPS = {
  concise: {
    maxBullets: 3,
    maxWordsBody: 40,
    maxTitleLines: 1,
    minTitleWords: 2,
    maxTitleWords: 6,
  },
  balanced: {
    maxBullets: 5,
    maxWordsBody: 60,
    maxTitleLines: 2,
    minTitleWords: 4,
    maxTitleWords: 10,
  },
  detailed: {
    maxBullets: 7,
    maxWordsBody: 100,
    maxTitleLines: 2,
    minTitleWords: 5,
    maxTitleWords: 12,
  },
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
    density === 'detailed'
      ? 'Title length (detailed): each slide title MUST be 5–12 words (full headline). Never 1–2 word stubs like "Market Reality".'
      : density === 'concise'
        ? 'Title length (concise): each slide title 2–6 words, one line.'
        : 'Title length (balanced): each slide title 4–10 words; avoid 1–2 word stubs except brand cover names.',
    density === 'detailed'
      ? 'Detailed copy volume: each body slide summary MUST be 2–3 full sentences of argument. beats[] MUST include short detail (label + 1-line explanation), not bare labels. Prefer enough substance that a reader understands the point without the image alone.'
      : null,
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
    '- Cover / brand name (purpose: cover): spoken outcome promise as title (not a stub label) + tagline/kicker + visual atmosphere',
    '- Problem / friction (purpose: problem): early body slide — name the pain; beats[] = 2-4 concrete friction points (situational, not vague)',
    '- Big idea / split: concise argument + supporting visual',
    '- Story / named moments: 2-4 distinct points with labels',
    '- Vision / atmosphere: emotional positioning and brand feel',
    '- Mission / beliefs: clear principle blocks',
    '- Audience / personas: distinct audience segments',
    '- Positioning: explicit comparison dimensions',
    '- Journey: sequence of stages and progression',
    '- Closing (purpose: closing): wrap-up + specific offer CTA intent in summary/beats (verb + outcome; time/number when brief supports) — not "learn more"',
    '',
    'Rules:',
    '- Strong narrative: title → optional agenda → problem (when the brief has friction) → one idea per body slide → closing',
    '- Slide 1 MUST be contentType title. Headline = spoken brand promise or deck name from source (not "Overview"). Subtitle = tagline. layoutId MUST be a title layout with heading:yes. Never large_image_v1.',
    '- Honor slide count, but prefer one story beat per slide (concept, vision, mission, audience…) rather than stuffing two arguments into one two-column slide.',
    '- title: headline that will appear on the slide (honor density title-word guidance above; never default to 2-word stubs for detailed)',
    '- subtitle: tagline / UPPERCASE-style kicker (1 line)',
    density === 'detailed'
      ? '- summary (detailed): 2–3 sentences of real argument — never a one-line topic blurb'
      : '- summary: 1–3 sentences of argument (this is the body, not a 25-word topic blurb)',
    density === 'detailed'
      ? '- beats[] (detailed): labeled points WITH a short detail phrase each (map to bullets/columns); for purpose problem use concrete pains'
      : '- beats[]: short labeled points (Wake Slowly / Brew Better / personas / menu items) that map to bullets or columns; for purpose problem use concrete pains',
    '- visual: one-line photo direction UNIQUE to this slide (establishing café vs people vs landscape vs food). Do not repeat the same product close-up.',
    '- Include purpose and contentIntent per slide (use purpose values: cover, problem, closing, and other narrative jobs as fit)',
    '- Include contentType[] hints and visualIntent[] hints for downstream layout selection',
    '- layoutId is optional and advisory unless layoutLocked=true',
    '- layoutLocked should be true only when user explicitly requests a fixed layout',
    '- imageType none → text-only / no image slots',
    '- watercolor/gouache/modern-art → include at least one gallery layout in decks of 5+',
    '- infographic/flat-line/isometric → include at least one diagram or icon-grid layout in decks of 5+',
    '- photo/scene/cinematic → at most one multi-image gallery',
    '- Use chart only when the source is quantitative; use device_frames when the slide is about an app/product UI / phone-tablet mockups (never diagram for those)',
    '- Chart density: N≤10 slides → max 2 charts; N≤16 → max 3; else max 4. Do not stack three chart slides in a short deck.',
    '- Deck title: concise natural title (3–10 words). Do NOT paste the prompt.',
    '- suggestedContentType should align with expected content structure',
    '- How-it-works / N-step workflow / pipeline slides → suggestedContentType "diagram" for 2–4 steps; use "timeline" when there are 5+ numbered steps. Never grid or bullet_list for those',
    '- Product UI / app screens / device mockups → suggestedContentType "device_frames" (not diagram)',
    '- visual_need: none|photo|illustration|chart|diagram_template — none when the layout has no image slots; diagram_template for process/SWOT/funnel layouts',
    '- Do NOT use path_b in the outline; Path B is decided later only for architecture/ERD-style slides',
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
    density === 'detailed'
      ? 'Title length (detailed): 5–12 words per slide headline; no 1–2 word stubs.'
      : density === 'concise'
        ? 'Title length (concise): 2–6 words per slide headline.'
        : 'Title length (balanced): 4–10 words per slide headline.',
    density === 'detailed'
      ? 'Detailed: each summary 2–3 sentences; beats include short detail text, not labels alone.'
      : null,
    narrativeLines.length ? narrativeLines.join('\n') : null,
    '',
    'User source / prompt:',
    String(sourceText),
    '',
    'Rules:',
    '- Return exactly one slide entry per pack slide (same order values).',
    '- Provide title, subtitle, summary, beats[], and visual per slide aligned with pack intent and user source.',
    '- Slide 1: spoken brand promise or name + tagline from source when present (not stub labels).',
    '- If a pack slide is problem/friction: beats[] = concrete pains; if closing: summary/beats imply an offer-style CTA intent.',
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
