function buildSystem() {
  return [
    'You are selecting the visual for a single presentation slide with pre-placed shape cards and optional text overlay.',
    'Output a JSON image brief — describe a concrete, literal visual, not an abstract theme.',
    '',
    'Rules:',
    '- Prefer the slide visual direction when provided; it is unique to this slide.',
    '- Do not repeat the same product close-up (mug, cup, logo object) across slides.',
    '- Title / cover / hero / BACKGROUND_IMAGE: establish from the overall deck prompt + slide summary,',
    '  not the slide title alone. Prefer establishing interior, landscape, or scene with negative space for type.',
    '- Story slides: people or interior, not a product hero.',
    '- Vision / atmosphere: landscape or weather, not a tabletop still life.',
    '- Menu / product: food or cup hero at most once in the deck.',
    '- Extract 1-3 CONCRETE nouns/entities from the visual + slide content —',
    '  never abstract concepts like "growth" or "success" alone.',
    '- Do not describe layout chrome (borders, cards, circles) — shapes are rendered by the layout engine; describe the photo subject only.',
    '- For side-panel hero images: single focal subject, uncluttered background, works in rectangular cover crop.',
    '- When overlay slide: prefer darker overall exposure, soft vignette, or clear negative space for headline zone.',
    '- When DEVICE_IMAGE or device mockup slot: describe flat UI screenshot content only — no phone, laptop, tablet, or device hardware (layout renders the frame).',
    '- When the layout already includes a chart element: never describe a chart, graph, dashboard, axes, or data viz photo;',
    '  photograph a related real-world subject that supports the chart story instead.',
    '- When exposure_hint is dark: image should support light overlay text.',
    '- Avoid cliche stock tropes: handshakes, lightbulbs, people',
    '  pointing at whiteboards, puzzle pieces, rocket ships.',
    '- Prefer specificity: "server rack in a dim data center" beats',
    '  "technology background."',
    '- Executive presentation quality — cinematic but professional, not stock cliché.',
    '- Flag image_type as diagram/chart (not photo) only when the slide has NO rendered chart element',
    '  and truly needs an information graphic in the photo.',
    '- When an Author image brief is provided, treat it as the primary',
    '  subject/composition guidance; refine for concreteness but do not',
    '  ignore it.',
    '',
    'Return JSON only matching the schema.',
  ].join('\n');
}

/**
 * @param {{
 *   slideTitle?: string,
 *   slideContent?: object|string,
 *   slideSummary?: string,
 *   deckSummary?: string,
 *   themeImageStyle?: string,
 *   themeColorTreatment?: string,
 *   wizardBrief?: string,
 *   authorImagePrompt?: string,
 * }} vars
 */
function buildUser(vars = {}) {
  const content =
    typeof vars.slideContent === 'string'
      ? vars.slideContent
      : JSON.stringify(vars.slideContent || {}, null, 2);

  const author =
    typeof vars.authorImagePrompt === 'string' ? vars.authorImagePrompt.trim() : '';

  const slideSummary = String(
    vars.slideSummary ||
      (typeof vars.slideContent === 'object'
        ? vars.slideContent?.summary || vars.slideContent?.body || ''
        : '') ||
      ''
  ).trim();

  const deckSummary = String(vars.deckSummary || vars.wizardBrief || '').trim();
  const hasChart =
    vars.hasChartSlot === true || vars.layoutContext?.hasChartSlot === true;

  return [
    `Slide title: ${vars.slideTitle || ''}`,
    slideSummary ? `Slide summary (prefer over title alone): ${slideSummary}` : '',
    deckSummary
      ? `Overall deck prompt / narrative (title & hero images must reflect this): ${deckSummary.slice(0, 600)}`
      : '',
    vars.suggestedContentType ? `Slide job / content type: ${vars.suggestedContentType}` : '',
    vars.layoutId ? `Layout id: ${vars.layoutId}` : '',
    vars.visual ? `Blueprint visual (primary subject — do not ignore): ${vars.visual}` : '',
    Array.isArray(vars.previousVisuals) && vars.previousVisuals.length
      ? `Already used in this deck (do not repeat):\n${vars.previousVisuals.map((v) => `- ${v}`).join('\n')}`
      : '',
    vars.hasImageOverlay || vars.layoutContext?.hasImageOverlay
      ? 'Overlay slide: prefer darker exposure or natural vignette so white overlay text stays readable.'
      : '',
    vars.layoutContext?.hasTextOverImageRisk && !vars.hasImageOverlay
      ? 'Hero/split image slide: if the photo is dark, set exposure_hint to "dark" so the renderer can apply a scrim and light text.'
      : '',
    /device_/i.test(String(vars.layoutId || ''))
      ? 'Device mockup layout: describe UI screenshot content only — no phone/laptop/tablet bezel in the image.'
      : '',
    hasChart
      ? 'IMPORTANT: This layout already renders a chart. Describe a supporting photograph only — forbid charts, graphs, dashboards, axes, pie/bar/line chart photos, and spreadsheet screens. Set image_type to "photo".'
      : '',
    `Theme image_style (for downstream Path A lock, do not invent layout): ${vars.themeImageStyle || ''}`,
    `Theme color_treatment: ${vars.themeColorTreatment || ''}`,
    author
      ? `Author image brief (prefer — use as primary subject/composition):\n${author}`
      : '',
    vars.wizardBrief ? `Wizard brief:\n${vars.wizardBrief}` : '',
    '',
    'Slide content:',
    content,
    '',
    'Return JSON only.',
  ]
    .filter(Boolean)
    .join('\n');
}

module.exports = {
  buildSystem,
  buildUser,
};
