function buildSystem() {
  return [
    'You are selecting the visual for a single presentation slide with pre-placed shape cards and optional text overlay.',
    'Output a JSON image brief — describe a concrete, literal visual, not an abstract theme.',
    '',
    'Rules:',
    '- Extract 1-3 CONCRETE nouns/entities from the slide content —',
    '  never abstract concepts like "growth" or "success" alone.',
    '- Do not describe layout chrome (borders, cards, circles) — shapes are rendered by the layout engine; describe the photo subject only.',
    '- For side-panel hero images: single focal subject, uncluttered background, works in rectangular cover crop.',
    '- When overlay slide: prefer darker overall exposure, soft vignette, or clear negative space for headline zone.',
    '- When DEVICE_IMAGE or device mockup slot: describe flat UI screenshot content only — no phone, laptop, tablet, or device hardware (layout renders the frame).',
    '- When exposure_hint is dark: image should support light overlay text.',
    '- Avoid cliche stock tropes: handshakes, lightbulbs, people',
    '  pointing at whiteboards, puzzle pieces, rocket ships.',
    '- Prefer specificity: "server rack in a dim data center" beats',
    '  "technology background."',
    '- Executive presentation quality — cinematic but professional, not stock cliché.',
    '- Flag image_type as diagram/chart (not photo) when the slide',
    '  needs to convey actual information or a relationship.',
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

  return [
    `Slide title: ${vars.slideTitle || ''}`,
    vars.layoutId ? `Layout id: ${vars.layoutId}` : '',
    vars.hasImageOverlay || vars.layoutContext?.hasImageOverlay
      ? 'Overlay slide: prefer darker exposure or natural vignette so white overlay text stays readable.'
      : '',
    vars.layoutContext?.hasTextOverImageRisk && !vars.hasImageOverlay
      ? 'Hero/split image slide: if the photo is dark, set exposure_hint to "dark" so the renderer can apply a scrim and light text.'
      : '',
    /device_/i.test(String(vars.layoutId || ''))
      ? 'Device mockup layout: describe UI screenshot content only — no phone/laptop/tablet bezel in the image.'
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
    'Output schema:',
    JSON.stringify(
      {
        subject: '...',
        image_type: 'photo|illustration|diagram|chart|icon',
        composition: '...',
        search_query: '...',
        negative_terms: [],
        alt_text: '...',
        exposure_hint: 'dark|balanced|light',
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
};
