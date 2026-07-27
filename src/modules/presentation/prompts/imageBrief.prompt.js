function buildSystem() {
  return [
    'You are selecting the visual for a single presentation slide.',
    'Output a JSON image brief - describe a concrete, literal visual,',
    'not an abstract theme.',
    '',
    'Rules:',
    '- Extract 1-3 CONCRETE nouns/entities from the slide content -',
    '  never abstract concepts like "growth" or "success" alone.',
    '- Avoid cliche stock tropes: handshakes, lightbulbs, people',
    '  pointing at whiteboards, puzzle pieces, rocket ships.',
    '- Prefer specificity: "server rack in a dim data center" beats',
    '  "technology background."',
    '- Flag image_type as diagram/chart (not photo) when the slide',
    '  needs to convey actual information or a relationship.',
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
 * }} vars
 */
function buildUser(vars = {}) {
  const content =
    typeof vars.slideContent === 'string'
      ? vars.slideContent
      : JSON.stringify(vars.slideContent || {}, null, 2);

  return [
    `Slide title: ${vars.slideTitle || ''}`,
    `Theme image_style (for downstream Path A lock, do not invent layout): ${vars.themeImageStyle || ''}`,
    `Theme color_treatment: ${vars.themeColorTreatment || ''}`,
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
      },
      null,
      2
    ),
  ].join('\n');
}

module.exports = {
  buildSystem,
  buildUser,
};
