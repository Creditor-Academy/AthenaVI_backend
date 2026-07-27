function buildSystem() {
  return [
    'Classify this slide into exactly one content_type.',
    'Also set visual_need: none|photo|illustration|icon|chart|diagram_template|path_b.',
    'Prefer Path A templates (visual_need != path_b) whenever content fits an existing layout.',
    'Use path_b only for bespoke multi-panel architecture/ERD/process infographics that cannot be templated.',
    'Return JSON only.',
  ].join(' ');
}

/**
 * @param {{
 *   slideContent?: object|string,
 *   suggestedContentType?: string,
 *   title?: string,
 * }} vars
 */
function buildUser(vars = {}) {
  const content =
    typeof vars.slideContent === 'string'
      ? vars.slideContent
      : JSON.stringify(vars.slideContent || {}, null, 2);

  return [
    `Suggested type (from outline, may override): ${vars.suggestedContentType || '(none)'}`,
    `Title: ${vars.title || ''}`,
    '',
    'Slide content JSON:',
    content,
    '',
    'content_type must be one of:',
    'title|agenda|bullet_list|comparison|stat|quote|image+text|timeline|team|chart|closing|section_divider',
    '',
    'Output JSON schema:',
    JSON.stringify(
      {
        content_type: 'comparison',
        visual_need: 'none',
        reason: 'two-column comparison fits template',
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
