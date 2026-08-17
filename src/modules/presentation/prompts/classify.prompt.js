function buildSystem() {
  return [
    'Classify this slide into exactly one content_type.',
    'Also set visual_need: none|photo|illustration|icon|chart|diagram_template|path_b.',
    'Prefer Path A templates (visual_need != path_b) whenever content fits an existing layout.',
    'Use path_b only for bespoke multi-panel architecture/ERD/process infographics that cannot be templated.',
    'DEFAULT: prefer visual_need "photo" or "illustration" for nearly every content slide so the deck has real imagery.',
    'Use visual_need "none" only for pure section dividers with no figurative need.',
    'Reserve content_type "title" for slide 1 only. Chapter/section headers → section_divider.',
    'section_divider is ONLY for chapter breaks with no bullets and no multi-point body — title plus optional one-line subtitle.',
    'If the slide has 2+ bullets or a multi-point body, use bullet_list even when the title contains "Section", chapter numbers, or act labels.',
    'Prefer the suggestedContentType from the outline when it conflicts with a chapter-style title but the slide has bullet content.',
    'Reserve content_type "closing" for the final slide only.',
    'Use visual_need "chart" only when the slide is primarily a data chart (content_type chart).',
    'Return JSON only.',
  ].join(' ');
}

/**
 * @param {{
 *   slideContent?: object|string,
 *   suggestedContentType?: string,
 *   title?: string,
 *   preferVisuals?: boolean,
 * }} vars
 */
function buildUser(vars = {}) {
  const content =
    typeof vars.slideContent === 'string'
      ? vars.slideContent
      : JSON.stringify(vars.slideContent || {}, null, 2);

  const preferVisuals = vars.preferVisuals !== false;

  return [
    `Suggested type (from outline, may override): ${vars.suggestedContentType || '(none)'}`,
    `Title: ${vars.title || ''}`,
    `Prefer visuals on this deck: ${preferVisuals ? 'yes — avoid visual_need none unless truly text-only' : 'no'}`,
    vars.wizardBrief ? `Wizard brief:\n${vars.wizardBrief}` : '',
    '',
    'Slide content JSON:',
    content,
    '',
    'content_type must be one of:',
    'title|agenda|bullet_list|comparison|stat|quote|image+text|timeline|team|chart|closing|section_divider|grid|pricing|device_frames|diagram',
    '',
    'Pick grid for multi-image galleries or bento card layouts.',
    'Pick device_frames for app/website/product UI mockups.',
    'Pick diagram (especially process steps) for numbered workflows, SWOT, funnel, matrix.',
    'Pick chart when the slide is primarily a data visualization.',
    '',
    'Output JSON schema:',
    JSON.stringify(
      {
        content_type: preferVisuals ? 'image+text' : 'bullet_list',
        visual_need: preferVisuals ? 'photo' : 'none',
        reason: preferVisuals
          ? 'executive slide benefits from a supporting photograph'
          : 'text-focused slide',
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
