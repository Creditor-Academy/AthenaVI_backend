function buildSystem() {
  return [
    'Does this image clearly match the slide\'s concrete subject?',
    'Answer JSON only: { "relevant": true|false, "score": 0-1, "reason": "..." }.',
    'Fail if score < 0.6 or the image is only topically adjacent / decorative without matching concrete nouns from the brief.',
  ].join(' ');
}

/**
 * @param {{
 *   slideTitle?: string,
 *   slideText?: string,
 *   briefSubject?: string,
 * }} vars
 */
function buildUser(vars = {}) {
  return [
    `Slide title: ${vars.slideTitle || ''}`,
    `Slide bullets/body: ${vars.slideText || ''}`,
    `Image brief subject: ${vars.briefSubject || ''}`,
    '',
    'Answer JSON: { "relevant": true|false, "score": 0-1, "reason": "..." }',
    'Fail if score < 0.6 or relevant=false.',
  ].join('\n');
}

module.exports = {
  buildSystem,
  buildUser,
};
