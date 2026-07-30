const { styleSuffix } = require('../catalogs/styles');

const LAYOUT_HINTS = Object.freeze({
  process: 'process / step flow with numbered badges and thin arrows',
  comparison: 'side-by-side comparison panels',
  timeline: 'horizontal or vertical timeline with dated milestones',
  stats: 'KPI / stats cards with large readable numbers',
  hierarchy: 'hierarchy or org-style tree diagram',
  funnel: 'funnel stages from wide to narrow',
  custom: 'custom multi-panel infographic layout',
});

/**
 * Build an infographic image prompt (Path-B style typesetting).
 */
function buildInfographicPrompt({
  prompt,
  styleId,
  brandPalette,
  infographic = {},
} = {}) {
  const layout = infographic.layout || 'custom';
  const layoutHint = LAYOUT_HINTS[layout] || LAYOUT_HINTS.custom;
  const title = infographic.title || '';
  const sections = Array.isArray(infographic.sections) ? infographic.sections : [];
  const palette =
    Array.isArray(brandPalette) && brandPalette.length
      ? brandPalette.join(', ')
      : 'brand accent colors';

  const panelLines = sections.map((section, i) => {
    const sectionTitle = section.title || `Panel ${i + 1}`;
    const bullets = Array.isArray(section.bullets)
      ? section.bullets.join('; ')
      : section.content || '';
    return `Panel ${i + 1} ("${sectionTitle}"): ${bullets}`;
  });

  const n = panelLines.length || 1;
  const lines = [
    `Create a clean, professional infographic-style diagram (${layoutHint}), ${n} panel(s)`,
    `arranged clearly on a white or light background, [${palette}] accent colors used consistently.`,
  ];

  if (title) {
    lines.push(`Overall title: "${title}".`);
  }

  if (panelLines.length) {
    lines.push('', ...panelLines);
  } else if (prompt) {
    lines.push('', `Content brief: ${String(prompt).trim()}`);
  }

  lines.push(
    '',
    'Style: flat icons, rounded rectangle boxes, thin arrows connecting',
    'steps, numbered circular badges for sequence, consistent sans-serif',
    'typography, sharp readable text, no photorealistic elements.'
  );

  const suffix = styleSuffix(styleId);
  if (suffix) {
    lines.push('', suffix);
  }

  return lines.join('\n');
}

module.exports = {
  buildInfographicPrompt,
  LAYOUT_HINTS,
};
