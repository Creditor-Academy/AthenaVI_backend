const LAYOUT_HINTS = Object.freeze({
  process: 'process / step flow with numbered badges and thin arrows',
  comparison: 'side-by-side comparison panels with horizontally aligned row titles',
  timeline: 'horizontal or vertical timeline with dated milestones',
  stats: 'KPI / stats cards with very large readable numbers',
  hierarchy: 'hierarchy as stacked rounded rectangles with indent/color cues — not a morphing pyramid',
  funnel: 'funnel as stacked rounded rectangles wide-to-narrow via width — not a 3D funnel mesh',
  custom: 'custom multi-panel infographic layout',
});

const LOCKED_STYLE_IDS = new Set([
  'cinematic',
  'photoreal',
  'watercolor',
  '3d_render',
  'neon',
  'dark_moody',
]);

const ALLOWED_STYLE_IDS = new Set(['flat_illustration', 'corporate', 'minimal', 'playful']);

function layoutCraft(layout) {
  switch (layout) {
    case 'process':
      return [
        'PROCESS: stacked left-to-right flow rows connected by thin arrows that never loop.',
        'Optional right sidebar (KEY POINTS) only if the spec includes a sidebar region.',
        'Optional footer note/callout. Distinct cards with numbered circular badges.',
      ].join(' ');
    case 'comparison':
      return 'COMPARISON: two or more columns; corresponding row titles aligned on the same horizontal line.';
    case 'timeline':
      return 'TIMELINE: chronological order; years as four digits in quotes (e.g. "1950" not 150); one consistent connector line.';
    case 'stats':
      return 'STATS: equal-size cards in an explicit grid (e.g. 2x3). Very large bold numbers. Captions 3–5 words maximum.';
    case 'hierarchy':
      return 'HIERARCHY: stacked rounded rectangles with indent and discrete color steps. Do not draw a morphing pyramid or trapezoids.';
    case 'funnel':
      return 'FUNNEL: stacked rounded rectangles that get narrower downward via width cues. Metrics must decrease. No 3D funnel mesh.';
    default:
      return 'CUSTOM: clear modular grid; header, flow rows, optional sidebar, optional footer.';
  }
}

function quote(value) {
  return `"${String(value).replace(/"/g, "'")}"`;
}

function regionLines(plan) {
  const regions = Array.isArray(plan.regions) ? plan.regions : [];
  const lines = [];
  regions.forEach((region, ri) => {
    const type = region.type || 'flowRow';
    const title = region.title ? ` ${quote(region.title)}` : '';
    lines.push(`Region ${ri + 1} [${type}]${title}:`);
    const steps = Array.isArray(region.steps) ? region.steps : [];
    if (!steps.length && type === 'header') {
      lines.push('  Header only — title and subtitle, no extra copy.');
      return;
    }
    steps.forEach((step) => {
      const num = String(step.number || '').padStart(2, '0');
      const heading = step.heading || '';
      const body = step.body || '';
      const icon = step.icon ? `; icon: ${step.icon}` : '';
      lines.push(
        `  Badge ${num} + heading ${quote(`Step ${Number(num)}: ${heading}`)}${body ? `; body ${quote(body)}` : ''}${icon}`
      );
    });
  });
  return lines;
}

function exactTextBlock(plan) {
  const items = Array.isArray(plan?.exactText) ? plan.exactText : [];
  if (!items.length) return [];
  return ['', 'EXACT TEXT — render each string as-is, do not misspell, merge, omit, or invent:', ...items.map((t) => `- ${quote(t)}`)];
}

function fallbackPanelLines(infographic = {}, prompt = '') {
  const title = infographic.title || '';
  const sections = Array.isArray(infographic.sections) ? infographic.sections : [];
  const lines = [];
  if (title) lines.push(`Overall title: ${quote(title)}.`);
  if (sections.length) {
    sections.forEach((section, i) => {
      const n = String(i + 1).padStart(2, '0');
      const sectionTitle = section.title || `Panel ${i + 1}`;
      const bullets = Array.isArray(section.bullets)
        ? section.bullets.join('; ')
        : section.content || '';
      lines.push(
        `Badge ${n} + heading ${quote(`Step ${i + 1}: ${sectionTitle}`)}${bullets ? `; body ${quote(bullets)}` : ''}`
      );
    });
  } else if (prompt) {
    lines.push(`Content brief: ${String(prompt).trim()}`);
  }
  return lines;
}

/**
 * Build an infographic image prompt from a planner spec (or section fallback).
 */
function buildInfographicPrompt({
  prompt,
  styleId,
  brandPalette,
  infographic = {},
  plan = null,
} = {}) {
  const layout = (plan && plan.layout) || infographic.layout || 'custom';
  const layoutHint = LAYOUT_HINTS[layout] || LAYOUT_HINTS.custom;
  const paletteList =
    (plan && Array.isArray(plan.palette) && plan.palette.length && plan.palette) ||
    (Array.isArray(brandPalette) && brandPalette.length && brandPalette) ||
    null;
  const palette = paletteList ? paletteList.join(', ') : 'navy/purple accents, green for success';
  const expected = plan?.expectedStepCount || infographic.sections?.length || 1;

  const lines = [
    `Create a clean, professional infographic-style diagram (${layoutHint}).`,
    `${expected} numbered flow step(s) must ALL appear on the canvas — do not drop the last step.`,
    `White or very light background, [${palette}] used consistently as discrete fills (no broken morphing gradients).`,
    'Fit every panel on the canvas with at least 5% margin on all edges. Do not clip content.',
  ];

  if (plan?.title) {
    lines.push(`Title (large bold): ${quote(plan.title)}.`);
  } else if (infographic.title) {
    lines.push(`Title (large bold): ${quote(infographic.title)}.`);
  }
  if (plan?.subtitle) {
    lines.push(`Subtitle (smaller): ${quote(plan.subtitle)}.`);
  }

  if (plan && Array.isArray(plan.regions) && plan.regions.length) {
    lines.push('', ...regionLines(plan));
  } else {
    lines.push('', ...fallbackPanelLines(infographic, prompt));
  }

  if (Array.isArray(plan?.metrics) && plan.metrics.length) {
    lines.push('', `Metrics in order: ${plan.metrics.join(' → ')}. Funnel/stats values must not increase mid-flow.`);
  }

  if (plan?.characterNotes) {
    lines.push(`Character consistency: ${plan.characterNotes}`);
  }

  lines.push(...exactTextBlock(plan));

  lines.push(
    '',
    layoutCraft(layout),
    '',
    'Craft: flat vector icons, rounded rectangle cards of equal size within a row,',
    'thin arrows for sequence (never looping), numbered circular badges 01, 02, 03… with no gaps or duplicates.',
    'Each flow step has BOTH a badge number AND a heading "Step N: …" so sequence survives if a badge corrupts.',
    'Typography: large bold title, medium-weight step headers, small regular body. Premium SaaS / poster look.',
    'Icons never overlap text. Distinct cards with clear spacing. No photorealistic elements, no 3D renders.',
    'Render every quoted string exactly. Do not misspell, merge words, substitute symbols for numbers, or invent extra copy.'
  );

  if (styleId && ALLOWED_STYLE_IDS.has(styleId) && !LOCKED_STYLE_IDS.has(styleId)) {
    if (styleId === 'flat_illustration') {
      lines.push('Style: flat vector illustration, clean shapes, limited palette.');
    } else if (styleId === 'corporate') {
      lines.push('Style: clean corporate, brand-safe, professional.');
    } else if (styleId === 'minimal') {
      lines.push('Style: minimalist, generous negative space, restrained palette.');
    } else if (styleId === 'playful') {
      lines.push('Style: playful, friendly rounded shapes — still flat vector, not photoreal.');
    }
  }

  return lines.join('\n');
}

module.exports = {
  buildInfographicPrompt,
  LAYOUT_HINTS,
  LOCKED_STYLE_IDS,
};
