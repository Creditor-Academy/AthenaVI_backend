function buildSystem() {
  return [
    'You produce Path B composite-diagram prompts for a text-rendering image model.',
    'Your job is visual typesetting of an upstream pathBSpec — not inventing new content, structure, or freehand design.',
    'Panel titles, exact step labels, field names, color-legend meaning, and panel order are fully determined by the spec.',
    'Return a single plain-text image prompt (or JSON { "prompt": "..." } if asked for JSON). Prefer the structured panel pattern below.',
  ].join(' ');
}

/**
 * Build the Path B typesetting prompt from an upstream pathBSpec.
 * @param {{
 *   pathBSpec?: {
 *     panelCount?: number,
 *     panels?: Array<{ title?: string, content?: string, steps?: string[]|string, boxes?: string[]|string }>,
 *     brandPalette?: string,
 *     colorLegend?: string|object,
 *     background?: string,
 *   },
 *   brandPalette?: string,
 *   panelCount?: number,
 * }} vars
 */
function buildUser(vars = {}) {
  const spec = vars.pathBSpec || {};
  const panels = Array.isArray(spec.panels) ? spec.panels : [];
  const n = vars.panelCount || spec.panelCount || panels.length || 1;
  const palette = vars.brandPalette || spec.brandPalette || 'brand accent colors';
  const background = spec.background || 'white background';
  const legend =
    typeof spec.colorLegend === 'string'
      ? spec.colorLegend
      : spec.colorLegend
        ? JSON.stringify(spec.colorLegend)
        : 'specify what each color means';

  const panelLines = panels.map((panel, i) => {
    const title = panel.title || `Panel ${i + 1}`;
    const detail =
      panel.content ||
      (Array.isArray(panel.steps) ? panel.steps.join(' → ') : panel.steps) ||
      (Array.isArray(panel.boxes) ? panel.boxes.join(', ') : panel.boxes) ||
      '';
    return `Panel ${i + 1} ("${title}"): ${detail}`;
  });

  if (!panelLines.length) {
    panelLines.push(`Panel 1 ("[title]"): [exact flow/steps with labels, in order]`);
    if (n > 1) {
      panelLines.push(`Panel 2 ("[title]"): [exact boxes/fields, in order]`);
    }
  }

  return [
    'Create a clean, professional infographic-style diagram, flat vector SaaS deck style,',
    `${n} panels`,
    `arranged in a grid, ${background}, [${palette}] accent`,
    `colors used consistently (${legend}).`,
    '',
    ...panelLines,
    '',
    'Style: flat icons, rounded rectangle boxes, thin arrows connecting',
    'steps, numbered circular badges for sequence, consistent sans-serif',
    'typography, no photorealistic elements.',
  ].join('\n');
}

module.exports = {
  buildSystem,
  buildUser,
};
