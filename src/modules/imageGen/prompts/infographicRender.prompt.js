const { composeRulesForMode } = require('../catalogs/formats');
const { layoutGuidanceFor, resolveArchetype } = require('../catalogs/archetypes');

function formatSection(section, index) {
  const n = section.number != null ? section.number : index + 1;
  const parts = [`[${n}] "${section.label}"`];
  if (section.body) parts.push(`body: ${section.body}`);
  if (section.metric) parts.push(`metric: ${section.metric}`);
  if (section.iconHint) parts.push(`icon: ${section.iconHint}`);
  if (Array.isArray(section.chips) && section.chips.length) {
    parts.push(`chips: ${section.chips.join(', ')}`);
  }
  if (section.color) parts.push(`accent: ${section.color}`);
  if (section.emphasize) parts.push('EMPHASIZE');
  return parts.join(' | ');
}

function buildContentBlock(spec) {
  const lines = [];
  lines.push(`Title (exact): "${spec.title}"`);
  if (spec.titleAccent) lines.push(`Title accent substring (exact): "${spec.titleAccent}"`);
  if (spec.subtitle) lines.push(`Subtitle (exact): "${spec.subtitle}"`);

  if (Array.isArray(spec.flows) && spec.flows.length) {
    lines.push('', 'Parallel flows — render as labeled side-by-side lanes/columns (one lane per flow):');
    spec.flows.forEach((flow, fi) => {
      lines.push(`Flow ${fi + 1} "${flow.label}":`);
      (flow.sections || []).forEach((section, si) => {
        lines.push(`  ${formatSection(section, si)}`);
      });
    });
  } else {
    lines.push('', 'Sections (exact copy, in order):');
    (spec.sections || []).forEach((section, si) => {
      lines.push(formatSection(section, si));
    });
  }

  if (spec.sidebar) {
    lines.push('', 'Sidebar (exact):');
    if (spec.sidebar.title) lines.push(`  title: ${spec.sidebar.title}`);
    if (spec.sidebar.body) lines.push(`  body: ${spec.sidebar.body}`);
    if (Array.isArray(spec.sidebar.items)) {
      spec.sidebar.items.forEach((item) => lines.push(`  - ${item}`));
    }
  }

  if (Array.isArray(spec.notes) && spec.notes.length) {
    lines.push('', 'Callout notes (exact):');
    spec.notes.forEach((note) => {
      lines.push(`  ${note.title ? `${note.title}: ` : ''}${note.body}`);
    });
  }

  if (spec.footerFlow && Array.isArray(spec.footerFlow.items)) {
    lines.push(
      '',
      `Footer chain (exact): ${spec.footerFlow.items.map((i) => i.label).join(' → ')}`
    );
  }

  return lines.join('\n');
}

/**
 * Build the image-model typesetting prompt from a validated InfographicSpec.
 * Independent of PPT Path B, but borrows the same "verbatim panel" discipline.
 */
function buildInfographicRenderPrompt({
  spec,
  format,
  hasReferences = false,
} = {}) {
  const orientation =
    (spec && spec.orientation) ||
    (format && format.id) ||
    'landscape';
  const archetypeId = (spec && spec.archetype) || 'process';
  const archetype = resolveArchetype(archetypeId);
  const layoutLine = layoutGuidanceFor(archetypeId, orientation);
  const { composeRules, safeZone } = composeRulesForMode(format, 'infographic');

  const parts = [
    'Create a clean, professional infographic as a flat vector / diagram typesetting image.',
    'Your job is visual TYPESSETTING of the exact content below — not inventing new copy, numbers, or structure.',
    'Reproduce every title, label, body, and metric VERBATIM and correctly spelled. Do not add, remove, or alter words or numbers.',
    'No photorealistic backgrounds. Prefer flat icons, rounded cards, thin connectors, and clear sans-serif typography.',
    '',
    `Canvas orientation: ${orientation}${format ? ` (${format.width}x${format.height})` : ''}`,
    `Archetype: ${archetype ? archetype.label : archetypeId}`,
    `Layout guidance: ${layoutLine}`,
  ];

  if (composeRules && composeRules.length) {
    parts.push('', 'Composition rules:', ...composeRules.map((r) => `- ${r}`));
  }
  if (safeZone) {
    parts.push(`Safe zone: ${safeZone}`);
  }

  if (spec.visualStyle && String(spec.visualStyle).trim()) {
    parts.push('', `Visual style (follow this appearance guidance): ${String(spec.visualStyle).trim()}`);
  } else {
    parts.push(
      '',
      'Visual style: none specified — make a clean, readable default; do not force a branded house look.'
    );
  }

  if (Array.isArray(spec.palette) && spec.palette.length) {
    parts.push(`Color palette (hard constraint): ${spec.palette.join(', ')}`);
  }

  parts.push('', '=== CONTENT TO TYPESET (exact) ===', buildContentBlock(spec), '=== END CONTENT ===');

  if (hasReferences) {
    parts.push(
      '',
      'Reference images: use only as brand, logo, or icon cues. Do NOT copy photographic scenes or replace diagram structure with photos.'
    );
  }

  parts.push(
    '',
    'Output a single finished infographic image filling the canvas with readable text and clear structure.'
  );

  return parts.filter((p) => p != null).join('\n');
}

module.exports = {
  buildInfographicRenderPrompt,
  buildContentBlock,
};
