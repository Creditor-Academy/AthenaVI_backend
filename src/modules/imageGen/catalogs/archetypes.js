/**
 * Infographic archetype catalog — content shape, not a fixed visual template.
 * layout[orientation] is typesetting guidance for the render prompt.
 */

const ARCHETYPES = Object.freeze([
  {
    id: 'process',
    label: 'Process',
    description: 'Ordered steps or stages toward an outcome',
    layout: {
      landscape: 'Left-to-right numbered chevron or step flow, arrows between steps.',
      portrait: 'Top-to-bottom vertical stack, downward arrows, numbered badges.',
      square: 'Balanced 2x2 grid or centered stepped column depending on step count.',
    },
    maxSections: { square: 8, landscape: 10, portrait: 14 },
  },
  {
    id: 'timeline',
    label: 'Timeline',
    description: 'Dated or chronological milestones',
    layout: {
      landscape: 'Horizontal timeline axis left-to-right with dated milestone markers.',
      portrait: 'Vertical timeline top-to-bottom with dated milestone markers.',
      square: 'Compact chronological path with clear date labels and short descriptions.',
    },
    maxSections: { square: 8, landscape: 10, portrait: 14 },
  },
  {
    id: 'comparison',
    label: 'Comparison',
    description: 'Two or more options on shared criteria',
    layout: {
      landscape: 'Side-by-side comparison columns with shared criteria rows.',
      portrait: 'Stacked comparison blocks or two vertical columns with clear headers.',
      square: 'Two equal columns or a split canvas with matching criteria labels.',
    },
    maxSections: { square: 8, landscape: 10, portrait: 12 },
  },
  {
    id: 'stats',
    label: 'Stats',
    description: 'KPI-style figures, minimal narrative',
    layout: {
      landscape: 'KPI card row or grid of large numbers with short captions.',
      portrait: 'Stacked KPI cards with large metrics and brief labels.',
      square: 'Centered metric grid (2x2 or 3-up) with large readable numbers.',
    },
    maxSections: { square: 6, landscape: 8, portrait: 10 },
  },
  {
    id: 'hierarchy',
    label: 'Hierarchy',
    description: 'Org, tree, or pyramid relationships',
    layout: {
      landscape: 'Left-to-right tree or pyramid with clear parent-child connectors.',
      portrait: 'Top-down org tree or pyramid with clear levels.',
      square: 'Centered hierarchical tree with readable level labels.',
    },
    maxSections: { square: 8, landscape: 10, portrait: 12 },
  },
  {
    id: 'list',
    label: 'List',
    description: 'An unordered or lightly-ordered set of items',
    layout: {
      landscape: 'Horizontal icon list or multi-column checklist with short labels.',
      portrait: 'Vertical icon list or checklist with generous spacing.',
      square: 'Grid of icon+label items with consistent alignment.',
    },
    maxSections: { square: 8, landscape: 10, portrait: 14 },
  },
  {
    id: 'cycle',
    label: 'Cycle',
    description: 'A process that loops back to its start',
    layout: {
      landscape: 'Circular or elliptical loop with numbered stages and connecting arrows.',
      portrait: 'Vertical cycle with return arrow, or circular loop fitted to portrait.',
      square: 'Centered circular cycle with numbered stages around a core idea.',
    },
    maxSections: { square: 8, landscape: 8, portrait: 10 },
  },
]);

const ARCHETYPE_BY_ID = Object.freeze(Object.fromEntries(ARCHETYPES.map((a) => [a.id, a])));

const ARCHETYPE_IDS = Object.freeze(ARCHETYPES.map((a) => a.id));

function listArchetypes() {
  return ARCHETYPES.map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
  }));
}

function resolveArchetype(archetypeId) {
  if (!archetypeId) return null;
  return ARCHETYPE_BY_ID[String(archetypeId).trim()] || null;
}

function layoutGuidanceFor(archetypeId, orientation) {
  const archetype = resolveArchetype(archetypeId) || ARCHETYPE_BY_ID.process;
  const key = orientation === 'portrait' || orientation === 'square' ? orientation : 'landscape';
  return archetype.layout[key] || archetype.layout.landscape;
}

function maxSectionsFor(archetypeId, orientation) {
  const archetype = resolveArchetype(archetypeId) || ARCHETYPE_BY_ID.process;
  const key = orientation === 'portrait' || orientation === 'square' ? orientation : 'landscape';
  return archetype.maxSections[key] || 10;
}

module.exports = {
  ARCHETYPES,
  ARCHETYPE_BY_ID,
  ARCHETYPE_IDS,
  listArchetypes,
  resolveArchetype,
  layoutGuidanceFor,
  maxSectionsFor,
};
