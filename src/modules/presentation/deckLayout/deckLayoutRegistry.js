const seed = require('../templates/seed-layouts.json');
const { toDeckLayout } = require('./toDeckLayout');
const { validateDeckLayout, validateDeckLayoutCollection } = require('./validateDeckLayout');

function asTemplate(row) {
  return {
    name: row.name,
    contentType: row.contentType,
    variant: row.variant,
    schema: row.schema,
  };
}

function listSeedTemplates() {
  return seed.map(asTemplate);
}

/**
 * All catalog layouts as DeckLayout metadata.
 * @param {{ includeElements?: boolean }} [options]
 */
function listDeckLayouts(options = {}) {
  return listSeedTemplates().map((template) => toDeckLayout(template, options));
}

const LAYOUT_ID_ALIASES = {
  process_linear_v1: 'process_linner_horti_v1',
};

function normalizeLayoutId(layoutId) {
  const id = String(layoutId || '').trim();
  return LAYOUT_ID_ALIASES[id] || id;
}

/**
 * Lookup one layout by existing layout_id.
 * @param {string} layoutId
 * @param {{ includeElements?: boolean }} [options]
 */
function getDeckLayout(layoutId, options = {}) {
  const id = normalizeLayoutId(layoutId);
  const template = listSeedTemplates().find(
    (t) => t.schema?.layout_id === id || t.variant === id
  );
  if (!template) return null;
  return toDeckLayout(template, options);
}

function getDeckLayoutElements(layoutId) {
  const layout = getDeckLayout(layoutId, { includeElements: true });
  return layout?.elements || [];
}

function validateRegistry(options = {}) {
  const layouts = listDeckLayouts(options);
  return validateDeckLayoutCollection(layouts);
}

module.exports = {
  listSeedTemplates,
  listDeckLayouts,
  getDeckLayout,
  getDeckLayoutElements,
  validateRegistry,
  toDeckLayout,
  validateDeckLayout,
  validateDeckLayoutCollection,
};
