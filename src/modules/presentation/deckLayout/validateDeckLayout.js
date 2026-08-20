const {
  DECK_LAYOUT_CATEGORIES,
  DECK_LAYOUT_SLIDE_PURPOSES,
  DECK_LAYOUT_CONTENT_CAPABILITIES,
  DECK_LAYOUT_DENSITIES,
  DECK_LAYOUT_STRUCTURES,
  DECK_LAYOUT_VISUAL_WEIGHTS,
  DECK_LAYOUT_IMAGE_POSITIONS,
  DECK_LAYOUT_TEXT_POSITIONS,
  DECK_LAYOUT_ALIGNMENTS,
  DECK_LAYOUT_DESIGN_STYLES,
  DECK_LAYOUT_MOODS,
  DECK_LAYOUT_INDUSTRIES,
  SUPPORTED_ELEMENT_KEYS,
  DECK_LAYOUT_SLOT_ROLES,
  CANVAS_ELEMENT_TYPES,
} = require('./deckLayout.constants');

function isNonNegInt(value) {
  return Number.isInteger(value) && value >= 0;
}

function pushInvalidEnum(errors, path, value, allowed) {
  if (!allowed.includes(value)) {
    errors.push(`${path} "${value}" is invalid`);
  }
}

function validateArrayEnums(errors, path, values, allowed) {
  if (!Array.isArray(values)) {
    errors.push(`${path} must be an array`);
    return;
  }
  values.forEach((value, i) => {
    if (!allowed.includes(value)) {
      errors.push(`${path}[${i}] "${value}" is invalid`);
    }
  });
}

function validateCapacity(errors, capacity) {
  if (!capacity || typeof capacity !== 'object') {
    errors.push('contentCapacity is required');
    return;
  }
  const keys = [
    'maxTitleCharacters',
    'maxSubtitleCharacters',
    'maxBodyCharacters',
    'maxBullets',
    'maxCards',
    'maxImages',
    'maxMetrics',
    'maxColumns',
  ];
  for (const key of keys) {
    if (!isNonNegInt(capacity[key])) {
      errors.push(`contentCapacity.${key} must be an integer >= 0`);
    }
  }
  if (!DECK_LAYOUT_DENSITIES.includes(capacity.density)) {
    errors.push(`contentCapacity.density "${capacity.density}" is invalid`);
  }
}

function validateSupportedElements(errors, supported) {
  if (!supported || typeof supported !== 'object') {
    errors.push('supportedElements is required');
    return;
  }
  for (const key of SUPPORTED_ELEMENT_KEYS) {
    if (typeof supported[key] !== 'boolean') {
      errors.push(`supportedElements.${key} must be a boolean`);
    }
  }
  for (const key of Object.keys(supported)) {
    if (!SUPPORTED_ELEMENT_KEYS.includes(key)) {
      errors.push(`supportedElements.${key} is not a known element key`);
    }
  }
}

function validateComposition(errors, composition) {
  if (!composition || typeof composition !== 'object') {
    errors.push('composition is required');
    return;
  }
  pushInvalidEnum(errors, 'composition.structure', composition.structure, DECK_LAYOUT_STRUCTURES);
  pushInvalidEnum(errors, 'composition.imagePosition', composition.imagePosition, DECK_LAYOUT_IMAGE_POSITIONS);
  pushInvalidEnum(errors, 'composition.textPosition', composition.textPosition, DECK_LAYOUT_TEXT_POSITIONS);
  pushInvalidEnum(errors, 'composition.alignment', composition.alignment, DECK_LAYOUT_ALIGNMENTS);
  pushInvalidEnum(errors, 'composition.visualWeight', composition.visualWeight, DECK_LAYOUT_VISUAL_WEIGHTS);
}

function validateStyle(errors, style) {
  if (!style || typeof style !== 'object') {
    errors.push('style is required');
    return;
  }
  validateArrayEnums(errors, 'style.designStyles', style.designStyles, DECK_LAYOUT_DESIGN_STYLES);
  validateArrayEnums(errors, 'style.moods', style.moods, DECK_LAYOUT_MOODS);
  if (!Array.isArray(style.industries)) {
    errors.push('style.industries must be an array');
  } else {
    style.industries.forEach((value, i) => {
      if (typeof value !== 'string' || !value.trim()) {
        errors.push(`style.industries[${i}] must be a non-empty string`);
      } else if (!DECK_LAYOUT_INDUSTRIES.includes(value)) {
        errors.push(`style.industries[${i}] "${value}" is invalid`);
      }
    });
  }
}

function validateSchema(errors, schema, layoutId) {
  if (schema == null) return;
  if (typeof schema !== 'object') {
    errors.push('schema must be an object');
    return;
  }
  if (!schema.layout_id) errors.push('schema.layout_id is required');
  if (layoutId && schema.layout_id && schema.layout_id !== layoutId) {
    errors.push(`id "${layoutId}" does not match schema.layout_id "${schema.layout_id}"`);
  }
  if (!Array.isArray(schema.slots)) {
    errors.push('schema.slots must be an array');
    return;
  }
  schema.slots.forEach((slot, index) => {
    if (!slot?.id) errors.push(`schema.slots[${index}].id is required`);
    if (!slot?.region) errors.push(`schema.slots[${index}].region is required`);
    const role = String(slot?.role || '').trim().toLowerCase();
    if (role && !DECK_LAYOUT_SLOT_ROLES.includes(role)) {
      errors.push(`schema.slots[${index}].role "${slot.role}" is unsupported`);
    }
  });
}

function validateElements(errors, elements) {
  if (elements == null) return;
  if (!Array.isArray(elements)) {
    errors.push('elements must be an array');
    return;
  }
  elements.forEach((el, index) => {
    if (!el || typeof el !== 'object') {
      errors.push(`elements[${index}] must be an object`);
      return;
    }
    if (!el.id) errors.push(`elements[${index}].id is required`);
    if (!CANVAS_ELEMENT_TYPES.includes(el.type)) {
      errors.push(`elements[${index}].type "${el.type}" is unsupported`);
    }
    const placement = el.placement;
    if (!placement || typeof placement !== 'object') {
      errors.push(`elements[${index}].placement is required`);
      return;
    }
    for (const key of ['x', 'y', 'width', 'height']) {
      if (typeof placement[key] !== 'number' || Number.isNaN(placement[key])) {
        errors.push(`elements[${index}].placement.${key} must be a number`);
      }
    }
  });
}

/**
 * Validate a DeckLayout metadata object.
 * @returns {{ ok: boolean, errors: string[] }}
 */
function validateDeckLayout(layout) {
  const errors = [];
  if (!layout || typeof layout !== 'object') {
    return { ok: false, errors: ['layout must be an object'] };
  }
  if (!layout.id) errors.push('missing ID');
  if (!layout.category) errors.push('missing category');
  else if (!DECK_LAYOUT_CATEGORIES.includes(layout.category)) {
    errors.push(`category "${layout.category}" is invalid`);
  }
  if (!layout.name) errors.push('name is required');
  if (!layout.description) errors.push('description is required');
  if (!Number.isInteger(layout.version) || layout.version < 1) {
    errors.push('version must be an integer >= 1');
  }
  if (!layout.contentType) errors.push('contentType is required');

  validateArrayEnums(errors, 'slidePurposes', layout.slidePurposes, DECK_LAYOUT_SLIDE_PURPOSES);
  validateArrayEnums(errors, 'contentTypes', layout.contentTypes, DECK_LAYOUT_CONTENT_CAPABILITIES);
  if (layout.tags != null && !Array.isArray(layout.tags)) {
    errors.push('tags must be an array');
  }

  validateCapacity(errors, layout.contentCapacity);
  validateComposition(errors, layout.composition);
  validateStyle(errors, layout.style);
  validateSupportedElements(errors, layout.supportedElements);
  validateSchema(errors, layout.schema, layout.id);
  validateElements(errors, layout.elements);

  return { ok: errors.length === 0, errors };
}

/**
 * Validate a collection and detect duplicate layout IDs.
 * @returns {{ ok: boolean, errors: string[] }}
 */
function validateDeckLayoutCollection(layouts) {
  if (!Array.isArray(layouts)) {
    return { ok: false, errors: ['layouts must be an array'] };
  }
  const errors = [];
  const seen = new Map();
  layouts.forEach((layout, index) => {
    const result = validateDeckLayout(layout);
    result.errors.forEach((msg) => errors.push(`layouts[${index}]: ${msg}`));
    const id = layout?.id;
    if (!id) return;
    if (seen.has(id)) {
      errors.push(`duplicate layout ID "${id}" (layouts[${seen.get(id)}] and layouts[${index}])`);
    } else {
      seen.set(id, index);
    }
  });
  return { ok: errors.length === 0, errors };
}

module.exports = {
  validateDeckLayout,
  validateDeckLayoutCollection,
};
