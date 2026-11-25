'use strict';

const { ContentContractValidationError } = require('./errors.js');
const { slotEnvelope, getGridDims } = require('./slotGeometry.js');
const {
  truncateWords,
  truncateChars,
  walkNormalizeStrings,
  clampSlotText,
} = require('./textNormalize.js');
const { textForSlot, coerceSlotText } = require('./slotText.js');

const CHARS_PER_WORD = 6;
const WORDS_PER_LINE = 12;
const DEFAULT_TITLE_CHARS = 80;
const DEFAULT_SUBTITLE_CHARS = 140;
const DEFAULT_BODY_LINE_CHARS = 72;

function countSlotPattern(slots, regex) {
  const ids = slots.map((s) => String(s.id || '').toUpperCase());
  let maxIndex = 0;
  for (const id of ids) {
    const match = id.match(regex);
    if (match && match[1]) {
      const idx = parseInt(match[1], 10);
      if (idx > maxIndex) maxIndex = idx;
    }
  }
  return maxIndex;
}

function countPlanItemSlots(slots) {
  const ids = slots.map((s) => String(s.id || '').toUpperCase());
  let max = 0;
  for (const id of ids) {
    const match = id.match(/^PLAN_\d+_ITEM_(\d+)$/);
    if (match) max = Math.max(max, parseInt(match[1], 10));
  }
  return max;
}

function countStepSlots(slots) {
  const stepIds = new Set();
  for (const slot of slots) {
    const m = String(slot?.id || '').match(/^(?:step|STEP)_(\d+)_/i);
    if (m) stepIds.add(m[1]);
  }
  return stepIds.size;
}

function countTableCellGrid(slots) {
  let maxR = 0;
  let maxC = 0;
  for (const slot of slots) {
    const m = String(slot?.id || '').match(/^CELL_(\d+)_(\d+)$/i);
    if (!m) continue;
    maxR = Math.max(maxR, Number(m[1]));
    maxC = Math.max(maxC, Number(m[2]));
  }
  return maxR > 0 && maxC > 0 ? maxR * maxC : 0;
}

function roleOf(slot) {
  return String(slot?.role || '').trim().toLowerCase();
}

function idOf(slot) {
  return String(slot?.id || '');
}

function charsFromLimits(slot, fallbackChars) {
  const maxWords = slot?.max_words != null ? Number(slot.max_words) : null;
  const maxLines = slot?.max_lines != null ? Number(slot.max_lines) : null;
  if (maxWords != null && maxWords > 0) return Math.round(maxWords * CHARS_PER_WORD);
  if (maxLines != null && maxLines > 0) return Math.round(maxLines * WORDS_PER_LINE * CHARS_PER_WORD);
  return fallbackChars;
}

function defaultLimitsForSlot(slot) {
  const role = roleOf(slot);
  const id = idOf(slot).toUpperCase();
  if (role === 'heading' || /^(MAIN_TITLE|HEADING|HEADLINE|TITLE|STATEMENT)$/.test(id)) {
    return {
      maxLines: slot.max_lines != null ? Number(slot.max_lines) : 2,
      maxWords: slot.max_words != null ? Number(slot.max_words) : null,
      maxChars: charsFromLimits(slot, DEFAULT_TITLE_CHARS),
    };
  }
  if (role === 'subheading' || id === 'SUBTITLE' || id === 'SUBHEADLINE') {
    return {
      maxLines: slot.max_lines != null ? Number(slot.max_lines) : 2,
      maxWords: slot.max_words != null ? Number(slot.max_words) : null,
      maxChars: charsFromLimits(slot, DEFAULT_SUBTITLE_CHARS),
    };
  }
  if (role === 'body' || role === 'caption' || /^BODY/.test(id)) {
    const lines = slot.max_lines != null ? Number(slot.max_lines) : 4;
    return {
      maxLines: lines,
      maxWords: slot.max_words != null ? Number(slot.max_words) : null,
      maxChars: charsFromLimits(slot, lines * DEFAULT_BODY_LINE_CHARS),
    };
  }
  if (role === 'stat') {
    return {
      maxLines: slot.max_lines != null ? Number(slot.max_lines) : 1,
      maxWords: slot.max_words != null ? Number(slot.max_words) : null,
      maxChars: charsFromLimits(slot, 15),
    };
  }
  return {
    maxLines: slot.max_lines != null ? Number(slot.max_lines) : null,
    maxWords: slot.max_words != null ? Number(slot.max_words) : null,
    maxChars: charsFromLimits(slot, DEFAULT_BODY_LINE_CHARS * 2),
  };
}

function deriveContentContract(schema) {
  const slots = Array.isArray(schema?.slots) ? schema.slots : [];
  const pointCount = countSlotPattern(slots, /^POINT_(\d+)_/i);
  const columnCount = countSlotPattern(slots, /^(?:CARD|COL|ROW|FEATURE)_(\d+)_/i);
  const stepCount = countStepSlots(slots);
  const hasDualMetrics = slots.some((s) => /^METRIC_A_/i.test(String(s?.id || '')))
    && slots.some((s) => /^METRIC_B_/i.test(String(s?.id || '')));

  const groups = {
    columns: Math.max(columnCount, pointCount),
    points: pointCount,
    stats: countSlotPattern(slots, /^STAT_(\d+)_/i),
    members: countSlotPattern(slots, /^MEMBER_(\d+)_/i),
    timeline: countSlotPattern(slots, /^MILESTONE_(\d+)_/i),
    steps: Math.max(stepCount, countSlotPattern(slots, /^STEP_(\d+)_/i)),
    quadrants: countSlotPattern(slots, /^Q(\d+)_/i),
    funnel: countSlotPattern(slots, /^FUNNEL_(\d+)_/i),
    bullets: countSlotPattern(slots, /^BULLET_(\d+)/i),
    quotes: countSlotPattern(slots, /^QUOTE_(\d+)/i),
    items: countSlotPattern(slots, /^ITEM_(\d+)/i),
    images: countSlotPattern(slots, /^IMAGE_(\d+)/i),
    plans: countSlotPattern(slots, /^PLAN_(\d+)_/i),
    planItems: countPlanItemSlots(slots),
    pricingFeatures: countSlotPattern(slots, /^FEATURE_(\d+)$/i),
    comparisonRows: countSlotPattern(slots, /^ROW_(\d+)_LEFT_/i),
    tableCells: countTableCellGrid(slots),
    dualMetrics: hasDualMetrics ? 2 : 0,
  };

  const slotMap = {};
  for (const slot of slots) {
    if (!slot?.id) continue;
    const limits = defaultLimitsForSlot(slot);
    slotMap[slot.id] = {
      role: roleOf(slot),
      maxLines: limits.maxLines,
      maxWords: limits.maxWords,
      maxChars: limits.maxChars,
      maxItems: slot.max_items != null ? Number(slot.max_items) : null,
      envelope: slotEnvelope(slot),
    };
  }

  const heading = slots.find(
    (s) => roleOf(s) === 'heading' || /^(MAIN_TITLE|HEADING|HEADLINE|TITLE)$/i.test(idOf(s))
  );
  const subtitle = slots.find((s) => roleOf(s) === 'subheading' || /^SUBTITLE$/i.test(idOf(s)));

  return {
    layoutId: String(schema?.layout_id || schema?.layoutId || ''),
    contentType: String(schema?.content_type || schema?.contentType || ''),
    groups,
    slots: slotMap,
    capacity: {
      maxTitleCharacters: heading ? charsFromLimits(heading, DEFAULT_TITLE_CHARS) : 0,
      maxSubtitleCharacters: subtitle ? charsFromLimits(subtitle, DEFAULT_SUBTITLE_CHARS) : 0,
      maxColumns: Math.max(groups.columns, 1),
      maxBullets: groups.bullets,
      maxImages: groups.images,
    },
    grid: getGridDims(slots),
  };
}

function titleWordLimit(contract) {
  const main = contract.slots.MAIN_TITLE || contract.slots.HEADING || contract.slots.TITLE;
  if (main?.maxWords) return main.maxWords;
  if (main?.maxChars) return Math.max(1, Math.ceil(main.maxChars / CHARS_PER_WORD));
  return 15;
}

function subtitleWordLimit(contract) {
  const sub = contract.slots.SUBTITLE || contract.slots.SUBHEADLINE;
  if (sub?.maxWords) return sub.maxWords;
  if (sub?.maxChars) return Math.max(1, Math.ceil(sub.maxChars / CHARS_PER_WORD));
  return 25;
}

function bodyWordLimit(contract) {
  const body = contract.slots.BODY || contract.slots.BODY_L;
  if (body?.maxWords) return body.maxWords;
  if (body?.maxChars) return Math.max(1, Math.ceil(body.maxChars / CHARS_PER_WORD));
  return 120;
}

function normalizeContentForLayout(content, schema) {
  if (!content || typeof content !== 'object') return {};

  const contract = deriveContentContract(schema);
  const normalized = walkNormalizeStrings(JSON.parse(JSON.stringify(content)));

  if (normalized.title) normalized.title = truncateWords(normalized.title, titleWordLimit(contract));
  if (normalized.subtitle) normalized.subtitle = truncateWords(normalized.subtitle, subtitleWordLimit(contract));
  if (normalized.body) normalized.body = truncateWords(normalized.body, bodyWordLimit(contract));

  if (Array.isArray(normalized.columns) && contract.groups.columns > 0) {
    normalized.columns = normalized.columns.slice(0, contract.groups.columns);
    normalized.columns.forEach((col) => {
      if (col.title) col.title = truncateWords(col.title, 10);
      if (col.body) col.body = truncateWords(col.body, 30);
    });
  }

  if (Array.isArray(normalized.stats) && contract.groups.stats > 0) {
    normalized.stats = normalized.stats.slice(0, contract.groups.stats);
    normalized.stats.forEach((stat) => {
      if (stat.value) stat.value = truncateChars(stat.value, 15);
      if (stat.label) stat.label = truncateWords(stat.label, 8);
    });
  }

  const membersArray = normalized.members || normalized.team || normalized.people;
  if (Array.isArray(membersArray) && contract.groups.members > 0) {
    const limitedMembers = membersArray.slice(0, contract.groups.members);
    limitedMembers.forEach((member) => {
      if (typeof member === 'object') {
        if (member.name) member.name = truncateWords(member.name, 5);
        if (member.role) member.role = truncateWords(member.role, 8);
        if (member.bio) member.bio = truncateWords(member.bio, 25);
      }
    });
    normalized.members = limitedMembers;
  }

  const timelineArray = normalized.timeline || normalized.milestones || normalized.events;
  if (Array.isArray(timelineArray) && contract.groups.timeline > 0) {
    const limitedTimeline = timelineArray.slice(0, contract.groups.timeline);
    limitedTimeline.forEach((item) => {
      if (typeof item === 'object') {
        if (item.label) item.label = truncateWords(item.label, 8);
        if (item.detail) item.detail = truncateWords(item.detail, 25);
      }
    });
    normalized.timeline = limitedTimeline;
  }

  const diagramCells =
    normalized.diagram?.cells || normalized.cells || normalized.steps || normalized.quadrants || normalized.funnel;
  if (Array.isArray(diagramCells)) {
    const limit = Math.max(contract.groups.steps, contract.groups.quadrants, contract.groups.funnel);
    if (limit > 0) {
      const limitedCells = diagramCells.slice(0, limit);
      limitedCells.forEach((cell) => {
        if (typeof cell === 'object') {
          if (cell.title) cell.title = truncateWords(cell.title, 8);
          if (cell.body) cell.body = truncateWords(cell.body, 25);
        }
      });
      if (contract.groups.steps > 0) normalized.steps = limitedCells;
      if (contract.groups.quadrants > 0) normalized.quadrants = limitedCells;
      if (contract.groups.funnel > 0) normalized.funnel = limitedCells;
    }
  }

  if (Array.isArray(normalized.bullets) && contract.groups.bullets > 0) {
    normalized.bullets = normalized.bullets.slice(0, contract.groups.bullets);
  }

  if (Array.isArray(normalized.items) && contract.groups.items > 0) {
    normalized.items = normalized.items.slice(0, contract.groups.items);
  }

  if (contract.groups.plans > 0 && Array.isArray(normalized.plans)) {
    normalized.plans = normalized.plans.slice(0, contract.groups.plans);
    const itemCap = contract.groups.planItems;
    if (itemCap > 0) {
      normalized.plans = normalized.plans.map((plan) => {
        if (!plan || typeof plan !== 'object') return plan;
        const next = { ...plan };
        if (Array.isArray(next.items) && next.items.length > itemCap) {
          next.items = next.items.slice(0, itemCap);
        }
        return next;
      });
    }
  }

  const quotesList = normalized.quotes || normalized.testimonials;
  if (Array.isArray(quotesList) && contract.groups.quotes > 0) {
    const limitedQuotes = quotesList.slice(0, contract.groups.quotes);
    limitedQuotes.forEach((q) => {
      if (typeof q === 'object' && q.text) q.text = truncateWords(q.text, 40);
    });
    normalized.quotes = limitedQuotes;
  }

  return normalized;
}

function isTextSlotRole(role) {
  const r = String(role || '').toLowerCase();
  return ['heading', 'subheading', 'body', 'caption', 'quote', 'stat', 'cta', 'eyebrow', 'label'].includes(r);
}

function pushArrayOverflow(errors, path, arr, max) {
  if (!Array.isArray(arr) || max <= 0) return;
  if (arr.length > max) {
    errors.push({
      code: 'ARRAY_OVERFLOW',
      path,
      message: `${path} has ${arr.length} items but layout allows ${max}`,
      actual: arr.length,
      max,
    });
  }
}

/**
 * Detect array/group overflows on raw content before normalizeContentForLayout can conceal them.
 * @returns {Array<{ code: string, path: string, message: string, actual?: number, max?: number }>}
 */
function collectRawArrayOverflowErrors(content, schema) {
  const errors = [];
  if (!schema || !Array.isArray(schema.slots)) return errors;
  const raw = content && typeof content === 'object' ? content : {};
  const contract = deriveContentContract(schema);
  const g = contract.groups || {};

  pushArrayOverflow(errors, 'columns', raw.columns, g.columns);
  pushArrayOverflow(errors, 'stats', raw.stats, g.stats);
  pushArrayOverflow(errors, 'members', raw.members || raw.team || raw.people, g.members);
  pushArrayOverflow(
    errors,
    'timeline',
    raw.timeline || raw.milestones || raw.events,
    g.timeline
  );
  pushArrayOverflow(errors, 'bullets', raw.bullets, g.bullets);
  pushArrayOverflow(errors, 'items', raw.items, g.items);
  pushArrayOverflow(errors, 'quotes', raw.quotes || raw.testimonials, g.quotes);
  pushArrayOverflow(errors, 'plans', raw.plans, g.plans);

  const comparisonRows = raw.comparison?.rows;
  if (Array.isArray(comparisonRows)) {
    pushArrayOverflow(errors, 'comparison.rows', comparisonRows, g.comparisonRows);
  }

  const table = raw.table;
  if (table && g.tableCells > 0) {
    const rowCount = Array.isArray(table.rows) ? table.rows.length : 0;
    if (rowCount > 0) {
      const colCount = Math.max(
        rowCount,
        ...(table.rows || []).map((r) => (Array.isArray(r) ? r.length : 0))
      );
      const cellEstimate = rowCount * Math.max(colCount, 1);
      if (cellEstimate > g.tableCells) {
        errors.push({
          code: 'ARRAY_OVERFLOW',
          path: 'table.rows',
          message: `table.rows exceeds layout table cell capacity (${cellEstimate} > ${g.tableCells})`,
          actual: cellEstimate,
          max: g.tableCells,
        });
      }
    }
  }

  const diagramCells =
    raw.diagram?.cells || raw.cells || raw.steps || raw.quadrants || raw.funnel;
  const stepLimit = Math.max(g.steps, g.quadrants, g.funnel);
  if (Array.isArray(diagramCells) && stepLimit > 0) {
    pushArrayOverflow(errors, 'diagram.cells', diagramCells, stepLimit);
  }

  return errors;
}

function contentFitsLayoutGroups(content, schema) {
  return collectRawArrayOverflowErrors(content, schema).length === 0;
}

function collectContentValidationErrors(content, schema) {
  const errors = [];
  if (!schema || !Array.isArray(schema.slots)) {
    return {
      valid: false,
      layoutId: '',
      errors: [{ code: 'INVALID_SCHEMA', message: 'Layout schema must include slots[]' }],
    };
  }

  const contract = deriveContentContract(schema);
  errors.push(...collectRawArrayOverflowErrors(content, schema));
  errors.push(...collectPostNormalizeContractErrors(content, schema, contract));

  return {
    valid: errors.length === 0,
    layoutId: contract.layoutId,
    errors,
  };
}

function collectPostNormalizeContractErrors(content, schema, contractIn) {
  const errors = [];
  if (!schema || !Array.isArray(schema.slots)) return errors;
  const contract = contractIn || deriveContentContract(schema);
  const normalized = normalizeContentForLayout(content, schema);

  for (const slot of schema.slots) {
    if (!slot?.id || !isTextSlotRole(slot.role)) continue;
    const limits = contract.slots[slot.id];
    if (!limits) continue;
    const raw = coerceSlotText(textForSlot(slot.id, normalized, schema)).trim();
    const clamped = clampSlotText(raw, limits);
    if (raw && limits.maxChars && raw.length > limits.maxChars && raw !== clamped) {
      errors.push({
        code: 'SLOT_CHAR_OVERFLOW',
        slotId: slot.id,
        message: `Slot ${slot.id} text exceeds ${limits.maxChars} characters`,
      });
    }
  }

  const requiresTitle = schema.slots.some(
    (s) => roleOf(s) === 'heading' || /^(MAIN_TITLE|HEADING|HEADLINE|TITLE)$/i.test(idOf(s))
  );
  if (requiresTitle) {
    const titleText = String(normalized.title || '').trim();
    if (!titleText) {
      errors.push({
        code: 'MISSING_TITLE',
        slotId: 'MAIN_TITLE',
        message: 'Layout requires a title but content.title is empty',
      });
    }
  }

  return errors;
}

function validateContentForLayoutSoft(content, schema) {
  return collectContentValidationErrors(content, schema);
}

function validateContentForLayout(content, schema) {
  const result = collectContentValidationErrors(content, schema);
  if (!result.valid) {
    throw new ContentContractValidationError(result.layoutId, result.errors);
  }
  return { valid: true, errors: [] };
}

function repairContentForLayout(content, schema, options) {
  return require('./contentRepair.js').repairContentForLayout(content, schema, options);
}

function repairContentForLayoutDetailed(content, schema, options) {
  return require('./contentRepair.js').repairContentForLayoutDetailed(content, schema, options);
}

function clampRepeatingGroups(content, contract, repairs) {
  return require('./contentRepair.js').clampRepeatingGroups(content, contract, repairs);
}

function assertContentForLayout(content, schema) {
  return validateContentForLayout(content, schema);
}

module.exports = {
  CHARS_PER_WORD,
  WORDS_PER_LINE,
  deriveContentContract,
  normalizeContentForLayout,
  collectRawArrayOverflowErrors,
  collectPostNormalizeContractErrors,
  contentFitsLayoutGroups,
  validateContentForLayout,
  validateContentForLayoutSoft,
  repairContentForLayout,
  repairContentForLayoutDetailed,
  clampRepeatingGroups,
  assertContentForLayout,
};
