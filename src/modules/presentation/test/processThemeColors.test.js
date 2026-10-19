'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const {
  processStepColors,
  isLegacyProcessColor,
  LEGACY_PROCESS_STEP_COLORS,
} = require('../diagrams/processThemeColors');
const horti = require('../diagrams/processLinearHortiLayout');
const hortiFour = require('../diagrams/processLinearHortiFourLayout');
const business = require('../diagrams/processLinearBusinessLayout');
const fourCards = require('../diagrams/processLinearFourCardsLayout');
const horizontal = require('../diagrams/processLinearHorizontalLayout');
const numeric = require('../diagrams/processLinearNumericLayout');
const numericCards = require('../diagrams/processLinearNumericCardsLayout');

const NAVY_THEME = {
  primary: '#1E3A8A',
  secondary: '#1D4ED8',
  accent: '#3B82F6',
  text: '#0F172A',
  muted: '#475569',
  bg: '#FFFFFF',
};

const schemaFor = (layoutId) =>
  (Array.isArray(SEED) ? SEED : SEED.layouts || []).find((t) => t.schema?.layout_id === layoutId)?.schema;

const colorsOf = (elements) =>
  elements.flatMap((el) => [el.content?.fill, el.content?.color]).filter((c) => typeof c === 'string');

test('every former default step color is recognised as legacy', () => {
  for (const mod of [horti, hortiFour, business, fourCards, horizontal, numeric, numericCards]) {
    for (const [key, value] of Object.entries(mod)) {
      if (!/DEFAULT_COLORS$/.test(key)) continue;
      for (const c of value) assert.ok(isLegacyProcessColor(c), `${key} ${c} must be in the legacy set`);
    }
  }
  assert.ok(LEGACY_PROCESS_STEP_COLORS.size >= 20);
});

test('process_linner_horti_v1 step colors come from the theme, not the rainbow palette', () => {
  const schema = schemaFor('process_linner_horti_v1');
  assert.ok(schema, 'seed layout exists');
  const elements = horti.layoutProcessLinearHorti([], schema, NAVY_THEME, { width: 1920, height: 1080 });
  const used = colorsOf(elements);
  assert.ok(used.length > 0);
  const legacy = used.filter((c) => isLegacyProcessColor(c) && !Object.values(NAVY_THEME).includes(c));
  assert.deepStrictEqual(legacy, [], `legacy rainbow colors leaked: ${legacy.join(', ')}`);

  const shapes = elements.filter((el) => /^STEP_\d+_SHAPE$/.test(el.slotId));
  const expected = processStepColors(NAVY_THEME, shapes.length);
  shapes.forEach((el, i) => assert.strictEqual(el.content.fill, expected[i]));
  assert.strictEqual(shapes[0].content.fill, NAVY_THEME.primary);
});

test('recompiling a slide saved with legacy rainbow fills re-themes it; custom colors survive', () => {
  const schema = schemaFor('process_linner_horti_v1');
  const legacyDoc = horti.PROCESS_LINEAR_HORTI_DEFAULT_COLORS.slice(0, 3).map((color, i) => ({
    slotId: `STEP_${i + 1}_SHAPE`,
    type: 'graphic',
    content: { fill: color, color },
  }));
  legacyDoc.push({ slotId: 'STEP_4_SHAPE', type: 'graphic', content: { fill: '#123456', color: '#123456' } });

  const elements = horti.layoutProcessLinearHorti(legacyDoc, schema, NAVY_THEME, { width: 1920, height: 1080 });
  const fills = Object.fromEntries(
    elements.filter((el) => /^STEP_\d+_SHAPE$/.test(el.slotId)).map((el) => [el.slotId, el.content.fill])
  );
  for (const slot of ['STEP_1_SHAPE', 'STEP_2_SHAPE', 'STEP_3_SHAPE']) {
    assert.ok(!isLegacyProcessColor(fills[slot]) || Object.values(NAVY_THEME).includes(fills[slot]), slot);
  }
  assert.strictEqual(fills.STEP_4_SHAPE, '#123456', 'user-chosen color is preserved');
});

test('all process layouts compile with a null palette (no crash, default theme family)', () => {
  const cases = [
    [horti.layoutProcessLinearHorti, 'process_linner_horti_v1'],
    [hortiFour.layoutProcessLinearHortiFour, 'process_linner_horti_four_v1'],
    [numeric.layoutProcessLinearNumeric, 'process_linner_numeric_v1'],
    [business.layoutProcessLinearBusiness, null],
    [fourCards.layoutProcessLinearFourCards, null],
    [horizontal.layoutProcessLinearHorizontal, null],
    [numericCards.layoutProcessLinearNumericCards, null],
  ];
  for (const [fn, layoutId] of cases) {
    assert.strictEqual(typeof fn, 'function');
    const out = fn([], (layoutId && schemaFor(layoutId)) || { slots: [] }, null, { width: 1920, height: 1080 });
    assert.ok(Array.isArray(out) && out.length > 0);
  }
});

test('brand chart colors take precedence when the theme defines them', () => {
  const brand = { ...NAVY_THEME, chartColors: ['#0B3D91', '#5B8DEF'] };
  assert.deepStrictEqual(processStepColors(brand, 3), ['#0B3D91', '#5B8DEF', '#0B3D91']);
});
