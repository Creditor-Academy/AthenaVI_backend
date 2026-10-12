'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { textForSlot } = require('@athena/contracts/slotText.js');
const { isCatalogPlaceholderText } = require('../catalogPlaceholder');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

const MARKER_TITLE = '__SLIDE_TITLE_MARKER__';

function richFixtureContent() {
  return {
    title: MARKER_TITLE,
    subtitle: '__SUBTITLE__',
    left: {
      title: '__LEFT_TITLE__',
      bullets: ['__LEFT_B1__', '__LEFT_B2__', '__LEFT_B3__'],
    },
    right: {
      title: '__RIGHT_TITLE__',
      bullets: ['__RIGHT_B1__', '__RIGHT_B2__', '__RIGHT_B3__'],
    },
    comparison: {
      rows: [
        {
          leftTitle: '__ROW1_LT__',
          leftBody: '__ROW1_LB__',
          rightTitle: '__ROW1_RT__',
          rightBody: '__ROW1_RB__',
        },
      ],
    },
    columns: Array.from({ length: 8 }, (_, i) => ({
      title: `__COL_T_${i + 1}__`,
      body: `__COL_B_${i + 1}__`,
    })),
    timeline: [
      {
        title: '__STEP1_T__',
        detail: '__STEP1_D__',
        label: '2024',
      },
    ],
    table: {
      headers: ['__H1__', '__H2__'],
      rows: [
        ['__R1C1__', '__R1C2__'],
        ['__R2C1__', '__R2C2__'],
      ],
      rowLabels: ['__RL1__', '__RL2__'],
    },
    stats: [
      { title: '__MA_T__', body: '__MA_D__', label: '__MA_L__' },
      { title: '__MB_T__', body: '__MB_D__', label: '__MB_L__' },
    ],
  };
}

const TITLE_LIKE = /^(title|heading|headline|main_title|subtitle|subheading)$/i;

const KNOWN_MAPPED = [
  { slot: 'POINT_2_TITLE', expect: '__COL_T_2__' },
  { slot: 'LEFT_BODY', expect: '__LEFT_B1__' },
  { slot: 'ROW_1_LEFT_BODY', expect: '__ROW1_LB__' },
  { slot: 'step_1_desc', expect: '__STEP1_D__' },
  { slot: 'CELL_2_2', expect: '__R2C2__' },
  { slot: 'METRIC_B_DESC', expect: '__MB_D__' },
];

test('canonical slots resolve to generated markers, not slide title', () => {
  const content = richFixtureContent();
  for (const { slot, expect } of KNOWN_MAPPED) {
    const got = textForSlot(slot, content, {}, null);
    assert.ok(got.includes(expect), `${slot}: expected fragment of ${expect}, got "${got}"`);
    assert.notEqual(got, MARKER_TITLE, `${slot} must not fall back to slide title`);
  }
});

const PART_A_SLOT_RES = [
  /^point_\d+_(title|desc)$/i,
  /^left_(title|body)$/i,
  /^right_(title|body)$/i,
  /^row_\d+_(left|right)_(title|body)$/i,
  /^step_\d+_(title|body|desc|label|year)$/i,
  /^cell_\d+_\d+$/i,
  /^col_\d+_header$/i,
  /^row_\d+_label$/i,
  /^metric_[ab]_(title|desc|label)$/i,
];

test('Part A text slots in seed layouts do not fall back to slide title', () => {
  const content = richFixtureContent();
  const failures = [];
  for (const entry of seedLayouts) {
    const schema = entry?.schema;
    if (!schema?.slots?.length) continue;
    for (const slot of schema.slots) {
      const id = String(slot.id || '');
      if (!PART_A_SLOT_RES.some((re) => re.test(id))) continue;
      const got = textForSlot(id, content, schema, null);
      if (got === MARKER_TITLE) failures.push(`${schema.layout_id}:${id}`);
    }
  }
  assert.ok(
    failures.length === 0,
    `Part A slots mapped to slide title (${failures.length}): ${failures.slice(0, 20).join(', ')}`
  );
});

test('isCatalogPlaceholderText flags Option A and Lorem ipsum', () => {
  assert.ok(isCatalogPlaceholderText('Option A'));
  assert.ok(isCatalogPlaceholderText('Lorem Ipsum'));
});
