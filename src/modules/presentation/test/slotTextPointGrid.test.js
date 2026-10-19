'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { textForSlot } = require('@athena/contracts/slotText.js');
const { runContentPreShape } = require('../contentPreShape.util');
const { compileSlide } = require('../slideCompiler.service');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function schemaForLayoutId(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry?.schema, `missing seed schema for ${layoutId}`);
  return entry.schema;
}

test('textForSlot maps POINT_2_TITLE and POINT_2_DESC from columns', () => {
  const content = {
    title: 'Operations pillars',
    columns: [
      { title: 'First', body: 'One' },
      { title: 'Dough quality', body: '48-hour cold ferment for flavor' },
    ],
  };
  assert.equal(textForSlot('POINT_2_TITLE', content, {}, null), 'Dough quality');
  assert.equal(textForSlot('POINT_2_DESC', content, {}, null), '48-hour cold ferment for flavor');
});

test('normalizePointGridContent pads columns for point grid layouts', () => {
  const layoutSchema = {
    layout_id: 'eight_short_texts_image_v1',
    slots: [{ id: 'POINT_1_TITLE' }, { id: 'POINT_8_DESC' }],
  };
  const shaped = runContentPreShape({ title: 'Menu highlights', columns: [{ title: 'A', body: 'a' }] }, layoutSchema);
  assert.ok(Array.isArray(shaped.columns));
  assert.equal(shaped.columns.length, 2);
});

test('eight_short_texts_image_v1 uses generated columns not SaaS defaults', async () => {
  const layoutSchema = schemaForLayoutId('eight_short_texts_image_v1');
  const content = {
    title: 'Bakery operations',
    columns: [
      { title: 'Morning bake', body: 'Croissants out by 7am' },
      { title: 'Sourdough', body: '48-hour ferment loaves' },
    ],
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const p2 = (elementsDoc?.elements || []).find((e) => String(e.slotId || '') === 'POINT_2_TITLE');
  assert.ok(p2?.content?.text?.includes('Sourdough'), p2?.content?.text);
  assert.ok(!/scalable engine/i.test(p2?.content?.text || ''), p2?.content?.text);
});
