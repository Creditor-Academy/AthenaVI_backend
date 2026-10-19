'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { compileSlide } = require('../slideCompiler.service');
const { textForSlot } = require('@athena/contracts/slotText.js');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function schemaForLayoutId(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry?.schema, `missing seed schema for ${layoutId}`);
  return entry.schema;
}

test('textForSlot maps step_1_desc from timeline', () => {
  const content = {
    title: 'Opening timeline',
    timeline: [
      {
        title: 'Site search',
        body: 'Scout high-footfall corners',
        detail: 'Scout high-footfall corners near schools',
      },
    ],
  };
  assert.equal(textForSlot('step_1_title', content, {}, null), 'Site search');
  assert.equal(textForSlot('step_1_desc', content, {}, null), 'Scout high-footfall corners near schools');
});

test('timeline_process_steps_v1 compile fills step_1_desc', async () => {
  const layoutSchema = schemaForLayoutId('timeline_process_steps_v1');
  const content = {
    title: 'How we launch',
    timeline: [
      {
        label: '01',
        title: 'Discover',
        detail: 'Interview franchisees and map supply chain',
      },
    ],
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const stepDesc = (elementsDoc?.elements || []).find(
    (e) => String(e.slotId || '').toLowerCase() === 'step_1_desc'
  );
  assert.ok(stepDesc?.content?.text?.includes('supply chain'), stepDesc?.content?.text);
});
