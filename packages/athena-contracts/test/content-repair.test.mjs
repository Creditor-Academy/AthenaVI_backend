#!/usr/bin/env node
import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  repairContentForLayoutDetailed,
  validateContentForLayoutSoft,
  clampRepeatingGroups,
  deriveContentContract,
  collectRawArrayOverflowErrors,
} = require('../contentContract.js');
const { isSyntheticRepairFingerprint } = require('../slotText.js');

const schemaThreeCol = {
  layout_id: 'test_three_col',
  slots: [
    { id: 'MAIN_TITLE', role: 'heading' },
    { id: 'CARD_1_TITLE', role: 'heading' },
    { id: 'CARD_1_BODY', role: 'body' },
    { id: 'CARD_2_TITLE', role: 'heading' },
    { id: 'CARD_2_BODY', role: 'body' },
    { id: 'CARD_3_TITLE', role: 'heading' },
    { id: 'CARD_3_BODY', role: 'body' },
  ],
};

test('clampRepeatingGroups does not pad short columns with synthetic titles', () => {
  const contract = deriveContentContract(schemaThreeCol);
  const out = clampRepeatingGroups({ title: 'Plan', columns: [{ title: 'A', body: 'One' }] }, contract, []);
  assert.equal(out.columns.length, 1);
  assert.equal(out.columns[0].title, 'A');
  assert.ok(!isSyntheticRepairFingerprint(out.columns[0].title));
});

test('repair fills missing title and does not invent column filler', () => {
  const { content, repairs } = repairContentForLayoutDetailed({ columns: [] }, schemaThreeCol);
  assert.ok(String(content.title || '').trim());
  assert.ok(repairs.length >= 1);
  assert.equal(Array.isArray(content.columns) ? content.columns.length : 0, 0);
  const v = validateContentForLayoutSoft(content, schemaThreeCol);
  assert.equal(v.valid, true, JSON.stringify(v.errors));
});

test('repair slices overflow bullets without hiding raw overflow signal', () => {
  const schema = {
    layout_id: 'bullets',
    slots: [
      { id: 'MAIN_TITLE', role: 'heading' },
      { id: 'BULLET_1', role: 'body' },
      { id: 'BULLET_2', role: 'body' },
    ],
  };
  const raw = { title: 'T', bullets: ['a', 'b', 'c', 'd'] };
  assert.ok(collectRawArrayOverflowErrors(raw, schema).length >= 1);
  const { content } = repairContentForLayoutDetailed(raw, schema);
  assert.equal(content.bullets.length, 2);
});
