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
} = require('../contentContract.js');

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

test('clampRepeatingGroups pads short columns', () => {
  const contract = deriveContentContract(schemaThreeCol);
  const out = clampRepeatingGroups({ title: 'Plan', columns: [{ title: 'A', body: 'One' }] }, contract, []);
  assert.equal(out.columns.length, 3);
  assert.ok(out.columns[2].title);
});

test('repair fills missing title and validates soft', () => {
  const { content, repairs } = repairContentForLayoutDetailed({ columns: [] }, schemaThreeCol);
  assert.ok(String(content.title || '').trim());
  assert.ok(repairs.length >= 1);
  const v = validateContentForLayoutSoft(content, schemaThreeCol);
  assert.equal(v.valid, true, JSON.stringify(v.errors));
});

test('repair slices overflow bullets', () => {
  const schema = {
    layout_id: 'bullets',
    slots: [
      { id: 'MAIN_TITLE', role: 'heading' },
      { id: 'BULLET_1', role: 'body' },
      { id: 'BULLET_2', role: 'body' },
    ],
  };
  const { content } = repairContentForLayoutDetailed(
    { title: 'T', bullets: ['a', 'b', 'c', 'd'] },
    schema
  );
  assert.equal(content.bullets.length, 2);
});
