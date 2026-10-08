'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { normalizeGalleryImageContent } = require('../contentPreShape.util');
const { buildSlotImagePrompt } = require('../contentImagePrompt.util');
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

test('normalizeGalleryImageContent builds columns from outline beats for bento', () => {
  const layoutSchema = schemaForLayoutId('grid_bento_three_v1');
  const content = normalizeGalleryImageContent(
    { title: 'Franchise growth pillars' },
    layoutSchema,
    {
      outlineSlide: {
        title: 'Franchise growth pillars',
        beats: ['Dough prep: 48hr ferment', 'Wood-fired oven: 900°F', 'Family dining experience'],
      },
      deckContext: { sourceText: 'Artisan pizza franchise expansion', deckNarrative: '' },
    }
  );
  assert.strictEqual(content.columns.length, 3);
  assert.ok(content.columns[0].title.toLowerCase().includes('dough') || content.columns[0].body);
  assert.ok(content.columns[1].title.toLowerCase().includes('oven') || content.columns[1].body);
  const prompts = content.imagePrompts || {};
  const p1 = String(prompts.IMAGE_1 || prompts.image_1 || '').toLowerCase();
  const p2 = String(prompts.IMAGE_2 || prompts.image_2 || '').toLowerCase();
  const p3 = String(prompts.IMAGE_3 || prompts.image_3 || '').toLowerCase();
  assert.ok(p1 && p2 && p3, 'expected three image prompts');
  assert.notStrictEqual(p1, p2);
  assert.notStrictEqual(p2, p3);
  assert.ok(
    p1.includes('pizza') || p1.includes('franchise') || p1.includes('artisan') || p1.includes('deck'),
    `IMAGE_1 should reflect deck theme: ${p1}`
  );
});

test('buildSlotImagePrompt for grid_bento_three includes deck snippet and distinct subjects', () => {
  const layoutSchema = schemaForLayoutId('grid_bento_three_v1');
  const content = {
    title: 'Menu highlights',
    columns: [
      { title: 'Margherita', body: 'Fresh basil' },
      { title: 'Pepperoni', body: 'Spicy cups' },
      { title: 'White pie', body: 'Garlic ricotta' },
    ],
  };
  const opts = { sourceText: 'Neighborhood pizza franchise deck' };
  const p1 = buildSlotImagePrompt('IMAGE_1', content, layoutSchema, opts);
  const p2 = buildSlotImagePrompt('IMAGE_2', content, layoutSchema, opts);
  assert.ok(/pizza|franchise|neighborhood/i.test(p1), p1);
  assert.ok(/margherita|pepperoni/i.test(p1 + p2), `${p1} vs ${p2}`);
  assert.notStrictEqual(p1.toLowerCase(), p2.toLowerCase());
});

test('textForSlot maps BADGE, HEADING, SUBTITLE for bento header slots', () => {
  const content = {
    badge: 'PIZZA SPOTLIGHT',
    title: 'Signature pies',
    subtitle: 'Three bestsellers from our franchise menu',
  };
  assert.strictEqual(textForSlot('BADGE', content), 'PIZZA SPOTLIGHT');
  assert.strictEqual(textForSlot('HEADING', content), 'Signature pies');
  assert.strictEqual(textForSlot('SUBTITLE', content), 'Three bestsellers from our franchise menu');
});
