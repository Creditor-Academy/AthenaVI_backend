'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { compileSlide } = require('../slideCompiler.service');
const { textForSlot } = require('@athena/contracts/slotText.js');
const { normalizeGalleryImageContent } = require('../contentPreShape.util');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function schemaForLayoutId(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry?.schema, `missing seed schema for ${layoutId}`);
  return entry.schema;
}

test('textForSlot binds PROS_1_TITLE and PROS_1_BODY from pros strings', () => {
  const content = {
    title: 'Franchise vs independent',
    prosTitle: 'Franchisee',
    consTitle: 'Independent',
    pros: ['Brand power: national marketing', 'Training: turnkey ops'],
    cons: ['Fees: royalty stack', 'Less flexibility: menu locked'],
  };
  assert.equal(textForSlot('PROS_PROJECT_TITLE', content, {}, null), 'Franchisee');
  assert.equal(textForSlot('PROS_1_TITLE', content, {}, null), 'Brand power');
  assert.equal(textForSlot('PROS_1_BODY', content, {}, null), 'national marketing');
  assert.equal(textForSlot('CONS_2_TITLE', content, {}, null), 'Less flexibility');
  assert.equal(textForSlot('CONS_2_BODY', content, {}, null), 'menu locked');
});

test('comparison_pros_cons_v1 compile fills row text slots', async () => {
  const layoutSchema = schemaForLayoutId('comparison_pros_cons_v1');
  const content = {
    title: 'Operating models compared',
    prosTitle: 'Franchise',
    consTitle: 'Independent',
    pros: [
      'Buying power: lower food cost',
      'Playbook: proven store layout',
      'Marketing: shared campaigns',
      'Financing: lender familiarity',
      'Expansion: multi-unit path',
    ],
    cons: [
      'Royalties: ongoing fees',
      'Menu control: limited local items',
      'Buildout: brand standards cost',
      'Reporting: heavy compliance',
      'Exit: transfer restrictions',
    ],
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const find = (slotId) =>
    (elementsDoc?.elements || []).find(
      (e) => String(e.slotId || '').toUpperCase() === slotId.toUpperCase()
    );
  const p1t = find('PROS_1_TITLE');
  const p1b = find('PROS_1_BODY');
  assert.ok(p1t?.content?.text?.includes('Buying power'), `PROS_1_TITLE: ${p1t?.content?.text}`);
  assert.ok(p1b?.content?.text?.includes('food cost'), `PROS_1_BODY: ${p1b?.content?.text}`);
});

test('normalizeGalleryImageContent fills six imagePrompts for grid_six_images', () => {
  const layoutSchema = schemaForLayoutId('grid_six_images_v1');
  const content = normalizeGalleryImageContent(
    {
      title: 'Signature pies',
      columns: [
        { title: 'Margherita', body: 'Classic basil' },
        { title: 'Pepperoni', body: 'Spicy cups' },
        { title: 'White pie', body: 'Garlic ricotta' },
        { title: 'Wood oven', body: '900F bake' },
        { title: 'Fresh dough', body: '48hr ferment' },
        { title: 'Family table', body: 'Shared pies' },
      ],
    },
    layoutSchema
  );
  const prompts = content.imagePrompts || {};
  const keys = Object.keys(prompts).filter((k) => /^IMAGE_/i.test(k));
  assert.ok(keys.length >= 6, `expected 6 image prompts, got ${keys.length}`);
});
