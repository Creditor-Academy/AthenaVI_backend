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

test('textForSlot maps ROW_1_LEFT_BODY from comparison.rows', () => {
  const content = {
    title: 'Franchise vs independent',
    left: { title: 'Franchise' },
    right: { title: 'Independent' },
    comparison: {
      rows: [
        {
          leftTitle: 'Fees',
          leftBody: 'Royalties and marketing fund',
          rightTitle: 'Freedom',
          rightBody: 'No ongoing royalty stack',
        },
      ],
    },
  };
  assert.equal(textForSlot('ROW_1_LEFT_TITLE', content, {}, null), 'Fees');
  assert.equal(textForSlot('ROW_1_LEFT_BODY', content, {}, null), 'Royalties and marketing fund');
  assert.equal(textForSlot('ROW_1_RIGHT_BODY', content, {}, null), 'No ongoing royalty stack');
});

test('comparison_table_v1 compile replaces Lorem ipsum row placeholders', async () => {
  const layoutSchema = schemaForLayoutId('comparison_table_v1');
  const content = {
    title: 'Operating models',
    left: { title: 'Franchise bakery' },
    right: { title: 'Independent shop' },
    comparison: {
      rows: [
        {
          leftTitle: 'Brand',
          leftBody: 'National campaigns and recognizable menu',
          rightTitle: 'Local brand',
          rightBody: 'Build reputation block by block',
        },
      ],
    },
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
  const body = find('ROW_1_LEFT_BODY');
  assert.ok(body?.content?.text?.includes('National campaigns'), body?.content?.text);
  assert.ok(!/lorem ipsum/i.test(body?.content?.text || ''), body?.content?.text);
});
