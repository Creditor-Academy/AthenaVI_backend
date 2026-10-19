'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { textForSlot } = require('@athena/contracts/slotText.js');
const { runContentPreShape } = require('../contentPreShape.util');

test('preShape + textForSlot binds comparison row for editor slot map parity', () => {
  const layoutSchema = {
    layout_id: 'comparison_table_v1',
    slots: [{ id: 'ROW_1_LEFT_BODY', role: 'body' }],
  };
  const shaped = runContentPreShape(
    {
      title: 'Models',
      comparison: {
        rows: [{ leftTitle: 'Fees', leftBody: 'Royalties apply', rightTitle: 'Free', rightBody: 'None' }],
      },
    },
    layoutSchema
  );
  assert.equal(textForSlot('ROW_1_LEFT_BODY', shaped, layoutSchema), 'Royalties apply');
});

test('preShape + textForSlot binds left side comparison bullets', () => {
  const layoutSchema = {
    layout_id: 'comparison_side_by_side_v1',
    slots: [{ id: 'LEFT_BODY', role: 'body' }],
  };
  const shaped = runContentPreShape(
    {
      title: 'Franchise vs indie',
      left: { title: 'Franchise', bullets: ['Buying power', 'Training'] },
      right: { title: 'Independent', bullets: ['Flexibility'] },
    },
    layoutSchema
  );
  const body = textForSlot('LEFT_BODY', shaped, layoutSchema);
  assert.ok(body.includes('Buying power'), body);
});

test('metric panel slots resolve from chart labels', () => {
  const content = {
    title: 'Share',
    chart: { labels: ['Dine-in', 'Delivery', 'Catering', 'Retail'], series: [{ values: [32, 24, 18, 26] }] },
  };
  assert.equal(textForSlot('METRIC_A_LABEL', content, { layout_id: 'chart_donut_context_v1' }), 'Dine-in');
  assert.equal(textForSlot('METRIC_B_VALUE', content, { layout_id: 'chart_donut_context_v1' }), '24%');
});
