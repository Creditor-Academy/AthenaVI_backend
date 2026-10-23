'use strict';

/**
 * Documents which canvas element types export to PPTX/PDF vs editor-only behavior.
 * Update when export.service addElementsToPptxSlide changes.
 */

const assert = require('assert');
const { test } = require('node:test');

const EXPORT_COVERAGE = {
  text: { pptx: 'native', pdf: 'html', notes: 'verticalAlign + align mapped; editor fitText shrink differs from PPT' },
  textbox: { pptx: 'native', pdf: 'html', notes: 'same as text' },
  image: { pptx: 'native', pdf: 'html', notes: 'S3 key preferred; cover fit approximated' },
  icon: { pptx: 'native', pdf: 'html', notes: 'same as image' },
  graphic: { pptx: 'rasterized-svg', pdf: 'rasterized-svg', notes: 'inline SVG → PNG; matches editor intent' },
  shape: { pptx: 'native', pdf: 'html', notes: 'gradients + roundRect; some flow shapes → rect' },
  chart: { pptx: 'native-chart', pdf: 'simple-html-bars', notes: 'PPT uses pptxgenjs; premium/donut styling differs from React renderer' },
  table: { pptx: 'native-table', pdf: 'placeholder', notes: 'PDF export shows "table" placeholder only' },
  embed: { pptx: 'link-box', pdf: 'link-box', notes: 'no iframe in file; title + URL only' },
  group: { pptx: 'skipped', pdf: 'skipped', notes: 'children export individually via childIds' },
  link: { pptx: 'unsupported', pdf: 'unsupported', notes: 'falls through — not in export switch' },
};

test('export element coverage matrix is stable', () => {
  assert.ok(EXPORT_COVERAGE.chart.pptx === 'native-chart');
  assert.ok(EXPORT_COVERAGE.table.pdf.includes('placeholder'));
  assert.ok(EXPORT_COVERAGE.group.pptx === 'skipped');
});
