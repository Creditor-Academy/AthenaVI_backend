'use strict';

/**
 * A slide the user emptied exports blank (CANVAS_FIX_PLAN B-3): no ghost title or deleted image.
 * Slides that never had a canvas keep the legacy title / image fallback.
 */
const assert = require('assert');
const { test } = require('node:test');
const { isUserEmptiedSlide, buildDeckHtml } = require('../slideHtml');

const ghostImage = { url: 'https://bucket.s3.us-east-1.amazonaws.com/w/assets/deleted.png', s3Key: 'w/assets/deleted.png' };
const emptied = {
  id: 's1',
  order: 1,
  manuallyEdited: true,
  content: { title: 'Untitled Presentation' },
  imageRef: ghostImage,
  elements: { version: 1, canvas: { width: 1920, height: 1080 }, elements: [], backgroundColor: '#C9DAF8' },
};
const neverCanvas = { id: 's2', order: 2, manuallyEdited: false, content: { title: 'Generated title' }, elements: null };

test('isUserEmptiedSlide: only edited slides with an empty canvas', () => {
  assert.strictEqual(isUserEmptiedSlide(emptied), true);
  assert.strictEqual(isUserEmptiedSlide(neverCanvas), false);
  assert.strictEqual(isUserEmptiedSlide({ ...emptied, manuallyEdited: false }), false, 'never edited: keeps the fallback');
  assert.strictEqual(isUserEmptiedSlide({ ...emptied, elements: { ...emptied.elements, elements: [{ id: 'a', type: 'text' }] } }), false);
});

test('HTML export: an emptied slide has no title or deleted image; a never-canvas slide keeps its title', async () => {
  const html = await buildDeckHtml({ aspectRatio: '16:9', themeTokens: { palette: {} }, slides: [emptied, neverCanvas] });
  assert.ok(!html.includes('Untitled Presentation'), 'no ghost title');
  assert.ok(!html.includes('deleted.png'), 'no ghost image');
  assert.ok(html.includes('Generated title'), 'legacy slides keep their content');
});
