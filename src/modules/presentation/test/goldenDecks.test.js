'use strict';

/**
 * The golden export decks (test/fixtures/export, built by
 * scripts/presentation-eval/build-golden-decks.js) stay usable: every deck builds a PPTX
 * with one slide per deck slide, element ids are unique, and every picture it references
 * is in fixtures/export/assets. The visual comparison itself is
 * scripts/presentation-eval/export-fidelity.js (needs a browser and LibreOffice).
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { test } = require('node:test');
const JSZip = require('jszip');
const s3Service = require('../../s3/s3.service');
const { buildPptxBuffer } = require('../export.service');

const DIR = path.join(__dirname, 'fixtures/export');

// S3 → the fixture pictures (as in export-fidelity.js); other keys are missing.
s3Service.getObjectBuffer = async (key) => {
  if (!String(key).startsWith('golden/')) throw Object.assign(new Error(`NoSuchKey: ${key}`), { name: 'NoSuchKey' });
  return fs.promises.readFile(path.join(DIR, 'assets', path.basename(key)));
};
const decks = fs.readdirSync(DIR).filter((f) => f.endsWith('.json'));

test('there are golden decks', () => {
  assert.deepEqual(decks.sort(), [
    'ai-dark.json',
    'ai-editorial.json',
    'ai-light.json',
    'forty-slides.json',
    'four-three.json',
    'kitchen-sink.json',
  ]);
});

for (const file of decks) {
  test(`golden deck ${file}: valid and builds a PPTX`, async () => {
    const deck = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8'));
    assert.ok(['16:9', '4:3'].includes(deck.aspectRatio));
    for (const slide of deck.slides) {
      const ids = slide.elements.elements.map((e) => e.id);
      assert.equal(new Set(ids).size, ids.length, `${slide.id}: duplicate element ids`);
      for (const el of slide.elements.elements) {
        const key = el.content?.s3Key;
        if (key) assert.ok(fs.existsSync(path.join(DIR, 'assets', path.basename(key))), `${slide.id}/${el.id}: missing ${key}`);
      }
    }
    const zip = await JSZip.loadAsync(await buildPptxBuffer(deck));
    const slides = Object.keys(zip.files).filter((f) => /^ppt\/slides\/slide\d+\.xml$/.test(f));
    assert.equal(slides.length, deck.slides.length);
    const withImages = deck.slides.filter((s) => s.elements.elements.some((e) => e.type === 'image' && e.content?.s3Key));
    if (withImages.length) {
      assert.ok(Object.keys(zip.files).some((f) => /^ppt\/media\/.*\.(jpe?g|png)$/.test(f)), 'pictures are embedded');
    }
  });
}
