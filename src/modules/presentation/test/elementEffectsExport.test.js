'use strict';

const assert = require('assert');
const { test } = require('node:test');
const JSZip = require('jszip');
const { buildPptxBuffer } = require('../export.service');
const { buildDeckHtml } = require('../slideHtml');
const { elementEffectCssFilter, elementEffectPptxShadow } = require('../elementEffects');

function deckWith(elements) {
  return {
    aspectRatio: '16:9',
    themeTokens: { palette: { bg: '#FFFFFF', text: '#111111', primary: '#2563EB' } },
    slides: [{ id: 's1', order: 1, content: {}, elements: { canvas: { width: 1800, height: 1012 }, elements } }],
  };
}

const shape = (id, effect) => ({
  id,
  type: 'shape',
  layer: 1,
  placement: { x: 100, y: 100, width: 400, height: 300 },
  content: { shape: 'rect', fill: '#2563EB', ...(effect ? { effect } : {}) },
});

async function slideXml(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  return zip.file('ppt/slides/slide1.xml').async('string');
}

test('effects: css filter matches the editor (stage px scaled to the canvas)', () => {
  assert.equal(elementEffectCssFilter({ effect: { type: 'blur', amount: 4 } }, { scale: 2 }), 'blur(8px)');
  assert.equal(
    elementEffectCssFilter({ effect: { type: 'shadow', offset: 10, angle: 90, blur: 5, color: '#ff0000', transparency: 25 } }),
    'drop-shadow(0px 10px 5px rgba(255, 0, 0, 0.75))'
  );
  assert.equal(elementEffectCssFilter({ effect: { type: 'nope' } }), '');
  assert.equal(elementEffectCssFilter({ effect: null }), '');
});

test('effects: pptx shadow only for effects PowerPoint can show', () => {
  const shadow = elementEffectPptxShadow(
    { effect: { type: 'shadow', offset: 10, angle: 360, blur: 5, color: '#FF0000', transparency: 25 } },
    { ptPerStagePx: 0.8 }
  );
  assert.deepEqual(shadow, { type: 'outer', color: 'FF0000', opacity: 0.75, blur: 4, offset: 8, angle: 0 });
  assert.equal(elementEffectPptxShadow({ effect: { type: 'glow' } }).offset, 0);
  for (const type of ['outline', 'glitch', 'blur']) {
    assert.equal(elementEffectPptxShadow({ effect: { type } }), undefined, type);
  }
});

test('pdf html: an element with an effect gets the filter; others do not', async () => {
  const html = await buildDeckHtml(
    deckWith([shape('a', { type: 'shadow', offset: 9, angle: 0, blur: 0, color: '#000000', transparency: 0 }), shape('b')]),
    { injectFonts: false }
  );
  // 1800 wide canvas / 900 stage = ×2.
  assert.ok(html.includes('filter:drop-shadow(18px 0px 0px #000000)'), 'scaled shadow on the element');
  assert.equal((html.match(/filter:/g) || []).length, 1, 'only the element with an effect');
});

test('pptx: a shape with a shadow effect exports a PowerPoint shadow', async () => {
  const xml = await slideXml(
    await buildPptxBuffer(deckWith([shape('a', { type: 'shadow' }), shape('b', { type: 'outline' }), shape('c')]))
  );
  assert.equal((xml.match(/<a:outerShdw /g) || []).length, 1, 'one shadow: outline has no PowerPoint form');
});
