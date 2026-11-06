'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { rasterReason, pptxRasterPlan, needsBackgroundPicture } = require('../pptxCapability');

const el = (type, content = {}, extra = {}) => ({ id: `${type}-1`, type, content, ...extra });

test('native in PowerPoint: polygon shapes, gradients, dashed borders, text effects, glow', () => {
  assert.equal(rasterReason(el('shape', { shape: 'hexagon', clipPath: 'polygon(25% 0%, 75% 0%, 100% 50%, 75% 100%, 25% 100%, 0% 50%)' })), null);
  assert.equal(rasterReason(el('shape', { shape: 'rect', fill: { type: 'gradient', stops: [] } })), null);
  assert.equal(rasterReason(el('shape', { shape: 'rect', borderStyle: 'dashed' })), null);
  assert.equal(rasterReason(el('shape', { shape: 'rect', effect: { type: 'glow' } })), null);
  for (const effect of ['shadow', 'lift', 'outline', 'hollow', 'neon', 'background']) {
    assert.equal(rasterReason(el('text', { text: 'x', textEffect: effect })), null, effect);
  }
  assert.equal(rasterReason(el('text', { text: 'x', fill: { type: 'gradient', stops: [] } })), null);
});

test('for Google Slides, gradients, glow text and hollow text are pictures', () => {
  const gs = { target: 'google-slides' };
  assert.equal(rasterReason(el('shape', { shape: 'rect', fill: { type: 'gradient', stops: [] } }), gs), 'gradient fill');
  assert.equal(rasterReason(el('text', { text: 'x', fill: { type: 'gradient', stops: [] } }), gs), 'gradient text');
  assert.equal(rasterReason(el('text', { text: 'x', textEffect: 'hollow' }), gs), 'text effect hollow');
  assert.equal(rasterReason(el('text', { text: 'x', textEffect: 'shadow' }), gs), null);
  assert.equal(needsBackgroundPicture({ elements: { backgroundFill: { type: 'gradient', stops: [] } } }, gs), true);
});

test('editable when PowerPoint can draw it: text, plain shapes, plain photos, charts, tables', () => {
  assert.equal(rasterReason(el('text', { text: 'Hi', listType: 'bullet' })), null);
  assert.equal(rasterReason(el('shape', { shape: 'rounded-rect', fill: '#2563EB', effect: { type: 'shadow' } })), null);
  assert.equal(rasterReason(el('shape', { shape: 'circle', fill: '#F97316' })), null);
  assert.equal(rasterReason(el('image', { url: 'https://x/y.jpg', crop: { x: 0.1 } })), null);
  assert.equal(rasterReason(el('chart', { chartType: 'bar' })), null);
  assert.equal(rasterReason(el('table', { rows: [['a']] })), null);
  assert.equal(rasterReason(el('group')), null);
});

test('a picture when PowerPoint would draw it wrong or not at all', () => {
  // A clip-path that isn't a % polygon, or a shape with no native outline.
  assert.match(rasterReason(el('shape', { shape: 'blob', clipPath: 'circle(40% at 50% 50%)' })), /shape blob/);
  assert.match(rasterReason(el('shape', { shape: 'banner-wavy' })), /shape banner-wavy/);
  assert.equal(rasterReason(el('shape', { shape: 'rect', borderStyle: 'double' })), 'double border');
  assert.equal(rasterReason(el('shape', { shape: 'device-frame' })), 'device frame');
  assert.equal(rasterReason(el('shape', { shape: 'rect', effect: { type: 'glitch' } })), 'effect glitch');
  assert.equal(rasterReason(el('image', { url: 'u', imageMask: { type: 'circle' } })), 'image mask');
  assert.equal(rasterReason(el('image', { url: 'u', imageMask: 'circle' })), 'image mask');
  assert.equal(rasterReason(el('image', { url: 'u', imageMask: { type: 'none' } })), null);
  assert.equal(rasterReason(el('image', { url: 'u', filter: 'vintage' })), 'image filter');
  assert.equal(rasterReason(el('image', { url: 'u', borderRadius: 12 })), 'rounded corners');
  assert.equal(rasterReason(el('image', { url: 'u', effect: { type: 'outline' } })), 'effect outline');
  assert.equal(rasterReason(el('text', { text: 'Arc', textShape: 'curve' })), 'curved text');
  assert.equal(rasterReason(el('text', { text: 'Echo', textEffect: 'echo' })), 'text effect echo');
  assert.equal(rasterReason(el('text', { text: 'Glitch', textEffect: 'glitch' })), 'text effect glitch');
  assert.equal(rasterReason(el('icon', { icon: 'star' })), 'icon / graphic');
  assert.equal(rasterReason(el('embed', { url: 'https://youtu.be/x' })), 'embed');
  // An empty image slot: the editor's placeholder picture, not a grey box.
  assert.equal(rasterReason(el('image', {})), 'image placeholder');
});

test('slide background images are pictures; gradients are native in PowerPoint', () => {
  assert.equal(needsBackgroundPicture({ elements: { backgroundImage: 'https://x/bg.jpg' } }), true);
  assert.equal(needsBackgroundPicture({ elements: { backgroundFill: { type: 'gradient', stops: [] } } }), false);
  assert.equal(needsBackgroundPicture({ elements: { backgroundColor: '#123456' } }), false);
});

test('plan: per slide, the elements to capture (with room for effects) and the background', () => {
  const plan = pptxRasterPlan([
    {
      id: 's1',
      elements: {
        backgroundImage: 'https://x/bg.jpg',
        elements: [
          el('text', { text: 'Hi' }, { id: 't' }),
          el('shape', { shape: 'blob', clipPath: 'circle(40%)', effect: { type: 'shadow' } }, { id: 'star' }),
          el('chart', { chartType: 'bar' }, { id: 'chart' }),
          el('group', {}, { id: 'g' }),
        ],
      },
    },
  ]);
  assert.equal(plan[0].slideId, 's1');
  assert.equal(plan[0].background, true);
  assert.deepEqual(plan[0].elements.map((e) => e.id), ['star', 'chart']);
  assert.equal(plan[0].elements[0].margin, 40, 'room for the shadow');
  assert.equal(plan[0].elements[1].fallbackOnly, true, 'a chart picture is only a fallback');
});
