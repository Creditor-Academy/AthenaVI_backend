'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { rasterReason, pptxRasterPlan, needsBackgroundPicture } = require('../pptxCapability');

const el = (type, content = {}, extra = {}) => ({ id: `${type}-1`, type, content, ...extra });

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
  assert.match(rasterReason(el('shape', { shape: 'hexagon', clipPath: 'polygon(25% 0%, 75% 0%)' })), /shape hexagon/);
  assert.match(rasterReason(el('shape', { shape: 'banner-wavy' })), /shape banner-wavy/);
  assert.equal(rasterReason(el('shape', { shape: 'rect', fill: { type: 'gradient', stops: [] } })), 'gradient fill');
  assert.equal(rasterReason(el('shape', { shape: 'rect', borderStyle: 'dashed' })), 'dashed border');
  assert.equal(rasterReason(el('shape', { shape: 'device-frame' })), 'device frame');
  assert.equal(rasterReason(el('shape', { shape: 'rect', effect: { type: 'glitch' } })), 'effect glitch');
  assert.equal(rasterReason(el('image', { url: 'u', imageMask: 'circle' })), 'image mask');
  assert.equal(rasterReason(el('image', { url: 'u', filter: 'vintage' })), 'image filter');
  assert.equal(rasterReason(el('image', { url: 'u', borderRadius: 12 })), 'rounded corners');
  assert.equal(rasterReason(el('image', { url: 'u', effect: { type: 'outline' } })), 'effect outline');
  assert.equal(rasterReason(el('text', { text: 'Arc', textShape: 'curve' })), 'curved text');
  assert.equal(rasterReason(el('text', { text: 'Glow', textEffect: 'neon' })), 'text effect neon');
  assert.equal(rasterReason(el('icon', { icon: 'star' })), 'icon / graphic');
  assert.equal(rasterReason(el('embed', { url: 'https://youtu.be/x' })), 'embed');
  // An empty image slot: the editor's placeholder picture, not a grey box.
  assert.equal(rasterReason(el('image', {})), 'image placeholder');
});

test('slide backgrounds that are an image or gradient become a picture', () => {
  assert.equal(needsBackgroundPicture({ elements: { backgroundImage: 'https://x/bg.jpg' } }), true);
  assert.equal(needsBackgroundPicture({ elements: { backgroundFill: { type: 'gradient', stops: [] } } }), true);
  assert.equal(needsBackgroundPicture({ elements: { backgroundGradientStart: '#000', backgroundGradientEnd: '#fff' } }), true);
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
          el('shape', { shape: 'star', clipPath: 'polygon(0 0)', effect: { type: 'shadow' } }, { id: 'star' }),
          el('group', {}, { id: 'g' }),
        ],
      },
    },
  ]);
  assert.equal(plan[0].slideId, 's1');
  assert.equal(plan[0].background, true);
  assert.deepEqual(plan[0].elements.map((e) => e.id), ['star']);
  assert.equal(plan[0].elements[0].margin, 40, 'room for the shadow');
});
