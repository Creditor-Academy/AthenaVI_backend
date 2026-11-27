'use strict';

/**
 * Media-panel inserts (attach asset, upload, stock) must keep the slide's background
 * (CANVAS_FIX_PLAN_25NOV2026, B-2). They used to rebuild the elements doc from
 * version/canvas/elements only, so the background colour, gradient or image disappeared.
 */
const assert = require('assert');
const { test } = require('node:test');
const { getElementsDoc, applyImageToElements } = require('../slideMedia.service');

const BACKGROUND = {
  backgroundColor: '#C9DAF8',
  backgroundGradientStart: '#E0F2FE',
  backgroundGradientEnd: '#FFFFFF',
  backgroundGradientAngle: 135,
  backgroundGradientKind: 'linear',
  backgroundGradientStops: [{ color: '#E0F2FE', at: 0 }, { color: '#FFFFFF', at: 1 }],
  backgroundFill: { type: 'gradient', kind: 'linear', angle: 135 },
  backgroundImage: 'https://bucket.s3.us-east-1.amazonaws.com/workspace/w/assets/bg.png',
  backgroundImageFit: 'cover',
};

function slideWith(extra = {}) {
  return {
    id: 's1',
    elements: {
      version: 1,
      canvas: { width: 1920, height: 1080 },
      elements: [{ id: 'txt1', type: 'text', layer: 1, content: { text: 'Title' } }],
      ...BACKGROUND,
      ...extra,
    },
  };
}

const image = {
  url: 'https://bucket.s3.us-east-1.amazonaws.com/workspace/w/assets/new.png',
  s3Key: 'workspace/w/assets/new.png',
  assetId: 'asset-1',
};

test('the doc handed to a Media insert keeps every background key', () => {
  const doc = getElementsDoc(slideWith());
  for (const [key, value] of Object.entries(BACKGROUND)) {
    assert.deepStrictEqual(doc[key], value, key);
  }
});

test('attaching a new image keeps the background and adds the image', () => {
  const slide = slideWith();
  const next = applyImageToElements(getElementsDoc(slide), image);
  for (const [key, value] of Object.entries(BACKGROUND)) {
    assert.deepStrictEqual(next[key], value, key);
  }
  assert.strictEqual(next.elements.length, 2);
  assert.strictEqual(next.elements[1].type, 'image');
  assert.strictEqual(next.elements[1].content.s3Key, image.s3Key);
  // The stored slide is not changed in place.
  assert.strictEqual(slide.elements.elements.length, 1);
});

test('filling an existing image keeps the background', () => {
  const slide = slideWith({
    elements: [{ id: 'img1', type: 'image', layer: 1, placement: { x: 0, y: 0, width: 400, height: 300 }, content: {} }],
  });
  const next = applyImageToElements(getElementsDoc(slide), { ...image, elementId: 'img1' });
  assert.strictEqual(next.backgroundColor, BACKGROUND.backgroundColor);
  assert.strictEqual(next.backgroundImage, BACKGROUND.backgroundImage);
  assert.strictEqual(next.elements.length, 1);
  assert.strictEqual(next.elements[0].content.s3Key, image.s3Key);
});

test('version and canvas still get defaults when the stored doc has none', () => {
  const doc = getElementsDoc({ elements: { elements: [], backgroundColor: '#000000' } });
  assert.strictEqual(doc.version, 1);
  assert.ok(doc.canvas && doc.canvas.width > 0 && doc.canvas.height > 0);
  assert.strictEqual(doc.backgroundColor, '#000000');
});
