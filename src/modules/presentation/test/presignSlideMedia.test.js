'use strict';

const { afterEach, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const s3Service = require('../../s3/s3.service');
const {
  attachPresignedMedia,
  isPresignableElement,
} = require('../presignSlideMedia');

const originalSign = s3Service.getPresignedGetUrl;

afterEach(() => {
  s3Service.getPresignedGetUrl = originalSign;
});

function mockSign() {
  const calls = [];
  s3Service.getPresignedGetUrl = async (key) => {
    calls.push(key);
    return `https://signed.example/${key}`;
  };
  return calls;
}

describe('isPresignableElement', () => {
  it('covers image, icon, and shape media the canvas actually paints', () => {
    assert.equal(isPresignableElement({ type: 'text', content: { url: 'x' } }), false);
    assert.equal(isPresignableElement({ type: 'image', content: {} }), true);
    assert.equal(isPresignableElement({ type: 'icon', content: { s3Key: 'k' } }), true);
    assert.equal(
      isPresignableElement({ type: 'shape', content: { deviceFrame: 'phone', screenUrl: 'u' } }),
      true
    );
    assert.equal(isPresignableElement({ type: 'shape', content: { fill: '#111' } }), false);
  });
});

describe('attachPresignedMedia', () => {
  it('signs icon and device-frame URLs, not only type=image', async () => {
    const calls = mockSign();
    const slide = await attachPresignedMedia({
      elements: {
        elements: [
          { id: 'i1', type: 'icon', content: { s3Key: 'icons/a.png', src: 'stale' } },
          {
            id: 'd1',
            type: 'shape',
            content: { deviceFrame: 'phone', s3Key: 'screens/b.jpg', screenUrl: 'stale' },
          },
          { id: 't1', type: 'text', content: { text: 'Hi' } },
        ],
      },
    });

    assert.deepEqual(calls.sort(), ['icons/a.png', 'screens/b.jpg']);
    assert.equal(slide.elements.elements[0].content.url, 'https://signed.example/icons/a.png');
    assert.equal(slide.elements.elements[0].content.src, 'https://signed.example/icons/a.png');
    assert.equal(slide.elements.elements[1].content.screenUrl, 'https://signed.example/screens/b.jpg');
    assert.equal(slide.elements.elements[2].content.text, 'Hi');
  });

  it('reuses a sign cache so the same key is signed once', async () => {
    const calls = mockSign();
    const cache = new Map();
    await attachPresignedMedia(
      {
        elements: {
          elements: [
            { id: 'a', type: 'image', content: { s3Key: 'shared.jpg' } },
            { id: 'b', type: 'image', content: { s3Key: 'shared.jpg' } },
          ],
        },
      },
      cache
    );
    assert.deepEqual(calls, ['shared.jpg']);
  });
});
