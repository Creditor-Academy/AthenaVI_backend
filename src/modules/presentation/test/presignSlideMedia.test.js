'use strict';

const { afterEach, describe, it } = require('node:test');
const assert = require('node:assert/strict');
const s3Service = require('../../s3/s3.service');
const {
  attachPresignedMedia,
  isPresignableElement,
  s3UrlKey,
  enrichDeckMediaKeysForExport,
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

describe('external images keep their own URL', () => {
  const STOCK = 'https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?w=1200';

  it('s3UrlKey: S3 URLs give a key, any other host gives null', () => {
    assert.equal(s3UrlKey('https://my-bucket.s3.us-east-1.amazonaws.com/ppt/a%20b.png'), 'ppt/a b.png');
    assert.equal(s3UrlKey('https://s3.us-east-1.amazonaws.com/my-bucket/ppt/c.png'), 'ppt/c.png');
    assert.equal(s3UrlKey(STOCK), null);
    assert.equal(s3UrlKey('https://cdn.example.com/ppt/d.png'), null);
    assert.equal(s3UrlKey('not a url'), null);
  });

  it('export: a stock photo is not given a fake S3 key (or the slide hero image)', () => {
    const deck = enrichDeckMediaKeysForExport({
      slides: [
        {
          id: 's1',
          imageRef: { s3Key: 'hero/key.jpg' },
          elements: {
            elements: [
              { id: 'stock', type: 'image', content: { url: STOCK } },
              { id: 'own', type: 'image', content: { url: 'https://b.s3.us-east-1.amazonaws.com/ppt/x.jpg' } },
              { id: 'empty', type: 'image', content: {} },
            ],
          },
        },
      ],
    });
    const [stock, own, empty] = deck.slides[0].elements.elements;
    assert.equal(stock.content.s3Key, undefined);
    assert.equal(own.content.s3Key, 'ppt/x.jpg');
    assert.equal(empty.content.s3Key, 'hero/key.jpg', 'an element with no picture still gets the hero');
  });

  it('presign: a stock photo URL is left alone, an S3 URL is signed', async () => {
    const calls = mockSign();
    const slide = await attachPresignedMedia({
      elements: {
        elements: [
          { id: 'stock', type: 'image', content: { url: STOCK } },
          { id: 'own', type: 'image', content: { url: 'https://b.s3.us-east-1.amazonaws.com/ppt/x.jpg' } },
        ],
      },
    });
    assert.deepEqual(calls, ['ppt/x.jpg']);
    assert.equal(slide.elements.elements[0].content.url, STOCK);
    assert.equal(slide.elements.elements[1].content.url, 'https://signed.example/ppt/x.jpg');
  });
});
