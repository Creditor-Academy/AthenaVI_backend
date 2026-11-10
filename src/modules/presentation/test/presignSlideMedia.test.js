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

describe('library graphics (SVG icons) in the editor and in exports', () => {
  const { inlineGraphicSvgsForExport } = require('../presignSlideMedia');
  const originalGet = s3Service.getObjectBuffer;
  const originalBucket = process.env.AWS_S3_BUCKET;
  const GRAPHIC = 'https://b.s3.us-east-1.amazonaws.com/presentations/_system/graphics/abc/original.svg?X-Amz-Date=20261019T061645Z&X-Amz-Expires=3600';
  const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill="currentColor" d="M0 0h16v16z"/></svg>';

  afterEach(() => {
    s3Service.getObjectBuffer = originalGet;
    if (originalBucket === undefined) delete process.env.AWS_S3_BUCKET;
    else process.env.AWS_S3_BUCKET = originalBucket;
  });

  it('a graphic gets a fresh link (its stored one expires after an hour)', async () => {
    mockSign();
    assert.equal(isPresignableElement({ type: 'graphic', content: { src: GRAPHIC } }), true);
    const slide = await attachPresignedMedia({
      elements: { elements: [{ id: 'g', type: 'graphic', content: { src: GRAPHIC, colorMode: 'recolorable' } }] },
    });
    const { content } = slide.elements.elements[0];
    assert.equal(content.src, 'https://signed.example/presentations/_system/graphics/abc/original.svg');
    assert.equal(content.colorMode, 'recolorable');
  });

  it('export: icons and graphics never take the slide hero photo', () => {
    const deck = enrichDeckMediaKeysForExport({
      slides: [
        {
          id: 's1',
          imageRef: { s3Key: 'hero/key.jpg' },
          elements: {
            elements: [
              { id: 'g', type: 'graphic', content: { src: GRAPHIC } },
              { id: 'g2', type: 'graphic', content: {} },
              { id: 'i', type: 'icon', content: {} },
            ],
          },
        },
      ],
    });
    const [g, g2, i] = deck.slides[0].elements.elements;
    assert.equal(g.content.s3Key, 'presentations/_system/graphics/abc/original.svg');
    assert.equal(g2.content.s3Key, undefined);
    assert.equal(i.content.s3Key, undefined);
  });

  it('export: a library SVG is read from the bucket once and put on the element', async () => {
    process.env.AWS_S3_BUCKET = 'b';
    const reads = [];
    s3Service.getObjectBuffer = async (key) => {
      reads.push(key);
      return Buffer.from(SVG);
    };
    const deck = await inlineGraphicSvgsForExport({
      slides: [
        { id: 's1', elements: { elements: [{ id: 'a', type: 'graphic', content: { src: GRAPHIC } }] } },
        {
          id: 's2',
          elements: {
            elements: [
              { id: 'b', type: 'graphic', content: { src: GRAPHIC } },
              { id: 'c', type: 'graphic', content: { svg: '<svg id="own"/>' } },
              { id: 'd', type: 'graphic', content: { src: 'https://cdn.example.com/x.svg' } },
              { id: 'e', type: 'image', content: { src: GRAPHIC } },
            ],
          },
        },
      ],
    });
    assert.deepEqual(reads, ['presentations/_system/graphics/abc/original.svg'], 'one read per file');
    const [b, c, d, e] = deck.slides[1].elements.elements;
    assert.equal(deck.slides[0].elements.elements[0].content.svg, SVG);
    assert.equal(b.content.svg, SVG);
    assert.equal(c.content.svg, '<svg id="own"/>', 'markup already on the element is kept');
    assert.equal(d.content.svg, undefined, 'another site is never read');
    assert.equal(e.content.svg, undefined, 'only graphics');
  });

  it('export: an unreadable or non-SVG file leaves the graphic as it was', async () => {
    process.env.AWS_S3_BUCKET = 'b';
    s3Service.getObjectBuffer = async () => Buffer.from('<Error>AccessDenied</Error>');
    const deck = await inlineGraphicSvgsForExport({
      slides: [{ id: 's', elements: { elements: [{ id: 'a', type: 'graphic', content: { src: GRAPHIC } }] } }],
    });
    assert.equal(deck.slides[0].elements.elements[0].content.svg, undefined);
    s3Service.getObjectBuffer = async () => {
      throw new Error('NoSuchKey');
    };
    const again = await inlineGraphicSvgsForExport({
      slides: [{ id: 's', elements: { elements: [{ id: 'a', type: 'graphic', content: { src: GRAPHIC } }] } }],
    });
    assert.equal(again.slides[0].elements.elements[0].content.svg, undefined);
  });
});
