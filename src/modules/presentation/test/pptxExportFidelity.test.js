'use strict';

const assert = require('assert');
const { test } = require('node:test');
const JSZip = require('jszip');
const sharp = require('sharp');
const { buildPptxBuffer } = require('../export.service');
const { buildDeckHtml, imageBufferToPptxImage, sniffImageMime, svgMarkupToPngBuffer } = require('../slideHtml');

const SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="currentColor"/></svg>';

function deckWith(elements, aspectRatio = '16:9', canvas = { width: 1920, height: 1080 }) {
  return {
    aspectRatio,
    themeTokens: { palette: { bg: '#FFFFFF', text: '#111111', primary: '#2563EB' } },
    slides: [{ id: 's1', order: 1, content: {}, elements: { canvas, elements } }],
  };
}

async function slideXml(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  return {
    zip,
    slide: await zip.file('ppt/slides/slide1.xml').async('string'),
    presentation: await zip.file('ppt/presentation.xml').async('string'),
  };
}

test('pptx text: editor-stage px font size converts to points (72px on 900px stage = 76.8pt on 13.333in)', async () => {
  const buffer = await buildPptxBuffer(
    deckWith([
      { id: 't', type: 'text', layer: 1, placement: { x: 0, y: 0, width: 800, height: 200 }, content: { text: 'Hello', fontSize: 72 } },
    ])
  );
  const { slide } = await slideXml(buffer);
  assert.match(slide, /sz="7680"/, 'expected 76.8pt (sz=7680) — same relative size as the 900px editor stage');
  assert.doesNotMatch(slide, /sz="3600"/, 'must not scale against the 1920 placement canvas');
});

test('pdf html: font size is scaled from the 900px editor stage to the 1920 canvas', async () => {
  const html = await buildDeckHtml(
    deckWith([
      { id: 't', type: 'text', layer: 1, placement: { x: 0, y: 0, width: 800, height: 200 }, content: { text: 'Hi', fontSize: 72 } },
    ]),
    { injectFonts: false }
  );
  // 72 × 1920 / 900 = 153.6
  assert.match(html, /font-size:153\.6px/);
});

test('pptx graphic: inline SVG is rasterized into an embedded image, not a placeholder', async () => {
  const buffer = await buildPptxBuffer(
    deckWith([
      { id: 'g', type: 'graphic', layer: 1, placement: { x: 100, y: 100, width: 400, height: 400 }, content: { svg: SVG } },
    ])
  );
  const { zip, slide } = await slideXml(buffer);
  const media = Object.keys(zip.files).filter((name) => name.startsWith('ppt/media/'));
  assert.ok(media.length >= 1, 'graphic should embed a media file');
  assert.match(slide, /<p:pic>/);
  assert.doesNotMatch(slide, />graphic</, 'grey "graphic" placeholder must not be emitted');
});

test('pptx 4:3 deck: slide size and element placement use 10in width', async () => {
  const buffer = await buildPptxBuffer(
    deckWith(
      [{ id: 'r', type: 'shape', layer: 1, placement: { x: 800, y: 0, width: 800, height: 600 }, content: { shape: 'rect', fill: '#000000' } }],
      '4:3',
      { width: 1600, height: 1200 }
    )
  );
  const { slide, presentation } = await slideXml(buffer);
  assert.match(presentation, /<p:sldSz cx="9144000" cy="6858000"/, '4:3 slide is 10in x 7.5in');
  // x = 800/1600 * 10in = 5in = 4572000 EMU
  assert.match(slide, /<a:off x="4572000" y="0"\/>/);
});

test('pptx shapes: rounded-rect and pill export as roundRect', async () => {
  const buffer = await buildPptxBuffer(
    deckWith([
      { id: 'a', type: 'shape', layer: 1, placement: { x: 0, y: 0, width: 400, height: 100 }, content: { shape: 'pill', fill: '#000000' } },
      { id: 'b', type: 'shape', layer: 2, placement: { x: 0, y: 200, width: 400, height: 100 }, content: { shape: 'rounded-rect', fill: '#000000' } },
    ])
  );
  const { slide } = await slideXml(buffer);
  assert.strictEqual((slide.match(/prstGeom prst="roundRect"/g) || []).length, 2);
});

test('image payload carries a MIME header pptxgenjs accepts; SVG/WebP rasterize to PNG', async () => {
  const png = await sharp({ create: { width: 4, height: 2, channels: 3, background: '#ff0000' } }).png().toBuffer();
  const jpeg = await sharp(png).jpeg().toBuffer();
  const webp = await sharp(png).webp().toBuffer();

  assert.strictEqual(sniffImageMime(png), 'image/png');
  assert.strictEqual(sniffImageMime(jpeg), 'image/jpeg');
  assert.strictEqual(sniffImageMime(webp), 'image/webp');
  assert.strictEqual(sniffImageMime(Buffer.from(SVG)), 'image/svg+xml');

  const fromJpeg = await imageBufferToPptxImage(jpeg);
  assert.ok(fromJpeg.data.startsWith('image/jpeg;base64,'));
  assert.deepStrictEqual([fromJpeg.width, fromJpeg.height], [4, 2]);

  const fromWebp = await imageBufferToPptxImage(webp);
  assert.ok(fromWebp.data.startsWith('image/png;base64,'));

  const fromSvg = await imageBufferToPptxImage(Buffer.from(SVG));
  assert.ok(fromSvg.data.startsWith('image/png;base64,'));
});

test('pdf html: page size follows deck aspect; inline SVG is rasterized, never injected raw', async () => {
  const html = await buildDeckHtml(
    deckWith(
      [{ id: 'g', type: 'graphic', layer: 1, placement: { x: 0, y: 0, width: 100, height: 100 }, content: { svg: SVG } }],
      '4:3',
      { width: 1600, height: 1200 }
    ),
    { injectFonts: false }
  );
  assert.match(html, /@page \{ size: 10in 7\.5in;/);
  assert.match(html, /src="data:image\/png;base64,/);
  assert.doesNotMatch(html, /<svg/);
});

test('svgMarkupToPngBuffer: ignores non-SVG input and rasterizes scriptable SVG inertly', async () => {
  assert.strictEqual(await svgMarkupToPngBuffer('<div>nope</div>'), null);
  const hostile = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" onload="alert(1)"><script>alert(1)</script><rect width="10" height="10"/></svg>';
  const out = await svgMarkupToPngBuffer(hostile, { width: 20, height: 20 });
  assert.ok(out && sniffImageMime(out) === 'image/png');
});
