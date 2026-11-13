'use strict';

const assert = require('assert');
const { test } = require('node:test');
const JSZip = require('jszip');
const {
  buildPptxText,
  resolveFontPx,
  letterSpacingPoints,
  bulletFor,
  applyTextTransform,
} = require('../pptxText');
const { buildPptxBuffer } = require('../export.service');

const BOX = { x: 1, y: 1, w: 5, h: 1 };
const SLIDE_W = 13.333;
const build = (content, extra = {}) =>
  buildPptxText({
    content,
    box: BOX,
    slideWidthIn: SLIDE_W,
    color: '111111',
    fontFace: 'Inter',
    runColor: () => 'FF0000',
    ...extra,
  });

test('text boxes have zero insets unless the element has padding (PowerPoint adds 0.1in otherwise)', () => {
  assert.deepEqual(build({ text: 'Hi' }).options.margin, [0, 0, 0, 0]);
  // padding 12 / paddingX 6 stage px → points on a 13.333in slide (×1.0666)
  assert.deepEqual(build({ text: 'Hi', padding: 12, paddingX: 6 }).options.margin, [6.4, 6.4, 12.8, 12.8]);
  assert.equal(build({ text: 'Hi' }).options.fit, 'none');
});

test('font size: the size the editor drew (fit-to-box), never larger than the stored size', () => {
  assert.equal(resolveFontPx({ fontSize: 40 }, { fontSize: 20.8 }), 20.8);
  assert.equal(resolveFontPx({ fontSize: 40 }, { fontSize: 44 }), 40);
  assert.equal(resolveFontPx({ fontSize: 40 }, null), 40);
  assert.equal(resolveFontPx({}, null), 22, 'the editor default');
  const { runs, fontPt } = build({ text: 'Hi', fontSize: 40 }, { measured: { fontSize: 20 } });
  assert.equal(fontPt, 21.3);
  assert.equal(runs[0].options.fontSize, 21.3);
});

test('line height is exact, like CSS (default 1.25)', () => {
  assert.equal(build({ text: 'Hi', fontSize: 30 }).options.lineSpacing, 40);
  assert.equal(build({ text: 'Hi', fontSize: 30, lineHeight: 1.5 }).options.lineSpacing, 48);
});

test('lists: one paragraph per line with the editor marker; numbered lists number', () => {
  const { runs } = build({ text: 'One\nTwo\nThree', listType: 'bullet' });
  assert.deepEqual(runs.map((r) => r.text), ['One', 'Two', 'Three']);
  assert.deepEqual(runs.map((r) => Boolean(r.options.breakLine)), [true, true, false]);
  assert.equal(runs[0].options.bullet.characterCode, '2022');
  assert.deepEqual(bulletFor('numbered'), { type: 'number' });
  assert.equal(bulletFor('check').characterCode, '2713');
  assert.equal(bulletFor(null), null);
  // Without a list, lines are still separate paragraphs but have no bullets.
  const plain = build({ text: 'a\nb' }).runs;
  assert.equal(plain[0].options.bullet, undefined);
  assert.equal(plain.length, 2);
});

test('uppercase, underline, strike, italic and links', () => {
  const { runs } = build({
    text: 'see www.example.com now',
    textTransform: 'uppercase',
    underline: true,
    strikethrough: true,
    italic: true,
  });
  assert.equal(runs.map((r) => r.text).join(''), 'SEE WWW.EXAMPLE.COM NOW');
  assert.ok(runs.every((r) => r.options.underline?.style === 'sng' && r.options.strike && r.options.italic));
  const link = runs.find((r) => r.options.hyperlink);
  assert.equal(link.options.hyperlink.url, 'https://www.example.com');
  assert.equal(link.options.color, '111111', 'links keep the text colour');
  assert.equal(applyTextTransform('hello big world', 'capitalize'), 'Hello Big World');
});

test('runs keep their own colour and weight', () => {
  const { runs } = build({
    text: 'Bold red',
    runs: [
      { text: 'Bold ', bold: true },
      { text: 'red', color: '#ff0000' },
    ],
  });
  assert.equal(runs[0].options.bold, true);
  assert.equal(runs[1].options.color, 'FF0000');
  assert.equal(runs[0].options.color, '111111');
});

test('letter spacing: a number is stage px (CSS), em is relative to the font size', () => {
  assert.equal(letterSpacingPoints(3, 20, SLIDE_W), 3.2);
  assert.equal(letterSpacingPoints('0.1em', 20, SLIDE_W), 2);
  assert.equal(letterSpacingPoints(null, 20, SLIDE_W), null);
});

test('PPTX XML: zero insets, no autofit, bullets, caps text, exact spacing, measured size', async () => {
  const deck = {
    aspectRatio: '16:9',
    themeTokens: { palette: { bg: '#0F172A', text: '#FFFFFF' } },
    slides: [
      {
        id: 's1',
        order: 1,
        content: {},
        elements: {
          canvas: { width: 1920, height: 1080 },
          backgroundColor: '#0F172A',
          elements: [
            {
              id: 't1',
              type: 'text',
              layer: 1,
              placement: { x: 100, y: 100, width: 800, height: 200 },
              content: { text: 'One\nTwo', fontSize: 40, listType: 'bullet', textTransform: 'uppercase' },
            },
          ],
        },
      },
    ],
  };
  const buffer = await buildPptxBuffer(deck, {
    assets: { textMetrics: { s1: { t1: { fontSize: 20, color: '#ABCDEF' } } } },
  });
  const xml = await (await JSZip.loadAsync(buffer)).file('ppt/slides/slide1.xml').async('string');
  assert.match(xml, /<a:bodyPr[^>]*lIns="0"[^>]*tIns="0"[^>]*rIns="0"[^>]*bIns="0"/);
  // No autofit element = PowerPoint leaves the (already fitted) size alone.
  assert.doesNotMatch(xml, /normAutofit|spAutoFit/);
  assert.equal((xml.match(/<a:buChar char="&#x2022;"/g) || []).length, 2);
  assert.match(xml, /<a:lnSpc><a:spcPts val="2660"\/>/, 'exact 1.25 × 21.3pt');
  // PowerPoint: uppercase is All Caps on the run, the typed text stays as typed (editable).
  assert.match(xml, /<a:t>One<\/a:t>/);
  assert.equal((xml.match(/<a:rPr[^>]*cap="all"/g) || []).length, 2);
  assert.match(xml, /sz="2130"/, 'measured 20 stage px → 21.3pt');
  assert.match(xml, /<a:srgbClr val="ABCDEF"/, 'the colour the editor drew');
  // The slide background colour is written (pptxgenjs ignores it when passed to addSlide).
  assert.match(xml, /<p:bg><p:bgPr><a:solidFill><a:srgbClr val="0F172A"/);

  // Google Slides: the text itself is uppercased (All Caps may not survive the import).
  const forSlides = await buildPptxBuffer(deck, {
    target: 'google-slides',
    assets: { textMetrics: { s1: { t1: { fontSize: 20, color: '#ABCDEF' } } } },
  });
  const slidesXml = await (await JSZip.loadAsync(forSlides)).file('ppt/slides/slide1.xml').async('string');
  assert.match(slidesXml, /<a:t>ONE<\/a:t>/);
  assert.doesNotMatch(slidesXml, /cap="all"/);
});

test('outlined shapes (transparent fill) have no fill, not a black one', async () => {
  const shape = (id, fill, extra = {}) => ({
    id,
    type: 'shape',
    layer: 1,
    placement: { x: 100, y: 100, width: 300, height: 200 },
    content: { shape: 'rect', fill, stroke: '#475569', strokeWidth: 3, ...extra },
  });
  const deck = {
    aspectRatio: '16:9',
    themeTokens: { palette: { bg: '#FFFFFF' } },
    slides: [
      {
        id: 's1',
        order: 1,
        content: {},
        elements: {
          canvas: { width: 1920, height: 1080 },
          elements: [shape('a', 'transparent'), shape('b', 'rgba(0,0,0,0)'), shape('c', '#2563EB', { stroke: 'transparent' })],
        },
      },
    ],
  };
  const xml = await (await JSZip.loadAsync(await buildPptxBuffer(deck))).file('ppt/slides/slide1.xml').async('string');
  assert.doesNotMatch(xml, /<a:srgbClr val="000000"/, 'nothing painted black');
  assert.equal((xml.match(/<a:noFill\/>/g) || []).length, 2, 'two outlined shapes without fill');
  assert.match(xml, /<a:srgbClr val="2563EB"/);
  assert.match(xml, /<a:srgbClr val="2563EB"\/><\/a:solidFill><a:ln><\/a:ln>/, 'a transparent stroke draws no line');
});

test('graphics are rasterized at 2× but never larger than 2048px on the long edge', () => {
  const { svgRasterSize } = require('../export.service');
  assert.deepEqual(svgRasterSize({ width: 46, height: 46 }), { width: 92, height: 92 });
  assert.deepEqual(svgRasterSize({ width: 1920, height: 1080 }), { width: 2048, height: 1152 });
  assert.deepEqual(svgRasterSize({}), { width: 200, height: 200 });
});
