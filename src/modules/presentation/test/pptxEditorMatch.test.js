'use strict';

/**
 * Exports that look like the editor (reported: AI decks changed text colours, manual decks came
 * out messy): every CSS colour form, the colours the editor actually drew, the elements the
 * editor actually draws, rounded rects, area charts, and no grey boxes for missing images.
 */

const assert = require('assert');
const { test } = require('node:test');
const JSZip = require('jszip');
const { parseColor, hex6 } = require('../pptxColor');
const { editorRuns, drawnRunColors, buildPptxText } = require('../pptxText');
const { withStageElements } = require('../exportRenderer.service');
const { editorChartSpec, pptxChartArgs } = require('../pptxChart');
const { buildPptxBuffer } = require('../export.service');

const PALETTE = { bg: '#FFFFFF', text: '#0F172A', primary: '#2563EB', secondary: '#F97316', accent: '#14B8A6' };
const P = (x, y, width, height) => ({ x, y, width, height });

function deckOf(elements, extra = {}) {
  return {
    aspectRatio: '16:9',
    themeTokens: { palette: PALETTE },
    slides: [{ id: 's1', order: 1, content: {}, elements: { canvas: { width: 1920, height: 1080 }, elements }, ...extra }],
  };
}

async function slideXml(deck, options) {
  const zip = await JSZip.loadAsync(await buildPptxBuffer(deck, options));
  return zip.file('ppt/slides/slide1.xml').async('string');
}

// ── Colours ───────────────────────────────────────────────────────────────────

test('colours: every CSS form the editor stores becomes a 6-digit hex (pptxgenjs paints the rest black)', () => {
  assert.deepEqual(parseColor('#FFFFFFCC'), { hex: 'FFFFFF', alpha: 0xcc / 255 });
  assert.deepEqual(parseColor('#fa0'), { hex: 'FFAA00', alpha: 1 });
  assert.deepEqual(parseColor('white'), { hex: 'FFFFFF', alpha: 1 });
  assert.deepEqual(parseColor('rgba(255, 0, 0, 0.5)'), { hex: 'FF0000', alpha: 0.5 });
  assert.deepEqual(parseColor('rgb(0 128 255 / 25%)'), { hex: '0080FF', alpha: 0.25 });
  assert.equal(parseColor('hsl(120, 100%, 50%)').hex, '00FF00');
  assert.equal(parseColor('linear-gradient(90deg, #112233 0%, #445566 100%)').hex, '112233');
  assert.equal(parseColor('transparent').alpha, 0);
  assert.equal(parseColor('var(--x)'), null);
  assert.equal(hex6('nonsense', '#334455'), '334455');
});

// ── Runs ──────────────────────────────────────────────────────────────────────

test('runs: duplicated runs are cut back to the text; runs that miss text fall back to it', () => {
  const doubled = editorRuns({ text: 'Hello', runs: [{ text: 'Hel' }, { text: 'loHello' }] });
  assert.equal(doubled.map((r) => r.text).join(''), 'Hello');
  const repeated = editorRuns({ text: '', runs: [{ text: 'AbcAbc' }] });
  assert.equal(repeated.map((r) => r.text).join(''), 'Abc');
  assert.equal(editorRuns({ text: 'Full title', runs: [{ text: 'Full' }] }), null);
  assert.equal(editorRuns({ text: 'x' }), null);
});

test('runs: the drawn (contrast-adjusted) run colours win, by character position', () => {
  const pieces = [{ text: 'Dark ' }, { text: 'Accent' }];
  const colorAt = drawnRunColors([{ text: 'Dark ', color: '#111111' }, { text: 'Accent', color: '#8B5E3C' }], pieces);
  assert.equal(colorAt(0), '#111111');
  assert.equal(colorAt(5), '#8B5E3C');
  assert.equal(drawnRunColors([{ text: 'Other', color: '#000000' }], pieces), null, 'text that does not line up is ignored');

  const { runs } = buildPptxText({
    content: { text: 'Dark Accent', runs: [{ text: 'Dark ', color: '#FFFFFF' }, { text: 'Accent', color: '#FFFFFF' }] },
    box: { x: 0, y: 0, w: 4, h: 1 },
    slideWidthIn: 13.333,
    color: '0F172A',
    runColor: () => 'FFFFFF',
    measured: { fontSize: 22, runs: [{ text: 'Dark ', color: '#111111' }, { text: 'Accent', color: '#8B5E3C' }] },
  });
  assert.deepEqual(runs.map((r) => r.options.color), ['111111', '8B5E3C']);
});

// ── What the editor draws ─────────────────────────────────────────────────────

test('stage elements replace the saved ones; a background element is flagged for the background picture', () => {
  const slide = {
    id: 's1',
    elements: { canvas: { width: 960, height: 540 }, elements: [{ id: 'bg', type: 'image', content: { useAsBackground: true } }] },
  };
  const stage = { canvas: { width: 1920, height: 1080 }, elements: [{ id: 'card', type: 'shape' }] };
  const out = withStageElements(slide, stage);
  assert.deepEqual(out.elements.elements, stage.elements);
  assert.deepEqual(out.elements.canvas, stage.canvas);
  assert.equal(out.elements.backgroundFromElement, true);
  assert.equal(withStageElements(slide, undefined), slide, 'no stage → the saved slide');
});

test('text: a plain-colour fill is not the ink (the editor only paints gradient fills into text)', async () => {
  const xml = await slideXml(
    deckOf([{ id: 't', type: 'text', placement: P(100, 100, 800, 100), content: { text: 'Eyebrow', color: '#222222', fill: '#E8A8A0' } }])
  );
  assert.match(xml, /<a:srgbClr val="222222"/);
  assert.doesNotMatch(xml, /E8A8A0/);
});

test('text: the colour the editor drew (measured) wins over the stored one', async () => {
  const xml = await slideXml(
    deckOf([{ id: 't', type: 'text', placement: P(100, 100, 800, 100), content: { text: '16.6x', color: '#E8A8A0' } }]),
    { assets: { textMetrics: { s1: { t: { fontSize: 40, color: '#1C1917', runs: [] } } }, pictures: {}, backgrounds: {} } }
  );
  assert.match(xml, /<a:srgbClr val="1C1917"/);
});

test('shapes: a rect with a border radius is a rounded rect, like the editor', async () => {
  const xml = await slideXml(
    deckOf([{ id: 'r', type: 'shape', placement: P(100, 100, 500, 300), content: { shape: 'rect', fill: '#E8A8A0', borderRadius: 30 } }])
  );
  assert.match(xml, /<a:prstGeom prst="roundRect">/);
});

test('charts: an area chart is a fill plus a smooth line with dots (combo), like the editor', () => {
  const spec = editorChartSpec({ chartType: 'area', labels: ['a', 'b'], series: [{ values: [1, 2] }], colors: ['#E8A8A0'] }, PALETTE);
  const args = pptxChartArgs(spec, {}, { x: 0, y: 0, w: 4, h: 3 }, { pt: (p) => p });
  assert.deepEqual(args.combo.map((c) => c.type), ['area', 'line']);
  assert.equal(args.combo[1].options.lineDataSymbol, 'circle');
  assert.equal(args.combo[1].options.lineSmooth, true);
});

test('images: a picture that cannot be loaded is skipped (the editor shows nothing), not a grey box', async () => {
  const s3Service = require('../../s3/s3.service');
  const original = s3Service.getObjectBuffer;
  s3Service.getObjectBuffer = async () => {
    throw new Error('NoSuchKey');
  };
  try {
    const report = {};
    const xml = await slideXml(
      deckOf([{ id: 'img', type: 'image', placement: P(100, 100, 600, 400), content: { s3Key: 'missing/photo.png' } }]),
      { report }
    );
    assert.doesNotMatch(xml, /<p:sp>/, 'no placeholder shape');
    assert.doesNotMatch(xml, /<p:pic>/);
    assert.equal(report.missing?.image, 1);
  } finally {
    s3Service.getObjectBuffer = original;
  }
});
