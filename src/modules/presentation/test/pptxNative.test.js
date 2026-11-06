'use strict';

/**
 * Phase 4: native PPTX output that matches the editor — charts, tables, custom shapes,
 * gradients, glow, text effects, opacity, embed links, notes and the export report.
 */

const assert = require('assert');
const { test } = require('node:test');
const JSZip = require('jszip');
const { editorChartSpec, pptxChartArgs, isColorVibrant } = require('../pptxChart');
const { buildPptxTable } = require('../pptxTable');
const { parsePolygonClipPath, custGeomPoints, dashTypeFor } = require('../pptxShapes');
const { gradFillXml, applyToSlide } = require('../pptxXmlPatches');
const { buildPptxBuffer } = require('../export.service');

const PALETTE = { bg: '#FFFFFF', text: '#0F172A', primary: '#2563EB', secondary: '#F97316', accent: '#14B8A6' };

// ── Charts ────────────────────────────────────────────────────────────────────

test('chart: like the editor — first series only, one vivid colour per bar, value labels', () => {
  const spec = editorChartSpec(
    { chartType: 'bar', labels: ['N', 'S', 'E'], series: [{ name: 'Rev', values: [1, 2, 3] }, { name: 'Cost', values: [9, 9, 9] }] },
    PALETTE
  );
  assert.equal(spec.kind, 'column', 'the editor draws "bar" as vertical columns');
  assert.deepEqual(spec.values, [1, 2, 3]);
  assert.equal(spec.colors.length, 3);
  assert.ok(spec.colors.every(isColorVibrant));
  const args = pptxChartArgs(spec, { ChartType: { bar: 'bar' } }, { x: 0, y: 0, w: 4, h: 3 }, { pt: (p) => p });
  assert.equal(args.options.barDir, 'col');
  assert.equal(args.options.showValue, true);
  assert.equal(args.options.valAxisHidden, true);
  assert.equal(args.data.length, 1);
});

test('chart: horizontal bars, smooth line, donut with % and the editor palette, kpi as text', () => {
  assert.equal(editorChartSpec({ chartType: 'horizontal_bar', labels: ['a'], series: [{ values: [1] }] }, PALETTE).kind, 'bar');
  const line = editorChartSpec({ chartType: 'line', labels: ['a', 'b'], series: [{ values: [1, 2] }] }, PALETTE);
  assert.equal(line.kind, 'line');
  assert.equal(pptxChartArgs(line, {}, { x: 0, y: 0, w: 1, h: 1 }, { pt: (p) => p }).options.lineSmooth, true);
  const donut = editorChartSpec({ chartType: 'doughnut', labels: ['a', 'b'], series: [{ values: [1, 2] }], colors: ['#777777'] }, PALETTE);
  assert.equal(donut.kind, 'donut');
  assert.equal(donut.colors[0], '#3B82F6', 'dull colours fall back to the editor donut palette');
  const donutArgs = pptxChartArgs(donut, {}, { x: 0, y: 0, w: 1, h: 1 }, { pt: (p) => p });
  assert.equal(donutArgs.options.holeSize, 55);
  assert.equal(donutArgs.options.showPercent, true);
  const kpi = editorChartSpec({ chartType: 'kpi', series: [{ values: [87] }], kpiLabel: 'NPS' }, PALETTE);
  assert.deepEqual(kpi.kpi, { value: '87', label: 'NPS' });
});

// ── Tables ────────────────────────────────────────────────────────────────────

const inch = (px) => px / 100;
const pt = (px) => px;

test('table: rebuilt from the measured grid — widths, heights, fills, ink, borders, card', () => {
  const measured = {
    card: { bg: '#FFFFFF', alpha: 0.92, border: { w: 1, color: '#94A3B8', alpha: 0.35 }, radius: 8 },
    table: { x: 8, y: 8, w: 300, h: 60 },
    cols: [200, 100],
    rows: [30, 30],
    cells: [
      [
        { text: 'Name', bg: '#F1F5F9', color: '#111111', fontSize: 10, fontWeight: 700, align: 'left', valign: 'middle', pad: [2, 4, 2, 4], border: Array(4).fill({ w: 1, color: '#E2E8F0' }) },
        { text: 'Score', bg: '#F1F5F9', color: '#111111', fontSize: 10, fontWeight: 700, align: 'right', valign: 'middle', pad: [2, 4, 2, 4], border: Array(4).fill({ w: 1, color: '#E2E8F0' }) },
      ],
      [
        { text: 'Ana', bg: null, color: '#334155', fontSize: 10, fontWeight: 400, align: 'left', valign: 'middle', pad: [2, 4, 2, 4], border: Array(4).fill({ w: 0, color: null }) },
        { text: '9', bg: null, color: '#334155', fontSize: 10, fontWeight: 400, align: 'right', valign: 'middle', pad: [2, 4, 2, 4], border: Array(4).fill({ w: 1, color: '#E2E8F0' }) },
      ],
    ],
  };
  const t = buildPptxTable({ content: {}, box: { x: 1, y: 1, w: 3.16, h: 0.76 }, measured, inch, pt, stageW: 316, stageH: 76 });
  assert.deepEqual(t.options.colW, [2, 1]);
  assert.deepEqual(t.options.rowH, [0.3, 0.3]);
  assert.equal(t.options.x, 1.08);
  assert.equal(t.rows[0][0].options.bold, true);
  assert.equal(t.rows[0][0].options.fill.color, 'F1F5F9');
  assert.equal(t.rows[1][0].options.fill, undefined);
  assert.equal(t.rows[1][1].options.align, 'right');
  assert.equal(t.rows[1][0].options.border[0].type, 'none');
  assert.equal(t.card.fill.transparency, 8);
  assert.equal(t.card.line.transparency, 65);
});

test('table: without a measurement, the editor CSS defaults (header row shaded and bold)', () => {
  const t = buildPptxTable({
    content: { hasHeader: true, rows: [['A', 'B'], ['1', '2']] },
    box: { x: 0, y: 0, w: 4, h: 2 },
    measured: null,
    inch,
    pt,
    stageW: 400,
    stageH: 200,
  });
  assert.equal(t.rows.length, 2);
  assert.equal(t.rows[0][0].options.fill.color, 'F1F5F9');
  assert.equal(t.rows[0][0].options.bold, true);
  assert.equal(t.rows[1][0].options.bold, false);
});

// ── Shapes ────────────────────────────────────────────────────────────────────

test('shapes: % polygons become custom geometry; other clip-paths do not', () => {
  const poly = parsePolygonClipPath('polygon(50% 0%, 100% 100%, 0% 100%)');
  assert.deepEqual(poly, [{ x: 0.5, y: 0 }, { x: 1, y: 1 }, { x: 0, y: 1 }]);
  assert.equal(parsePolygonClipPath('circle(40%)'), null);
  assert.equal(parsePolygonClipPath('polygon(10px 0, 20px 10px, 0 10px)'), null);
  const points = custGeomPoints(poly, { w: 2, h: 1 });
  assert.deepEqual(points[0], { x: 1, y: 0, moveTo: true });
  assert.deepEqual(points.at(-1), { close: true });
  assert.equal(dashTypeFor('dashed'), 'dash');
  assert.equal(dashTypeFor('dotted'), 'sysDot');
  assert.equal(dashTypeFor('solid'), null);
});

// ── XML patches ───────────────────────────────────────────────────────────────

test('gradients: CSS angle → DrawingML angle, stops in order, radial path', () => {
  const xml = gradFillXml({ stops: [{ color: '#FF0000', at: 0 }, { color: '#0000FF', at: 1, alpha: 0.5 }], angle: 180 });
  assert.match(xml, /<a:gs pos="0"><a:srgbClr val="FF0000"\/><\/a:gs><a:gs pos="100000"><a:srgbClr val="0000FF"><a:alpha val="50000"\/><\/a:srgbClr><\/a:gs>/);
  assert.match(xml, /<a:lin ang="5400000"/, 'CSS 180° (to bottom) = DrawingML 90°');
  assert.match(gradFillXml({ stops: [{ color: '#000', at: 0 }, { color: '#fff', at: 1 }], radial: true }), /<a:path path="circle">/);
});

test('patches: shape fill, glow before an existing shadow, text runs in schema order', () => {
  const slide = '<p:sld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="111111"/></a:solidFill></p:bgPr></p:bg><p:spTree>'
    + '<p:sp><p:nvSpPr><p:cNvPr id="2" name="athena-1"></p:cNvPr></p:nvSpPr><p:spPr><a:prstGeom prst="rect"/><a:solidFill><a:srgbClr val="FF0000"/></a:solidFill><a:ln></a:ln><a:effectLst><a:outerShdw/></a:effectLst></p:spPr></p:sp>'
    + '<p:sp><p:nvSpPr><p:cNvPr id="3" name="athena-2"></p:cNvPr></p:nvSpPr><p:spPr/><p:txBody><a:p><a:r><a:rPr lang="en-US" sz="2000"><a:solidFill><a:srgbClr val="222222"/></a:solidFill><a:latin typeface="Inter"/></a:rPr><a:t>Hi</a:t></a:r></a:p></p:txBody></p:sp>'
    + '</p:spTree></p:sld>';
  const out = applyToSlide(slide, [
    { name: 'athena-1', kind: 'shapeGradient', gradient: { stops: [{ color: '#000000', at: 0 }, { color: '#FFFFFF', at: 1 }], angle: 90 } },
    { name: 'athena-1', kind: 'glow', color: '#FACC15', radiusPt: 10, alpha: 0.6 },
    { name: 'athena-2', kind: 'text', outline: { widthPt: 2, color: '#000000' }, shadow: { color: '#000000', alpha: 0.4, blurPt: 3, distPt: 3, angleDeg: 45 }, highlight: '#FEF08A' },
    { kind: 'backgroundGradient', gradient: { stops: [{ color: '#111111', at: 0 }, { color: '#222222', at: 1 }], angle: 160 } },
  ]);
  assert.match(out, /<a:prstGeom prst="rect"\/><a:gradFill[\s\S]*?<\/a:gradFill><a:ln>/, 'gradient in place of the fill, before the line');
  assert.match(out, /<a:effectLst><a:glow rad="127000">[\s\S]*?<\/a:glow><a:outerShdw\/>/, 'glow first in the effect list');
  assert.match(
    out,
    /<a:rPr lang="en-US" sz="2000"><a:ln w="25400">[\s\S]*?<\/a:ln><a:solidFill>[\s\S]*?<\/a:solidFill><a:effectLst><a:outerShdw [\s\S]*?<\/a:effectLst><a:highlight>[\s\S]*?<\/a:highlight><a:latin typeface="Inter"\/><\/a:rPr>/,
    'run: ln, fill, effects, highlight, then fonts'
  );
  assert.match(out, /<p:bg><p:bgPr><a:gradFill[\s\S]*?<\/a:gradFill><a:effectLst\/><\/p:bgPr><\/p:bg>/);
});

// ── A whole deck ──────────────────────────────────────────────────────────────

const P = (x, y, width, height, extra = {}) => ({ x, y, width, height, rotation: 0, opacity: 1, ...extra });

function nativeDeck() {
  return {
    aspectRatio: '16:9',
    themeTokens: { palette: PALETTE, fonts: { heading: 'Inter', body: 'Inter' } },
    slides: [
      {
        id: 's1',
        order: 1,
        content: { notes: 'Speaker note' },
        elements: {
          canvas: { width: 1920, height: 1080 },
          backgroundFill: { type: 'gradient', angle: 160, stops: [{ color: '#1E1B4B', at: 0 }, { color: '#0F766E', at: 1 }] },
          elements: [
            { id: 'grad', type: 'shape', layer: 1, placement: P(100, 100, 400, 300), content: { shape: 'rounded-rect', borderRadius: 20, fill: { type: 'gradient', angle: 90, stops: [{ color: '#F97316', at: 0 }, { color: '#E11D48', at: 1 }] } } },
            { id: 'tri', type: 'shape', layer: 1, placement: P(600, 100, 300, 300, { opacity: 0.5 }), content: { shape: 'triangle-up', fill: '#14B8A6', clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)', effect: { type: 'glow' } } },
            { id: 'dash', type: 'shape', layer: 1, placement: P(1000, 100, 300, 200), content: { shape: 'rect', fill: 'transparent', stroke: '#FFFFFF', strokeWidth: 3, borderStyle: 'dashed' } },
            { id: 'neon', type: 'text', layer: 2, placement: P(100, 500, 800, 120), content: { text: 'Neon heading', fontSize: 40, textEffect: 'neon', neonColor: '#EC4899' } },
            { id: 'shadowed', type: 'text', layer: 2, placement: P(100, 650, 800, 120), content: { text: 'Shadowed', fontSize: 40, textEffect: 'shadow' } },
            { id: 'gtext', type: 'text', layer: 2, placement: P(100, 800, 800, 120), content: { text: 'Gradient text', fontSize: 40, fill: { type: 'gradient', angle: 90, stops: [{ color: '#22D3EE', at: 0 }, { color: '#A78BFA', at: 1 }] } } },
            { id: 'chart', type: 'chart', layer: 2, placement: P(1000, 400, 800, 500), content: { chartType: 'bar', labels: ['A', 'B', 'C'], series: [{ name: 'S', values: [1, 2, 3] }] } },
            { id: 'kpi', type: 'chart', layer: 2, placement: P(1500, 100, 300, 200), content: { chartType: 'kpi', series: [{ values: [42] }], kpiLabel: 'NPS' } },
            { id: 'tbl', type: 'table', layer: 2, placement: P(1000, 900, 800, 160), content: { hasHeader: true, rows: [['A', 'B'], ['1', '2']] } },
            { id: 'curved', type: 'text', layer: 3, placement: P(100, 950, 600, 100), content: { text: 'Curved words', fontSize: 30, textShape: 'curve' } },
            { id: 'video', type: 'embed', layer: 3, placement: P(1400, 950, 400, 100), content: { url: 'https://www.youtube.com/watch?v=abc', title: 'Video' } },
          ],
        },
      },
    ],
  };
}

const PNG_1PX = 'image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

test('a deck: native gradients, custom shape, dashes, text effects, chart, kpi, table, notes, links, report', async () => {
  const report = {};
  const assets = {
    textMetrics: {},
    pictures: {
      s1: {
        curved: { data: PNG_1PX, box: { x: 100, y: 950, width: 600, height: 100 }, reason: 'curved text' },
        video: { data: PNG_1PX, box: { x: 1400, y: 950, width: 400, height: 100 }, reason: 'embed' },
        chart: { data: PNG_1PX, box: { x: 1000, y: 400, width: 800, height: 500 }, reason: 'chart', fallbackOnly: true },
      },
    },
    backgrounds: {},
  };
  const buffer = await buildPptxBuffer(nativeDeck(), { assets, report });
  // PPTX_NATIVE_OUT=file.pptx keeps the file, e.g. to check it against the OOXML schemas.
  if (process.env.PPTX_NATIVE_OUT) require('fs').writeFileSync(process.env.PPTX_NATIVE_OUT, buffer);
  const zip = await JSZip.loadAsync(buffer);
  const xml = await zip.file('ppt/slides/slide1.xml').async('string');

  assert.match(xml, /<p:bg><p:bgPr><a:gradFill/, 'native gradient background');
  assert.ok((xml.match(/<a:gradFill/g) || []).length >= 3, 'background, shape and text gradients');
  assert.match(xml, /<a:custGeom>/, 'polygon triangle is a custom shape');
  assert.match(xml, /<a:glow rad=/, 'glow on the triangle and the neon text');
  assert.match(xml, /<a:prstDash val="dash"\/>/, 'dashed border');
  assert.match(xml, /<a:rPr[^>]*>(?:(?!<\/a:rPr>)[\s\S])*<a:effectLst><a:outerShdw/, 'text shadow on the runs');
  assert.match(xml, /<a:t>42<\/a:t>[\s\S]*<a:t>NPS<\/a:t>/, 'kpi chart as text');
  assert.equal((xml.match(/<p:graphicFrame>/g) || []).length, 2, 'one native chart and one table');
  assert.match(xml, /<a:tbl>/);
  // Two pictures (curved text, embed) — the chart picture is only a fallback.
  assert.equal((xml.match(/<p:pic>/g) || []).length, 2);
  const rels = await zip.file('ppt/slides/_rels/slide1.xml.rels').async('string');
  assert.match(rels, /youtube\.com\/watch\?v=abc/, 'the embed picture links to the video');
  const notesFile = Object.keys(zip.files).find((f) => /notesSlide\d+\.xml$/.test(f));
  const notes = await zip.file(notesFile).async('string');
  assert.match(notes, /Speaker note/);
  assert.match(notes, /Curved words/, 'text drawn as a picture is kept in the notes');
  assert.ok(report.native['custom shape'] >= 1 && report.native.table === 1 && report.native.kpi === 1);
  assert.deepEqual(report.pictures, { 'curved text': 1, embed: 1 });
  assert.ok(report.patches >= 6);
});

test('a cropped photo keeps a native, re-croppable crop (srcRect), not a baked copy', async () => {
  const s3Service = require('../../s3/s3.service');
  const sharp = require('sharp');
  const original = s3Service.getObjectBuffer;
  const photo = await sharp({ create: { width: 400, height: 200, channels: 3, background: '#2563EB' } }).png().toBuffer();
  s3Service.getObjectBuffer = async () => photo;
  try {
    const deck = {
      aspectRatio: '16:9',
      themeTokens: { palette: PALETTE },
      slides: [
        {
          id: 's1',
          order: 1,
          content: {},
          elements: {
            canvas: { width: 1920, height: 1080 },
            elements: [
              { id: 'img', type: 'image', layer: 1, placement: P(100, 100, 600, 400), content: { s3Key: 'k/photo.png', crop: { x: 0.2, y: 0.1, width: 0.5, height: 0.6 } } },
            ],
          },
        },
      ],
    };
    const zip = await JSZip.loadAsync(await buildPptxBuffer(deck));
    const xml = await zip.file('ppt/slides/slide1.xml').async('string');
    assert.match(xml, /<a:srcRect l="20000" r="30000" t="10000" b="30000"\/>/);
    const media = Object.keys(zip.files).find((f) => /^ppt\/media\/.+\.(png|jpe?g)$/.test(f));
    const meta = await sharp(await zip.file(media).async('nodebuffer')).metadata();
    assert.deepEqual([meta.width, meta.height], [400, 200], 'the whole photo is embedded');
  } finally {
    s3Service.getObjectBuffer = original;
  }
});
