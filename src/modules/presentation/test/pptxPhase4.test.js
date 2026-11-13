'use strict';

// Phase 4 completion: curved library shapes, lines and masked / rounded photos as native
// geometry, native groups, text that grows to fit (Canva-style), per-run sizes, All Caps,
// slides with no elements drawn like the editor, and the export report.

const assert = require('assert');
const { test, before } = require('node:test');
const JSZip = require('jszip');
const sharp = require('sharp');

// A real picture for every image element, without the network (stubbed before export.service
// takes its reference).
const slideHtml = require('../slideHtml');

let photo = null;
slideHtml.fetchImageForPptx = async () => photo;

const {
  clampRadii,
  roundedBoxPath,
  clipPathToPolygon,
  pathToCustGeomXml,
  isSquareBox,
} = require('../pptxShapes');
const { orderForGroups, wrapGroup } = require('../pptxGroups');
const { rasterReason } = require('../pptxCapability');
const { pptxReportSummary } = require('../exportJob.util');
const { buildPptxBuffer } = require('../export.service');

before(async () => {
  const buf = await sharp({ create: { width: 400, height: 200, channels: 3, background: '#3366cc' } }).png().toBuffer();
  photo = { data: `image/png;base64,${buf.toString('base64')}`, width: 400, height: 200 };
});

const slideXml = async (buffer, n = 1) => (await JSZip.loadAsync(buffer)).file(`ppt/slides/slide${n}.xml`).async('string');

function deckWith(elements, extra = {}) {
  return {
    id: 'd1',
    aspectRatio: '16:9',
    themeTokens: { palette: { bg: '#FFFFFF', text: '#111111', primary: '#2563EB' } },
    slides: [{ id: 's1', order: 1, content: {}, elements: { canvas: { width: 1920, height: 1080 }, elements }, ...extra }],
  };
}

// ── Geometry ──────────────────────────────────────────────────────────────────

test('border radius: radii too big for the box shrink together, as the browser does', () => {
  // A 280 × 140 box asking for 999px top corners (an arch): both scale to half the width.
  const [tl, tr, br, bl] = clampRadii([[999, 999], [999, 999], [0, 0], [0, 0]], 280, 140);
  assert.ok(Math.abs(tl[0] - 140) < 0.01 && Math.abs(tr[0] - 140) < 0.01, `${tl} ${tr}`);
  assert.deepEqual([br, bl], [[0, 0], [0, 0]]);
  assert.equal(isSquareBox([[0, 0], [0, 0], [0, 0], [0, 0]]), true);
});

test('a rounded box becomes four curves; a semicircle has two', () => {
  const pill = roundedBoxPath([[50, 50], [50, 50], [50, 50], [50, 50]], 200, 100);
  assert.equal(pill.filter((s) => s.cubic).length, 4);
  const semi = roundedBoxPath([[140, 140], [140, 140], [0, 0], [0, 0]], 280, 140);
  assert.equal(semi.filter((s) => s.cubic).length, 2);
  // The path stays inside the box.
  const coords = semi.flatMap((s) => s.move || s.line || s.cubic || []);
  assert.ok(coords.every((v) => v >= -1e-9 && v <= 1 + 1e-9));
  // An inset (border inside the box) moves the outline in.
  const inset = roundedBoxPath([[0, 0], [0, 0], [0, 0], [0, 0]], 100, 100, { inset: 5 });
  assert.deepEqual(inset[0].move, [0.05, 0.05]);
  assert.match(pathToCustGeomXml(pill), /^<a:custGeom>[\s\S]*<a:cubicBezTo>[\s\S]*<a:close\/>[\s\S]*<\/a:custGeom>$/);
});

test('picture masks: the oval mask is an ellipse cut by the box; polygons and circles too', () => {
  // oval (side right): ellipse(88% 96% at 100% 50%) — starts 12% in from the left.
  const oval = clipPathToPolygon('ellipse(88% 96% at 100% 50%)', 800, 600);
  const xs = oval.map((p) => p.x);
  const ys = oval.map((p) => p.y);
  assert.ok(Math.abs(Math.min(...xs) - 0.12) < 0.005, `left edge ${Math.min(...xs)}`);
  assert.ok(Math.max(...xs) <= 1 && Math.min(...ys) >= 0 && Math.max(...ys) <= 1, 'clipped to the box');
  const hex = clipPathToPolygon('polygon(50% 0%, 93% 25%, 93% 75%, 50% 100%, 7% 75%, 7% 25%)', 300, 300);
  assert.equal(hex.length, 6);
  const circle = clipPathToPolygon('circle(50% at 50% 50%)', 200, 200);
  assert.ok(circle.length > 100);
  assert.equal(clipPathToPolygon('inset(10px)', 100, 100), null);
});

test('raster plan: measured box shapes, lines and masked photos stay native', () => {
  const cloud = { id: 'c', type: 'shape', content: { shape: 'cloud-1' } };
  assert.equal(rasterReason(cloud), 'shape cloud-1', 'without a measurement it is a picture');
  assert.equal(rasterReason(cloud, { measuredShape: { kind: 'box', radii: [[1, 1]] } }), null);
  assert.equal(rasterReason({ type: 'shape', content: { shape: 'line-dashed' } }, { measuredShape: { kind: 'line' } }), null);
  const oval = { type: 'image', content: { url: 'https://x/p.png', imageMask: { type: 'oval' } } };
  assert.equal(rasterReason(oval), 'image mask');
  const frame = { kind: 'media', w: 800, h: 600, clipPath: 'ellipse(88% 96% at 100% 50%)', radii: [[0, 0], [0, 0], [0, 0], [0, 0]], borderWidth: 0 };
  assert.equal(rasterReason(oval, { measuredShape: frame }), null);
  assert.equal(rasterReason(oval, { measuredShape: { ...frame, borderWidth: 2 } }), 'image border');
  const filtered = { type: 'image', content: { url: 'https://x/p.png', filter: 'grayscale' } };
  assert.equal(rasterReason(filtered, { measuredShape: frame }), 'image filter', 'filters stay pictures');
});

// ── Groups ────────────────────────────────────────────────────────────────────

test('groups: kept together, moved together when nothing between them overlaps, else split', () => {
  const el = (id, x, groupId) => ({ id, groupId, box: { x, y: 0, w: 10, h: 10 } });
  const together = orderForGroups([el('a', 0, 'g'), el('b', 20, 'g'), el('c', 40)]);
  assert.deepEqual(together.groups, [{ groupId: 'g', ids: ['a', 'b'] }]);
  // 'x' sits between the members in layer order but overlaps neither: members move together.
  const lifted = orderForGroups([el('a', 0, 'g'), el('x', 100), el('b', 20, 'g')]);
  assert.deepEqual(lifted.order.map((e) => e.id), ['x', 'a', 'b']);
  assert.equal(lifted.groups.length, 1);
  // 'y' sits between them and covers 'a': moving would change the slide, so no group.
  const blocked = orderForGroups([el('a', 0, 'g'), el('y', 5), el('b', 20, 'g')]);
  assert.deepEqual(blocked.groups, []);
  assert.deepEqual(blocked.split, ['g']);
  assert.deepEqual(blocked.order.map((e) => e.id), ['a', 'y', 'b']);
});

test('wrapGroup puts adjacent objects in a <p:grpSp> spanning them', () => {
  const obj = (name, x) =>
    `<p:sp><p:nvSpPr><p:cNvPr id="${x}" name="${name}"/></p:nvSpPr><p:spPr><a:xfrm><a:off x="${x * 100}" y="0"/><a:ext cx="100" cy="50"/></a:xfrm></p:spPr></p:sp>`;
  const xml = `<p:spTree>${obj('a', 2)}${obj('b', 3)}</p:spTree>`;
  const out = wrapGroup(xml, ['a', 'b'], 'Group g');
  assert.match(out, /<p:grpSp><p:nvGrpSpPr><p:cNvPr id="4" name="Group g"\/>/);
  assert.match(out, /<a:off x="200" y="0"\/><a:ext cx="200" cy="50"\/><a:chOff x="200" y="0"\/><a:chExt cx="200" cy="50"\/>/);
  assert.equal(wrapGroup(`<p:spTree>${obj('a', 2)}<p:sp>other</p:sp>${obj('b', 3)}</p:spTree>`, ['a', 'b']).includes('grpSp'), false, 'not adjacent → unchanged');
});

// ── Built PPTX ────────────────────────────────────────────────────────────────

test('PPTX: a measured cloud shape is native custom geometry with curves; a dashed line is a native line', async () => {
  const deck = deckWith([
    { id: 'cloud', type: 'shape', layer: 1, placement: { x: 100, y: 100, width: 400, height: 300 }, content: { shape: 'cloud-1', fill: '#2563EB' } },
    { id: 'ring', type: 'shape', layer: 2, placement: { x: 600, y: 100, width: 300, height: 300 }, content: { shape: 'ring', fill: 'transparent', stroke: '#2563EB', strokeWidth: 14 } },
    { id: 'line', type: 'shape', layer: 3, placement: { x: 100, y: 600, width: 800, height: 40 }, content: { shape: 'line-dashed', fill: '#2563EB' } },
  ]);
  const shapeMetrics = {
    s1: {
      cloud: { kind: 'box', w: 200, h: 150, borderWidth: 0, radii: [[100, 90], [100, 90], [100, 60], [100, 60]] },
      ring: { kind: 'box', w: 150, h: 150, borderWidth: 7, borderStyle: 'solid', borderColor: '#2563EB', radii: [[75, 75], [75, 75], [75, 75], [75, 75]] },
      line: { kind: 'line', w: 400, h: 0, borderWidth: 4, borderStyle: 'dashed', borderColor: '#2563EB', line: { y: 0.5, x0: 0, x1: 1 } },
    },
  };
  const xml = await slideXml(await buildPptxBuffer(deck, { assets: { shapeMetrics } }));
  assert.equal((xml.match(/<a:custGeom>/g) || []).length, 2, 'cloud and ring');
  assert.ok((xml.match(/<a:cubicBezTo>/g) || []).length >= 8);
  assert.match(xml, /<a:prstGeom prst="line">/);
  assert.match(xml, /prstDash val="dash"/);
  // The ring: no fill, its border as the line.
  assert.match(xml, /<a:noFill\/><a:ln w="\d+"[^>]*><a:solidFill><a:srgbClr val="2563EB"/);
});

test('PPTX: a photo with an oval mask is a native picture cut to the oval', async () => {
  const deck = deckWith([
    { id: 'p', type: 'image', layer: 1, placement: { x: 900, y: 0, width: 1020, height: 1080 }, content: { url: 'https://cdn.test/photo.png', imageMask: { type: 'oval', side: 'right' } } },
  ]);
  const shapeMetrics = { s1: { p: { kind: 'media', w: 478, h: 506, borderWidth: 0, clipPath: 'ellipse(88% 96% at 100% 50%)', radii: [[0, 0], [0, 0], [0, 0], [0, 0]] } } };
  const xml = await slideXml(await buildPptxBuffer(deck, { assets: { shapeMetrics } }));
  const pic = xml.slice(xml.indexOf('<p:pic>'), xml.indexOf('</p:pic>'));
  assert.ok(pic, 'a picture');
  assert.match(pic, /<a:custGeom>[\s\S]*<a:lnTo>/);
  assert.doesNotMatch(pic, /<a:prstGeom/);
});

test('PPTX: text longer than its box keeps every line and grows the box (Canva-style)', async () => {
  const deck = deckWith([
    { id: 't', type: 'text', layer: 1, slotId: 'BODY', placement: { x: 100, y: 100, width: 800, height: 200 }, content: { text: 'a\nb\nc\nd', fontSize: 30 } },
  ]);
  const textMetrics = { s1: { t: { fontSize: 30, color: '#111111', contentHeight: 150, frameHeight: 75 } } };
  const xml = await slideXml(await buildPptxBuffer(deck, { assets: { textMetrics } }));
  assert.match(xml, /<a:spAutoFit\/>/, 'Resize shape to fit text');
  assert.equal((xml.match(/<a:t>[abcd]<\/a:t>/g) || []).length, 4, 'every line kept');
  const sp = xml.slice(xml.indexOf('<p:sp>'));
  const cy = Number(/<a:ext cx="\d+" cy="(\d+)"/.exec(sp)[1]);
  assert.ok(Math.abs(cy - 2 * 200 * (7.5 / 1080) * 914400) < 2000, `box doubled: ${cy}`);
});

test('PPTX: a run drawn at its own size keeps that size', async () => {
  const deck = deckWith([
    {
      id: 't',
      type: 'text',
      layer: 1,
      placement: { x: 100, y: 100, width: 800, height: 200 },
      content: { text: 'Big small', fontSize: 40, runs: [{ text: 'Big ' }, { text: 'small', fontSize: 20 }] },
    },
  ]);
  const textMetrics = {
    s1: { t: { fontSize: 40, color: '#111111', runs: [{ text: 'Big ', fontSize: 40 }, { text: 'small', fontSize: 20 }] } },
  };
  const xml = await slideXml(await buildPptxBuffer(deck, { assets: { textMetrics } }));
  const sizes = [...xml.matchAll(/<a:rPr[^>]*sz="(\d+)"[^>]*>[\s\S]*?<a:t>([^<]*)<\/a:t>/g)].map((m) => [m[2], Number(m[1])]);
  const big = sizes.find(([t]) => t.startsWith('Big'))[1];
  const small = sizes.find(([t]) => t === 'small')[1];
  assert.ok(Math.abs(big / small - 2) < 0.05, JSON.stringify(sizes));
});

test('PPTX: grouped elements become one native group; overlapping in-between elements keep them apart', async () => {
  const deck = deckWith([
    { id: 'a', type: 'shape', layer: 1, groupId: 'g1', placement: { x: 100, y: 100, width: 200, height: 200 }, content: { shape: 'rect', fill: '#FF0000' } },
    { id: 'b', type: 'text', layer: 2, groupId: 'g1', placement: { x: 100, y: 320, width: 400, height: 80 }, content: { text: 'Label', fontSize: 30 } },
    { id: 'g1', type: 'group', layer: 2, childIds: ['a', 'b'], placement: { x: 100, y: 100, width: 400, height: 300 }, content: {} },
    { id: 'c', type: 'shape', layer: 3, groupId: 'g2', placement: { x: 1000, y: 100, width: 200, height: 200 }, content: { shape: 'rect', fill: '#00FF00' } },
    { id: 'cover', type: 'shape', layer: 4, placement: { x: 1050, y: 150, width: 100, height: 100 }, content: { shape: 'rect', fill: '#0000FF' } },
    { id: 'd', type: 'shape', layer: 5, groupId: 'g2', placement: { x: 1100, y: 150, width: 200, height: 200 }, content: { shape: 'rect', fill: '#000000' } },
  ]);
  const report = {};
  const xml = await slideXml(await buildPptxBuffer(deck, { report }));
  assert.equal((xml.match(/<p:grpSp>/g) || []).length, 1, 'g1 only');
  const group = xml.slice(xml.indexOf('<p:grpSp>'), xml.indexOf('</p:grpSp>'));
  assert.match(group, /FF0000/);
  assert.match(group, /<a:t>Label<\/a:t>/);
  assert.equal(report.groups.native, 1);
});

test('PPTX: a slide with no elements is drawn the way the editor shows it', async () => {
  const deck = {
    id: 'd1',
    aspectRatio: '16:9',
    themeTokens: { palette: { bg: '#FFFFFF', text: '#111111' } },
    slides: [
      {
        id: 's1',
        order: 1,
        title: 'Quarterly Review',
        description: ['Revenue up', 'Costs down'],
        content: { title: 'Quarterly Review' },
        imageRef: { url: 'https://cdn.test/hero.png' },
        elements: { canvas: { width: 1920, height: 1080 }, elements: [] },
      },
    ],
  };
  const fallbackMetrics = {
    s1: {
      title: { text: 'Quarterly Review', box: { x: 102, y: 102, width: 1700, height: 102 }, fontSize: 40, lineHeight: 48, bold: true, color: '#0F172A', opacity: 1, fontFamily: 'Inter', marginBottom: 16 },
      list: {
        box: { x: 102, y: 240, width: 1300, height: 140 },
        indent: 32,
        items: [
          { text: 'Revenue up', box: { x: 170, y: 240, width: 1200, height: 50 }, fontSize: 20, lineHeight: 24, bold: false, color: '#334155', opacity: 0.9, fontFamily: 'Inter', marginBottom: 12 },
          { text: 'Costs down', box: { x: 170, y: 300, width: 1200, height: 50 }, fontSize: 20, lineHeight: 24, bold: false, color: '#334155', opacity: 0.9, fontFamily: 'Inter', marginBottom: 12 },
        ],
      },
      visual: { box: { x: 102, y: 420, width: 1716, height: 560 }, borderColor: '#334155', borderWidth: 2, borderStyle: 'dashed', radius: 12, opacity: 0.5 },
      image: { box: { x: 106, y: 424, width: 1708, height: 552 }, radius: 8, opacity: 0.5 },
    },
  };
  const xml = await slideXml(await buildPptxBuffer(deck, { assets: { fallbackMetrics } }));
  assert.match(xml, /<a:t>Quarterly Review<\/a:t>/);
  assert.equal((xml.match(/<a:buChar/g) || []).length, 2, 'the description as a bullet list');
  assert.match(xml, /prstDash val="dash"/, 'the dashed image frame');
  const pic = xml.slice(xml.indexOf('<p:pic>'), xml.indexOf('</p:pic>'));
  assert.match(pic, /<a:custGeom>/, 'the image keeps its rounded corners');
  assert.match(pic, /alphaModFix amt="50000"/, 'at half opacity, as in the editor');
});

test('report: plain words for what became a picture, the fonts inside, groups and grown text', () => {
  const summary = pptxReportSummary({
    native: { text: 5, shape: 3 },
    text: { 'grown to fit': 2 },
    pictures: { 'curved text': 1, 'image filter': 2, 'icon / graphic': 3, 'text effect glitch': 1 },
    fonts: { embedded: ['Inter (regular)', 'Inter (bold)', 'Nunito (regular)'], unavailable: [] },
    groups: { native: 2 },
  });
  assert.equal(summary.editable, 8);
  assert.deepEqual(summary.pictures, [
    { label: 'icons and graphics', count: 3 },
    { label: 'photo filters', count: 2 },
    { label: 'curved text', count: 1 },
    { label: 'text effects', count: 1 },
  ]);
  assert.deepEqual(summary.fonts, ['Inter', 'Nunito']);
  assert.equal(summary.groups, 2);
  assert.equal(summary.grownText, 2);
});

test('library clip shapes the element doesn\'t store (arrow line) use the clip-path the editor drew', async () => {
  const arrow = { id: 'arrow', type: 'shape', layer: 1, placement: { x: 100, y: 100, width: 400, height: 48 }, content: { shape: 'line-arrow', fill: '#2563EB' } };
  const clip = 'polygon(0% 40%, 72% 40%, 72% 20%, 100% 50%, 72% 80%, 72% 60%, 0% 60%)';
  assert.equal(rasterReason(arrow), 'shape line-arrow');
  assert.equal(rasterReason(arrow, { measuredShape: { kind: 'clip', clipPath: clip } }), null);
  const xml = await slideXml(await buildPptxBuffer(deckWith([arrow]), { assets: { shapeMetrics: { s1: { arrow: { kind: 'clip', clipPath: clip, w: 187, h: 22 } } } } }));
  assert.match(xml, /<a:custGeom>/);
  assert.equal((xml.match(/<a:lnTo>/g) || []).length, 6, 'the seven-point arrow');
});

test('photos: kept at ~200 ppi of their shown size; opaque PNGs become JPEG, transparent ones stay PNG', async () => {
  const { shrinkPhotoForPptx } = require('../pptxMedia');
  // Noise compresses badly, so the PNG is big like an AI photo.
  const noise = (channels) => {
    const raw = require('crypto').randomBytes(2400 * 1600 * channels);
    // Transparent: make the alpha channel really vary.
    if (channels === 4) for (let i = 3; i < raw.length; i += 4) raw[i] = raw[i] & 0x7f;
    return sharp(raw, { raw: { width: 2400, height: 1600, channels } }).png().toBuffer();
  };
  const opaque = await noise(3);
  const photoIn = { data: `image/png;base64,${opaque.toString('base64')}`, width: 2400, height: 1600 };
  // Shown 3in × 2in, cover: 200 ppi → 600px wide.
  const out = await shrinkPhotoForPptx(photoIn, { w: 3, h: 2 }, { fit: 'cover' });
  assert.ok(out.shrunk);
  assert.match(out.data, /^image\/jpeg;base64,/);
  assert.equal(out.width, 600);
  assert.equal(out.height, 400);
  // A crop shows a quarter of the width: the whole photo keeps 4× the pixels.
  const cropped = await shrinkPhotoForPptx(photoIn, { w: 3, h: 2 }, { crop: { x: 0, y: 0, width: 0.25, height: 0.25 } });
  assert.equal(cropped.width, 2400, 'never enlarged; the crop needs every pixel');
  // Transparency stays PNG.
  const clear = await noise(4);
  const pngOut = await shrinkPhotoForPptx({ data: `image/png;base64,${clear.toString('base64')}`, width: 2400, height: 1600 }, { w: 3, h: 2 });
  assert.match(pngOut.data, /^image\/png;base64,/);
  // Small images are left alone.
  const small = { data: `image/png;base64,${(await sharp({ create: { width: 10, height: 10, channels: 3, background: '#fff' } }).png().toBuffer()).toString('base64')}`, width: 10, height: 10 };
  assert.equal(await shrinkPhotoForPptx(small, { w: 1, h: 1 }), small);
});
