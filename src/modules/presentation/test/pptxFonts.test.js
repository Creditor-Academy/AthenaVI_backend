'use strict';

/**
 * Fonts in PowerPoint (Phase 5): the font the editor drew is the one PPTX names, and the deck's
 * Google Fonts travel inside the file as EOT `.fntdata` parts PowerPoint (and LibreOffice) read.
 */

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { test } = require('node:test');
const JSZip = require('jszip');

// Never touch the real font cache from tests.
process.env.PPTX_FONT_CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pptx-fonts-test-'));

const { primaryFamily, shouldEmbedFamily, ttfToEot, fontNames, fontUsage, embedPptxFonts } = require('../pptxFonts');
const { buildPptxText } = require('../pptxText');
const { buildPptxBuffer, resolveExportFontFace, editorThemeFonts } = require('../export.service');

/** A minimal TrueType font: just the OS/2, head and name tables the EOT header reads. */
function fakeTtf({ family = 'Test Sans', style = 'Regular', weight = 400, italic = false, fsType = 0, sfnt = 0x00010000 } = {}) {
  const os2 = Buffer.alloc(86);
  os2.writeUInt16BE(1, 0); // version
  os2.writeUInt16BE(weight, 4);
  os2.writeUInt16BE(fsType, 8);
  for (let i = 0; i < 10; i += 1) os2[32 + i] = i + 1; // panose
  os2.writeUInt32BE(0x00000007, 42); // unicode range 1
  os2.writeUInt16BE(italic ? 0x01 : 0x40, 62); // fsSelection
  os2.writeUInt32BE(0x00000001, 78); // code page range 1
  const head = Buffer.alloc(54);
  head.writeUInt32BE(0xdeadbeef, 8); // checkSumAdjustment

  const strings = [
    [1, family],
    [2, style],
    [4, `${family} ${style}`],
    [5, 'Version 1.000'],
  ].map(([id, text]) => {
    const le = Buffer.from(text, 'utf16le');
    const be = Buffer.alloc(le.length);
    for (let j = 0; j < le.length; j += 2) {
      be[j] = le[j + 1];
      be[j + 1] = le[j];
    }
    return { id, be };
  });
  const recordsSize = 6 + strings.length * 12;
  const name = Buffer.alloc(recordsSize + strings.reduce((n, s) => n + s.be.length, 0));
  name.writeUInt16BE(0, 0);
  name.writeUInt16BE(strings.length, 2);
  name.writeUInt16BE(recordsSize, 4);
  let stringAt = 0;
  strings.forEach((s, i) => {
    const at = 6 + i * 12;
    name.writeUInt16BE(3, at);
    name.writeUInt16BE(1, at + 2);
    name.writeUInt16BE(0x409, at + 4);
    name.writeUInt16BE(s.id, at + 6);
    name.writeUInt16BE(s.be.length, at + 8);
    name.writeUInt16BE(stringAt, at + 10);
    s.be.copy(name, recordsSize + stringAt);
    stringAt += s.be.length;
  });

  const tables = [
    ['OS/2', os2],
    ['head', head],
    ['name', name],
  ];
  const header = Buffer.alloc(12 + tables.length * 16);
  header.writeUInt32BE(sfnt, 0);
  header.writeUInt16BE(tables.length, 4);
  let offset = header.length;
  tables.forEach(([tag, data], i) => {
    const at = 12 + i * 16;
    header.write(tag, at, 'latin1');
    header.writeUInt32BE(offset, at + 8);
    header.writeUInt32BE(data.length, at + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...tables.map(([, data]) => data)]);
}

// ── Family names ──────────────────────────────────────────────────────────────

test('fonts: the first family of a CSS font list is the PowerPoint typeface', () => {
  assert.equal(primaryFamily('"Playfair Display", serif'), 'Playfair Display');
  assert.equal(primaryFamily("'Outfit', sans-serif"), 'Outfit');
  assert.equal(primaryFamily('Inter, sans-serif'), 'Inter');
  assert.equal(primaryFamily('sans-serif'), null);
  assert.equal(primaryFamily('var(--ppt-font-body, inherit)'), null);
  assert.equal(primaryFamily(''), null);
  assert.equal(shouldEmbedFamily('Outfit'), true);
  assert.equal(shouldEmbedFamily('Arial'), false, 'Office fonts are never embedded');
  assert.equal(shouldEmbedFamily('Calibri'), false);
  assert.equal(shouldEmbedFamily('+mn-lt'), false, 'theme references are not families');
});

test('fonts: the font for a text element follows the editor (measured first, then its role rule)', () => {
  const theme = editorThemeFonts({ fonts: { heading: 'Playfair Display', body: 'Outfit', subheading: 'Lora' } });
  assert.deepEqual(theme, { heading: 'Playfair Display', body: 'Outfit' });
  assert.deepEqual(editorThemeFonts({}), { heading: 'Inter', body: 'Inter' }, 'the editor falls back to Inter');

  assert.equal(resolveExportFontFace({}, { role: 'body' }, theme, { fontFamily: 'Merriweather' }), 'Merriweather');
  assert.equal(resolveExportFontFace({ fontFamily: '"Roboto", sans-serif' }, {}, theme), 'Roboto');
  assert.equal(resolveExportFontFace({}, { role: 'title' }, theme), 'Playfair Display');
  assert.equal(resolveExportFontFace({}, { slotId: 'SECTION_HEADING' }, theme), 'Playfair Display');
  // The editor draws subtitles and stats in the body font (it used to get the heading font).
  assert.equal(resolveExportFontFace({}, { role: 'subtitle' }, theme), 'Outfit');
  assert.equal(resolveExportFontFace({}, { role: 'stat_value' }, theme), 'Outfit');
});

test('fonts: a run takes the family the editor drew it in; font stacks become one family', () => {
  const { runs } = buildPptxText({
    content: { text: 'Plain Fancy', runs: [{ text: 'Plain ' }, { text: 'Fancy', fontFamily: 'Lobster, cursive' }] },
    box: { x: 0, y: 0, w: 4, h: 1 },
    slideWidthIn: 13.333,
    color: '111111',
    fontFace: 'Outfit',
    runColor: () => '111111',
    measured: { fontSize: 22, runs: [{ text: 'Plain ', fontFamily: 'Outfit' }, { text: 'Fancy', fontFamily: 'Pacifico' }] },
  });
  assert.deepEqual(runs.map((r) => r.options.fontFace), ['Outfit', 'Pacifico']);

  const unmeasured = buildPptxText({
    content: { text: 'X', runs: [{ text: 'X', fontFamily: '"Lobster", cursive' }] },
    box: { x: 0, y: 0, w: 4, h: 1 },
    slideWidthIn: 13.333,
    color: '111111',
    runColor: () => '111111',
  });
  assert.equal(unmeasured.runs[0].options.fontFace, 'Lobster');
});

// ── EOT ───────────────────────────────────────────────────────────────────────

test('EOT: header from the font tables, then the untouched TrueType data', () => {
  const ttf = fakeTtf({ family: 'Test Sans', style: 'Bold', weight: 700 });
  assert.deepEqual(fontNames(ttf), { family: 'Test Sans', style: 'Bold' });
  const eot = ttfToEot(ttf);
  assert.equal(eot.readUInt32LE(0), eot.length, 'EOTSize');
  assert.equal(eot.readUInt32LE(4), ttf.length, 'FontDataSize');
  assert.equal(eot.readUInt32LE(8), 0x00020001, 'version');
  assert.equal(eot.readUInt32LE(12), 0, 'no compression / XOR');
  assert.deepEqual([...eot.subarray(16, 26)], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 'PANOSE');
  assert.equal(eot.readUInt32LE(28), 700, 'weight');
  assert.equal(eot.readUInt16LE(34), 0x504c, 'magic number');
  assert.equal(eot.readUInt32LE(36), 7, 'unicode range 1');
  assert.equal(eot.readUInt32LE(52), 1, 'code page range 1');
  assert.equal(eot.readUInt32LE(60), 0xdeadbeef, 'checkSumAdjustment');
  const familySize = eot.readUInt16LE(82);
  assert.equal(eot.toString('utf16le', 84, 84 + familySize), 'Test Sans');
  assert.ok(eot.subarray(eot.length - ttf.length).equals(ttf), 'font data at the end');

  assert.equal(ttfToEot(fakeTtf({ italic: true }))[27], 1, 'italic flag');
  assert.equal(ttfToEot(fakeTtf({ fsType: 0x0002 })), null, 'restricted licence: not embedded');
  assert.equal(ttfToEot(fakeTtf({ sfnt: 0x4f54544f })), null, 'CFF (OTTO) fonts are not embedded');
});

// ── Embedding ─────────────────────────────────────────────────────────────────

test('usage: families with the faces their runs need; Office fonts and theme refs skipped', () => {
  const usage = fontUsage([
    '<a:rPr lang="en-US" b="1"><a:latin typeface="Outfit" pitchFamily="34" charset="0"/></a:rPr>',
    '<a:rPr i="1"><a:latin typeface="Playfair Display"/></a:rPr><a:rPr><a:latin typeface="Outfit"/></a:rPr>',
    '<a:defRPr sz="1200"><a:latin typeface="Arial"/></a:defRPr><a:rPr><a:latin typeface="+mn-lt"/></a:rPr>',
  ]);
  assert.deepEqual([...usage.keys()], ['Outfit', 'Playfair Display']);
  assert.deepEqual([...usage.get('Outfit')].sort(), ['bold', 'regular']);
  assert.deepEqual([...usage.get('Playfair Display')].sort(), ['italic', 'regular']);
});

const P = (x, y, width, height) => ({ x, y, width, height });

test('embedding: the fonts the slides use are in the PPTX as PowerPoint expects them', async () => {
  const deck = {
    aspectRatio: '16:9',
    themeTokens: { palette: { bg: '#FFFFFF', text: '#111111' }, fonts: { heading: 'Athena Test Serif', body: 'Athena Test Sans' } },
    slides: [
      {
        id: 's1',
        order: 1,
        content: {},
        elements: {
          canvas: { width: 1920, height: 1080 },
          elements: [
            { id: 'h', type: 'text', role: 'title', placement: P(100, 100, 1600, 200), content: { text: 'Title', bold: true } },
            { id: 'b', type: 'text', role: 'body', placement: P(100, 400, 1600, 200), content: { text: 'Body' } },
            { id: 'x', type: 'text', role: 'body', placement: P(100, 700, 1600, 200), content: { text: 'Missing', fontFamily: 'Not A Google Font' } },
          ],
        },
      },
    ],
  };
  const zip = await JSZip.loadAsync(await buildPptxBuffer(deck));
  assert.equal(zip.file('ppt/fonts/font1.fntdata'), null, 'not embedded unless asked (no network in tests)');
  const theme = await zip.file('ppt/theme/theme1.xml').async('string');
  assert.match(theme, /<a:majorFont><a:latin typeface="Athena Test Serif"\/>/);
  assert.match(theme, /<a:minorFont><a:latin typeface="Athena Test Sans"\/>/);

  const requested = [];
  const download = async (family, face) => {
    requested.push(`${family}/${face}`);
    if (family === 'Not A Google Font') return null;
    return fakeTtf({ family, style: face === 'bold' ? 'Bold' : 'Regular', weight: face === 'bold' ? 700 : 400 });
  };
  const result = await embedPptxFonts(zip, { download });
  assert.deepEqual(requested.sort(), ['Athena Test Sans/regular', 'Athena Test Serif/bold', 'Athena Test Serif/regular', 'Not A Google Font/regular']);
  assert.deepEqual(result.unavailable, ['Not A Google Font']);
  assert.equal(result.embedded.length, 2);

  const presentation = await zip.file('ppt/presentation.xml').async('string');
  assert.match(presentation, /embedTrueTypeFonts="1"/);
  assert.match(presentation, /<p:notesSz [^>]*\/><p:embeddedFontLst>/, 'after notesSz (schema order)');
  assert.match(presentation, /<p:embeddedFont><p:font typeface="Athena Test Serif" charset="0"\/><p:regular r:id="rId\d+"\/><p:bold r:id="rId\d+"\/><\/p:embeddedFont>/);
  assert.match(presentation, /<p:font typeface="Athena Test Sans" charset="0"\/><p:regular r:id="rId\d+"\/><\/p:embeddedFont>/);
  const rels = await zip.file('ppt/_rels/presentation.xml.rels').async('string');
  const fontRels = [...rels.matchAll(/Id="(rId\d+)" Type="[^"]+\/font" Target="fonts\/(font\d+\.fntdata)"/g)];
  assert.equal(fontRels.length, 3);
  for (const [, id, target] of fontRels) {
    assert.match(presentation, new RegExp(`r:id="${id}"`));
    const data = await zip.file(`ppt/fonts/${target}`).async('nodebuffer');
    assert.equal(data.readUInt16LE(34), 0x504c, 'an EOT file');
  }
  const ids = [...rels.matchAll(/Id="(rId\d+)"/g)].map((m) => m[1]);
  assert.equal(new Set(ids).size, ids.length, 'relationship ids stay unique');
  const types = await zip.file('[Content_Types].xml').async('string');
  assert.match(types, /<Default Extension="fntdata" ContentType="application\/x-fontdata"\/>/);
});
