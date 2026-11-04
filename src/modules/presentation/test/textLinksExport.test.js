'use strict';

const assert = require('assert');
const { test } = require('node:test');
const JSZip = require('jszip');
const { buildPptxBuffer } = require('../export.service');
const { buildDeckHtml } = require('../slideHtml');
const { linkedRuns, safeLinkHref } = require('../textLinks');

const URL = 'https://360.articulate.com/review/content/d91edd25-c491-4389-a3b2-18b5ce1ba69f/review';

function deckWith(elements) {
  return {
    aspectRatio: '16:9',
    themeTokens: { palette: { bg: '#FFFFFF', text: '#111111', primary: '#2563EB' } },
    slides: [{ id: 's1', order: 1, content: {}, elements: { canvas: { width: 1920, height: 1080 }, elements } }],
  };
}

const textEl = (content) => ({
  id: 't',
  type: 'text',
  layer: 1,
  placement: { x: 0, y: 0, width: 800, height: 200 },
  content: { fontSize: 24, ...content },
});

async function slideParts(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  return {
    slide: await zip.file('ppt/slides/slide1.xml').async('string'),
    rels: await zip.file('ppt/slides/_rels/slide1.xml.rels').async('string'),
  };
}

test('links: only http(s) / mailto / tel hrefs are kept', () => {
  assert.equal(safeLinkHref('javascript:alert(1)'), null);
  const runs = linkedRuns([{ text: 'x', href: 'javascript:alert(1)' }, { text: ' see www.a.io.' }]);
  assert.deepEqual(
    runs.map((r) => [r.text, r.href || null]),
    [
      ['x', null],
      [' see ', null],
      ['www.a.io', 'https://www.a.io'],
      ['.', null],
    ]
  );
});

test('pptx: a URL typed as plain text exports as a hyperlink', async () => {
  const { slide, rels } = await slideParts(
    await buildPptxBuffer(deckWith([textEl({ text: `Review: ${URL}` })]))
  );
  assert.match(slide, /<a:hlinkClick r:id="rId\d+"/);
  assert.ok(rels.includes(`Target="${URL}"`), 'relationship targets the URL');
  assert.match(slide, /Review: </, 'text before the link is kept');
});

test('pptx: a linked run exports as a hyperlink on just those words', async () => {
  const { slide, rels } = await slideParts(
    await buildPptxBuffer(
      deckWith([
        textEl({
          text: 'Read the guide',
          runs: [{ text: 'Read the ', color: '#111111' }, { text: 'guide', color: '#111111', href: 'https://guide.io' }],
        }),
      ])
    )
  );
  assert.equal((slide.match(/<a:hlinkClick /g) || []).length, 1);
  assert.ok(rels.includes('Target="https://guide.io"'));
});

test('pdf html: links are anchors, unsafe hrefs are not', async () => {
  const html = await buildDeckHtml(
    deckWith([
      textEl({
        text: 'guide bad',
        runs: [{ text: 'guide', href: 'https://guide.io' }, { text: ' bad', href: 'javascript:alert(1)' }],
      }),
      { ...textEl({ text: `Review ${URL}` }), id: 't2' },
    ]),
    { injectFonts: false }
  );
  assert.ok(html.includes('<a href="https://guide.io"'));
  assert.ok(html.includes(`<a href="${URL}"`));
  assert.ok(!html.includes('javascript:'));
});
