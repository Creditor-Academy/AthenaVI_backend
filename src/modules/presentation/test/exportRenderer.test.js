'use strict';

/**
 * Exports through the editor renderer page (export-render.html). The real page lives in the
 * frontend; here a stand-in page with the same window.__athenaExport contract is served
 * locally, so the backend side (load, PDF, images, PPTX pictures / measurements, fallback) is
 * tested on its own.
 */

const assert = require('assert');
const http = require('http');
const { test, before, after } = require('node:test');
const JSZip = require('jszip');
const sharp = require('sharp');

const { checkExportBrowser } = require('../../../shared/utils/exportBrowser');
const exportRenderer = require('../exportRenderer.service');
const exportService = require('../export.service');

const FAKE_PAGE = `<!doctype html><html><head><meta charset="utf-8">
<style>
  html,body{margin:0;background:transparent}
  .export-slide{position:relative;overflow:hidden;break-after:page}
  .export-slide:last-child{break-after:auto}
  .export-isolating .export-slide:not([data-isolated]){display:none}
  .export-isolating [data-export-el]:not([data-isolated]){visibility:hidden}
  .export-isolating--element .export-slide[data-isolated]{background:none!important}
</style></head><body><div id="root"></div><script>
const root = document.getElementById('root');
function slideOf(id){ return [...document.querySelectorAll('.export-slide')].find(n => n.dataset.slideId === id); }
window.__athenaExport = {
  version: 1,
  loaded: true,
  render(payload) {
    root.innerHTML = '';
    for (const s of payload.deck.slides) {
      const doc = s.elements || {};
      const sec = document.createElement('section');
      sec.className = 'export-slide';
      sec.dataset.slideId = s.id;
      sec.dataset.canvasWidth = 1920;
      sec.dataset.canvasHeight = 1080;
      sec.style.cssText = 'width:900px;height:506.25px;background:' + (doc.backgroundColor || '#fff');
      if (doc.backgroundImage) sec.style.backgroundImage = 'linear-gradient(90deg,#ff0000,#0000ff)';
      for (const el of doc.elements || []) {
        const p = el.placement, c = el.content || {};
        const d = document.createElement('div');
        d.dataset.exportEl = el.id;
        d.style.cssText = 'position:absolute;left:' + p.x / 19.2 + '%;top:' + p.y / 10.8 + '%;width:' + p.width / 19.2 + '%;height:' + p.height / 10.8 + '%;';
        if (c.fill) d.style.background = c.fill;
        if (c.clipPath) d.style.clipPath = c.clipPath;
        if (el.type === 'text') {
          const t = document.createElement('div');
          t.className = 'ppt-text-display';
          t.style.fontSize = (c.fontSize / 2) + 'px';
          t.style.color = 'rgb(18, 52, 86)';
          t.textContent = c.text;
          d.appendChild(t);
        }
        sec.appendChild(d);
      }
      root.appendChild(sec);
    }
    const slides = [...document.querySelectorAll('.export-slide')].map(n => ({ id: n.dataset.slideId, stageWidth: 900, stageHeight: 506, canvasWidth: 1920, canvasHeight: 1080 }));
    return Promise.resolve({ version: 1, slides, failedImages: [] });
  },
  measure() {
    const out = {};
    document.querySelectorAll('.export-slide').forEach(s => {
      out[s.dataset.slideId] = {};
      s.querySelectorAll('[data-export-el]').forEach(f => {
        const t = f.querySelector('.ppt-text-display');
        if (t) out[s.dataset.slideId][f.dataset.exportEl] = { fontSize: parseFloat(t.style.fontSize), color: '#123456', overflow: false };
      });
    });
    return out;
  },
  isolate({ slideId, elementId, margin }) {
    this.release();
    const s = slideOf(slideId); if (!s) return null;
    const f = elementId ? [...s.querySelectorAll('[data-export-el]')].find(n => n.dataset.exportEl === elementId) : null;
    if (elementId && !f) return null;
    root.classList.add('export-isolating'); if (f) root.classList.add('export-isolating--element');
    s.setAttribute('data-isolated', ''); if (f) f.setAttribute('data-isolated', '');
    const sr = s.getBoundingClientRect(); const r = f ? f.getBoundingClientRect() : sr; const m = f ? (margin || 0) : 0;
    const left = Math.max(sr.left, r.left - m), top = Math.max(sr.top, r.top - m);
    const right = Math.min(sr.right, r.right + m), bottom = Math.min(sr.bottom, r.bottom + m);
    const k = 1920 / sr.width;
    return { clip: { x: left + scrollX, y: top + scrollY, width: right - left, height: bottom - top },
             box: { x: (left - sr.left) * k, y: (top - sr.top) * k, width: (right - left) * k, height: (bottom - top) * k } };
  },
  release() {
    root.classList.remove('export-isolating', 'export-isolating--element');
    document.querySelectorAll('[data-isolated]').forEach(n => n.removeAttribute('data-isolated'));
  },
};
</script></body></html>`;

const P = (x, y, width, height) => ({ x, y, width, height });
const DECK = {
  id: 'd1',
  aspectRatio: '16:9',
  themeTokens: { palette: { bg: '#FFFFFF', text: '#111111' } },
  slides: [
    {
      id: 'a',
      order: 1,
      content: {},
      elements: {
        canvas: { width: 1920, height: 1080 },
        backgroundColor: '#FFFFFF',
        elements: [
          { id: 'title', type: 'text', layer: 2, slotId: 'TITLE', placement: P(100, 80, 1200, 160), content: { text: 'Fitted title', fontSize: 40 } },
          { id: 'hex', type: 'shape', layer: 1, placement: P(1300, 300, 400, 400), content: { shape: 'blob', fill: '#F97316', clipPath: 'circle(40% at 50% 50%)' } },
          { id: 'tri', type: 'shape', layer: 1, placement: P(800, 300, 300, 300), content: { shape: 'triangle-up', fill: '#14B8A6', clipPath: 'polygon(50% 0%, 0% 100%, 100% 100%)' } },
          { id: 'box', type: 'shape', layer: 1, placement: P(100, 600, 400, 300), content: { shape: 'rect', fill: '#2563EB' } },
        ],
      },
    },
    {
      id: 'b',
      order: 2,
      content: {},
      elements: {
        canvas: { width: 1920, height: 1080 },
        backgroundColor: '#0F172A',
        backgroundImage: 'https://example.invalid/bg.jpg',
        elements: [{ id: 'cap', type: 'text', layer: 2, placement: P(100, 800, 1000, 120), content: { text: 'Over a photo', fontSize: 30 } }],
      },
    },
  ],
};

let server;
let baseUrl;
let browserOk = false;
const savedEnv = {};

before(async () => {
  for (const key of ['EXPORT_RENDER_URL', 'FRONTEND_URL', 'PPT_EXPORT_RENDERER']) savedEnv[key] = process.env[key];
  server = http.createServer((req, res) => {
    if (req.url.startsWith('/export-render.html')) {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(FAKE_PAGE);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browserOk = (await checkExportBrowser()).ok;
});

after(() => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  server?.close();
});

function useRenderer(url = `${baseUrl}/export-render.html`) {
  process.env.EXPORT_RENDER_URL = url;
  delete process.env.PPT_EXPORT_RENDERER;
}

test('where the renderer is: EXPORT_RENDER_URL, else FRONTEND_URL; legacy switches it off', () => {
  delete process.env.EXPORT_RENDER_URL;
  delete process.env.PPT_EXPORT_RENDERER;
  process.env.FRONTEND_URL = 'https://app.example.com/';
  assert.equal(exportRenderer.exportRenderUrl(), 'https://app.example.com/export-render.html');
  process.env.EXPORT_RENDER_URL = 'https://cdn.example.com/x/export-render.html';
  assert.equal(exportRenderer.exportRenderUrl(), 'https://cdn.example.com/x/export-render.html');
  process.env.PPT_EXPORT_RENDERER = 'legacy';
  assert.equal(exportRenderer.exportRenderUrl(), null);
  assert.equal(exportRenderer.isRendererEnabled(), false);
  delete process.env.PPT_EXPORT_RENDERER;
  delete process.env.FRONTEND_URL;
});

test('the render page may load its bundle, fonts and pictures, nothing else', () => {
  const origin = 'https://app.example.com';
  const req = (url, type, { child = false } = {}) => ({
    url: () => url,
    resourceType: () => type,
    frame: () => ({ parentFrame: () => (child ? {} : null) }),
  });
  assert.equal(exportRenderer.allowRequest(req(`${origin}/export-render.html`, 'document'), origin), true);
  assert.equal(exportRenderer.allowRequest(req(`${origin}/assets/app.js`, 'script'), origin), true);
  assert.equal(exportRenderer.allowRequest(req('https://images.pexels.com/p.jpg', 'image'), origin), true);
  assert.equal(exportRenderer.allowRequest(req('https://fonts.gstatic.com/s/inter.woff2', 'font'), origin), true);
  assert.equal(exportRenderer.allowRequest(req('data:image/png;base64,AAAA', 'image'), origin), true);
  assert.equal(exportRenderer.allowRequest(req('https://evil.example/x.js', 'script'), origin), false);
  assert.equal(exportRenderer.allowRequest(req('https://api.example.com/api/me', 'fetch'), origin), false);
  assert.equal(exportRenderer.allowRequest(req('https://youtube.com/embed/x', 'document', { child: true }), origin), false);
  assert.equal(exportRenderer.allowRequest(req('http://169.254.169.254/latest/meta-data/', 'image'), origin), false);
  assert.equal(exportRenderer.allowRequest(req('file:///etc/passwd', 'image'), origin), false);
});

test('PDF through the renderer: one 13.333 × 7.5in page per slide', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  useRenderer();
  const pdf = await exportService.buildPdfBuffer(DECK, {});
  const text = pdf.toString('latin1');
  assert.equal((text.match(/\/Type\s*\/Page[^s]/g) || []).length, 2);
  assert.match(text, /\/MediaBox \[0 0 960 540\]/);
});

test('images through the renderer: exactly 1920 × 1080 each, numbered in deck order, valid zip', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  useRenderer();
  const out = await exportService.buildRasterExport(DECK, { format: 'PNG', deckName: 'Deck' });
  assert.equal(out.ext, 'zip');
  const zip = await JSZip.loadAsync(out.buffer, { checkCRC32: true });
  assert.deepEqual(Object.keys(zip.files), ['Deck-slide-01.png', 'Deck-slide-02.png']);
  for (const name of Object.keys(zip.files)) {
    const meta = await sharp(await zip.file(name).async('nodebuffer')).metadata();
    assert.deepEqual([meta.width, meta.height], [1920, 1080], name);
  }
  const single = await exportService.buildRasterExport(DECK, { format: 'JPEG', slideId: 'b', deckName: 'Deck' });
  assert.equal(single.ext, 'jpg');
  const meta = await sharp(single.buffer).metadata();
  assert.deepEqual([meta.format, meta.width, meta.height], ['jpeg', 1920, 1080]);
});

test('PPTX through the renderer: measured text, pictures for odd shapes, background pictures', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  useRenderer();
  const assets = await exportRenderer.capturePptxAssets(DECK);
  assert.equal(assets.textMetrics.a.title.fontSize, 20);
  assert.deepEqual(Object.keys(assets.pictures.a), ['hex'], 'only the non-polygon clip-path shape becomes a picture');
  assert.ok(assets.backgrounds.b.startsWith('image/jpeg;base64,'));
  assert.ok(!assets.backgrounds.a, 'a plain colour stays a colour');

  // The circle-clipped shape's picture is transparent around it (its corners are empty).
  const png = Buffer.from(assets.pictures.a.hex.data.split(',')[1], 'base64');
  const { data, info } = await sharp(png).raw().toBuffer({ resolveWithObject: true });
  assert.equal(data[3], 0, 'top-left corner is transparent');
  const centre = (Math.floor(info.height / 2) * info.width + Math.floor(info.width / 2)) * info.channels;
  assert.deepEqual([data[centre], data[centre + 1], data[centre + 2], data[centre + 3]], [249, 115, 22, 255]);
  // Its box is the element's box (canvas px), give or take a pixel of margin.
  const box = assets.pictures.a.hex.box;
  assert.ok(Math.abs(box.x - 1300) <= 6 && Math.abs(box.width - 400) <= 10, JSON.stringify(box));

  const pptx = await exportService.buildPptxBuffer(DECK, { assets });
  const zip = await JSZip.loadAsync(pptx);
  const s1 = await zip.file('ppt/slides/slide1.xml').async('string');
  const s2 = await zip.file('ppt/slides/slide2.xml').async('string');
  assert.equal((s1.match(/<p:pic>/g) || []).length, 1, 'the circle-clipped shape is a picture');
  assert.match(s1, /<a:custGeom>[\s\S]*?<a:srgbClr val="14B8A6"/, 'the polygon triangle is a native custom shape');
  assert.match(s1, /<a:prstGeom prst="rect">[\s\S]*<a:srgbClr val="2563EB"/, 'the plain box stays a shape');
  assert.match(s1, /sz="2130"/, 'title at the fitted 20 stage px');
  assert.match(s1, /<a:srgbClr val="123456"/, 'title in the colour the editor drew');
  assert.match(s2, /<p:bg><p:bgPr><a:blipFill/, 'slide 2 background is the captured picture');
});

test('if the render page is unreachable, export falls back to the built-in renderer', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  useRenderer(`${baseUrl}/missing.html`);
  const pdf = await exportService.buildPdfBuffer(DECK, {});
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
  // PPTX still builds (no measurements / pictures).
  await assert.rejects(exportRenderer.capturePptxAssets(DECK), /did not load/);
});
