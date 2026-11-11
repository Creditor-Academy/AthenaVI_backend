'use strict';

// Slide selection (any set of slides) and image options (size, JPEG quality, transparency) for
// every export format, plus the credit charge for slide images made in the browser.
// The DB, S3, credits and inbox are stubbed; renders use a real headless browser when present.
process.env.PPT_EXPORT_HEARTBEAT_INTERVAL_MS = '40';

const assert = require('assert');
const { test, before } = require('node:test');
const JSZip = require('jszip');
const sharp = require('sharp');

const { checkExportBrowser } = require('../../../shared/utils/exportBrowser');
const deckGeneration = require('../deckGeneration.service');
const presentationDao = require('../presentation.dao');
const s3Service = require('../../s3/s3.service');
const presentationCredit = require('../presentationCredit.service');
const inboxService = require('../../inbox/inbox.service');

const rows = new Map();
const uploads = new Map();
let currentDeck = null;
const charges = [];
let canAfford = true;

presentationDao.findExport = async (id) => rows.get(id) || null;
presentationDao.updateExport = async (id, data) => {
  const row = { ...rows.get(id), ...data, updatedAt: new Date() };
  rows.set(id, row);
  return row;
};
presentationDao.createExport = async (data) => {
  const id = `q${rows.size + 1}`;
  const now = new Date();
  rows.set(id, { id, ...data, createdAt: now, updatedAt: now });
  return { id };
};
presentationDao.findDeckById = async () => currentDeck;
presentationDao.incrementDeckCreditsCharged = async () => {};
s3Service.uploadFileToKey = async (buffer, key) => {
  uploads.set(key, buffer);
};
s3Service.getPresignedGetUrl = async (key) => `https://s3.test/${key}`;
presentationCredit.assertAfford = async () => {
  if (!canAfford) {
    const err = new Error('Insufficient credits');
    err.statusCode = 402;
    throw err;
  }
};
presentationCredit.chargeFlat = async (args) => {
  charges.push(args);
  return { charged: 3 };
};
inboxService.notifyUser = async () => {};
deckGeneration.loadPresentationDeck = async () => ({ deck: currentDeck, project: { id: 'p1', name: 'Q3 Plan' } });

const exportService = require('../export.service');

function slide(id, order, color) {
  return {
    id,
    order,
    content: {},
    elements: {
      canvas: { width: 960, height: 540 },
      elements: [
        { id: `${id}-box`, type: 'shape', layer: 1, placement: { x: 80, y: 80, width: 400, height: 200 }, content: { shape: 'rect', fill: color } },
        { id: `${id}-t`, type: 'text', layer: 2, placement: { x: 80, y: 320, width: 700, height: 80 }, content: { text: `Slide ${order}`, fontSize: 30 } },
      ],
    },
  };
}

const fiveSlides = () => ({
  id: 'deck1',
  aspectRatio: '16:9',
  themeTokens: { palette: { bg: '#FFFFFF', text: '#111111' } },
  // Saved out of order on purpose: exports always follow `order`.
  slides: [slide('d', 4, '#a855f7'), slide('a', 1, '#2563eb'), slide('e', 5, '#ef4444'), slide('b', 2, '#10b981'), slide('c', 3, '#f97316')],
});

let seq = 0;
function queueRow(format) {
  seq += 1;
  const id = `exp${seq}`;
  const now = new Date();
  rows.set(id, { id, deckId: 'deck1', format, status: 'QUEUED', createdAt: now, updatedAt: now });
  return id;
}
const run = (exportId, extra = {}) =>
  exportService.processExport({ exportId, workspaceId: 'w1', userId: 'u1', projectId: 'p1', projectName: 'Q3 Plan', ...extra });

let browserOk = false;
before(async () => {
  browserOk = (await checkExportBrowser()).ok;
});

// ── Pure helpers ──────────────────────────────────────────────────────────────

test('selection: any set of slides, always in deck order; slideId still works', () => {
  const deck = fiveSlides();
  const ids = (sel) => exportService.selectExportSlides(deck, sel).map((s) => s.id);
  assert.deepEqual(ids({}), ['a', 'b', 'c', 'd', 'e']);
  assert.deepEqual(ids({ slideIds: ['e', 'b', 'd'] }), ['b', 'd', 'e']);
  assert.deepEqual(ids({ slideId: 'c' }), ['c']);
  // slideIds wins over the older slideId.
  assert.deepEqual(ids({ slideId: 'c', slideIds: ['a'] }), ['a']);
});

test('image options are clamped; only PNG can be transparent', () => {
  const o = exportService.imageExportOptions;
  assert.deepEqual(o({ format: 'PNG' }), { scale: 1, quality: 90, transparent: false });
  assert.deepEqual(o({ format: 'PNG', scale: 3, transparent: true }), { scale: 3, quality: 90, transparent: true });
  assert.deepEqual(o({ format: 'JPEG', scale: 7, quality: 20, transparent: true }), { scale: 1, quality: 60, transparent: false });
  assert.equal(o({ format: 'JPEG', quality: 140 }).quality, 100);
});

// ── Queue / charge ────────────────────────────────────────────────────────────

test('queue: a slide that is not in the deck is a 404, before anything is queued', async () => {
  currentDeck = fiveSlides();
  const before = rows.size;
  await assert.rejects(
    exportService.queueExport({ workspaceId: 'w1', presentationId: 'p1', userId: 'u1', format: 'PDF', slideIds: ['a', 'zz'] }),
    (err) => err.statusCode === 404 || err.status === 404
  );
  assert.equal(rows.size, before);
});

test('browser images: charged the export fee once per download id, checked like a server export', async () => {
  currentDeck = fiveSlides();
  charges.length = 0;
  const downloadId = '3f1c2b4e-1111-4a2b-8c3d-123456789abc';
  const res = await exportService.chargeBrowserExport({
    workspaceId: 'w1', presentationId: 'p1', userId: 'u1', format: 'PNG', slideIds: ['b', 'd'], downloadId,
  });
  assert.equal(res.slideCount, 2);
  assert.equal(res.creditsCharged, 3);
  assert.equal(charges.length, 1);
  assert.equal(charges[0].idempotencyKey, `ppt:export:browser:deck1:${downloadId}`);
  assert.equal(charges[0].feature, 'ppt_export');

  await assert.rejects(
    exportService.chargeBrowserExport({ workspaceId: 'w1', presentationId: 'p1', userId: 'u1', format: 'PNG', slideIds: ['nope'], downloadId }),
    (err) => (err.statusCode || err.status) === 404
  );
  await assert.rejects(
    exportService.chargeBrowserExport({ workspaceId: 'w1', presentationId: 'p1', userId: 'u1', format: 'PDF', slideIds: ['a'], downloadId }),
    (err) => (err.statusCode || err.status) === 400
  );
  canAfford = false;
  try {
    await assert.rejects(
      exportService.chargeBrowserExport({ workspaceId: 'w1', presentationId: 'p1', userId: 'u1', format: 'PNG', slideIds: ['a'], downloadId }),
      /Insufficient credits/
    );
  } finally {
    canAfford = true;
  }
  assert.equal(charges.length, 1, 'nothing charged when the request is refused');
});

// ── Real renders ──────────────────────────────────────────────────────────────

test('PNG of slides 2, 4 and 5 at 2×: a zip of three 1920×1080 files named by page number', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  currentDeck = fiveSlides();
  const id = queueRow('PNG');
  await run(id, { slideIds: ['e', 'b', 'd'], image: { scale: 2 } });
  const row = rows.get(id);
  assert.equal(row.status, 'READY', row.error);
  const zip = await JSZip.loadAsync(uploads.get(row.s3Key), { checkCRC32: true });
  assert.deepEqual(Object.keys(zip.files), ['2.png', '4.png', '5.png']);
  const meta = await sharp(await zip.file('4.png').async('nodebuffer')).metadata();
  assert.deepEqual([meta.width, meta.height], [1920, 1080]);
});

test('JPEG quality changes the file; PDF and PPTX keep only the chosen slides', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  currentDeck = fiveSlides();
  const low = queueRow('JPEG');
  await run(low, { slideIds: ['c'], image: { quality: 60 } });
  const high = queueRow('JPEG');
  await run(high, { slideIds: ['c'], image: { quality: 100 } });
  assert.equal(rows.get(low).status, 'READY', rows.get(low).error);
  assert.ok(uploads.get(rows.get(low).s3Key).length < uploads.get(rows.get(high).s3Key).length, 'quality 60 is smaller than 100');

  const pdf = queueRow('PDF');
  await run(pdf, { slideIds: ['d', 'a'] });
  const pdfBuf = uploads.get(rows.get(pdf).s3Key);
  assert.equal((pdfBuf.toString('latin1').match(/\/Type\s*\/Page[^s]/g) || []).length, 2);

  const pptx = queueRow('PPTX');
  // Google Slides: no font embedding, so the test never downloads fonts.
  await run(pptx, { slideIds: ['b', 'c', 'e'], pptxTarget: 'google-slides' });
  assert.equal(rows.get(pptx).status, 'READY', rows.get(pptx).error);
  const deckZip = await JSZip.loadAsync(uploads.get(rows.get(pptx).s3Key));
  const slideFiles = Object.keys(deckZip.files).filter((f) => /^ppt\/slides\/slide\d+\.xml$/.test(f));
  assert.equal(slideFiles.length, 3);
  const first = await deckZip.file('ppt/slides/slide1.xml').async('string');
  assert.match(first, /Slide 2/, 'first slide of the file is deck slide 2');
});
