'use strict';

// Fast heartbeats so the tests can see them during a real render.
process.env.PPT_EXPORT_HEARTBEAT_INTERVAL_MS = '40';
process.env.PPT_EXPORT_MAX_CONCURRENT_BROWSER = '2';
// Short render timeout so the "slide never loads" case fails quickly.
process.env.PPT_EXPORT_PUPPETEER_TIMEOUT_MS = '5000';

const assert = require('assert');
const { test, before } = require('node:test');
const JSZip = require('jszip');

const {
  createSemaphore,
  withHeartbeat,
  pdfRenderTimeoutMs,
  exportFileExt,
  slideImageFilename,
  normalizeExportError,
  EXPORT_ERROR_MESSAGES,
} = require('../exportJob.util');
const AppError = require('../../../shared/utils/AppError');
const { checkExportBrowser, BrowserUnavailableError } = require('../../../shared/utils/exportBrowser');

// Stub the DB / S3 / credits / inbox / deck loader before export.service takes its references.
const deckGeneration = require('../deckGeneration.service');
const presentationDao = require('../presentation.dao');
const s3Service = require('../../s3/s3.service');
const presentationCredit = require('../presentationCredit.service');
const inboxService = require('../../inbox/inbox.service');

const rows = new Map();
const uploads = new Map();
const decks = new Map();
const statusLog = [];

presentationDao.findExport = async (id) => rows.get(id) || null;
presentationDao.updateExport = async (id, data) => {
  const row = { ...rows.get(id), ...data, updatedAt: new Date() };
  rows.set(id, row);
  statusLog.push({ id, status: row.status, beat: Object.keys(data).length === 1 && data.error === null });
  return row;
};
presentationDao.findDeckById = async (id) => {
  const deck = decks.get(id);
  if (deck instanceof Error) throw deck;
  return deck || null;
};
presentationDao.incrementDeckCreditsCharged = async () => {};
s3Service.uploadFileToKey = async (buffer, key) => {
  uploads.set(key, buffer);
};
s3Service.getPresignedGetUrl = async (key, _sec, opts) => `https://s3.test/${key}#${opts?.responseContentDisposition}`;
presentationCredit.chargeFlat = async () => ({ skipped: true });
inboxService.notifyUser = async () => {};
deckGeneration.loadPresentationDeck = async () => ({ deck: { id: 'deck1' }, project: { id: 'p1', name: 'Q3 Plan' } });

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

function deckOf(slides) {
  return { id: 'deck1', aspectRatio: '16:9', themeTokens: { palette: { bg: '#FFFFFF', text: '#111111' } }, slides };
}

let exportSeq = 0;
function queueRow(format, deckId = 'deck1') {
  exportSeq += 1;
  const id = `exp${exportSeq}`;
  const now = new Date();
  rows.set(id, { id, deckId, format, status: 'QUEUED', createdAt: now, updatedAt: now });
  return id;
}

const run = (exportId, extra = {}) =>
  exportService.processExport({ exportId, workspaceId: 'w1', userId: 'u1', projectId: 'p1', projectName: 'Q3 Plan', ...extra });

let browserOk = false;
before(async () => {
  browserOk = (await checkExportBrowser()).ok;
});

// ── Pure helpers ──────────────────────────────────────────────────────────────

test('semaphore: at most `limit` holders, waiters served in order, release is idempotent', async () => {
  const sem = createSemaphore(2);
  const order = [];
  const r1 = await sem.acquire();
  const r2 = await sem.acquire();
  const p3 = sem.acquire().then((r) => {
    order.push('third');
    return r;
  });
  const p4 = sem.acquire().then((r) => {
    order.push('fourth');
    return r;
  });
  await new Promise((r) => setImmediate(r));
  assert.equal(sem.active, 2);
  assert.equal(sem.waiting, 2);
  assert.deepEqual(order, []);
  r1();
  r1(); // a second call must not free another slot
  const r3 = await p3;
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(order, ['third']);
  assert.equal(sem.active, 2);
  r2();
  const r4 = await p4;
  assert.deepEqual(order, ['third', 'fourth']);
  r3();
  r4();
  assert.equal(sem.active, 0);
});

test('heartbeat: beats while the work runs and stops afterwards', async () => {
  let beats = 0;
  const value = await withHeartbeat(
    () => {
      beats += 1;
    },
    () => new Promise((r) => setTimeout(() => r('done'), 130)),
    25
  );
  assert.equal(value, 'done');
  assert.ok(beats >= 3, `beats=${beats}`);
  const after = beats;
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(beats, after, 'no beats after the work finished');
  // A failing beat never fails the work; a failing job still stops the timer.
  await withHeartbeat(() => Promise.reject(new Error('db down')), () => new Promise((r) => setTimeout(r, 60)), 10);
  await assert.rejects(withHeartbeat(() => {}, async () => { throw new Error('boom'); }, 10), /boom/);
});

test('file names: zip exports are named .zip; slide images are numbered by deck position', () => {
  assert.equal(exportFileExt({ format: 'PNG', s3Key: 'presentations/w/d/exports/e1.zip' }), 'zip');
  assert.equal(exportFileExt({ format: 'PNG', s3Key: 'presentations/w/d/exports/e1.png' }), 'png');
  assert.equal(exportFileExt({ format: 'JPEG' }), 'jpg');
  assert.equal(exportFileExt({ format: 'PDF', s3Key: null }), 'pdf');
  assert.equal(slideImageFilename('Q3 Plan: "final"', 3, 'png'), 'Q3 Plan final-slide-03.png');
  assert.equal(slideImageFilename('', 12, 'jpg'), 'presentation-slide-12.jpg');
});

test('PDF timeout grows with the deck and is capped', () => {
  assert.equal(pdfRenderTimeoutMs(1), 180_000);
  assert.equal(pdfRenderTimeoutMs(40), 320_000);
  assert.equal(pdfRenderTimeoutMs(1000), 15 * 60 * 1000);
});

test('errors: users get a plain message, never a stack or driver error', () => {
  assert.equal(normalizeExportError(new BrowserUnavailableError()), EXPORT_ERROR_MESSAGES.browser);
  assert.equal(
    normalizeExportError(new Error('Could not find Chrome (ver. 150.0.7871.24). This can occur if…')),
    EXPORT_ERROR_MESSAGES.browser
  );
  assert.equal(
    normalizeExportError(new Error('Failed to launch the browser process! /app/chrome: error while loading shared libraries')),
    EXPORT_ERROR_MESSAGES.browser
  );
  assert.match(normalizeExportError(new Error('Navigation timeout of 180000 ms exceeded')), /timed out \(180s limit\)/);
  assert.equal(normalizeExportError(new Error('Protocol error (Page.printToPDF): Target closed')), EXPORT_ERROR_MESSAGES.crashed);
  assert.equal(normalizeExportError(new Error('connect ECONNREFUSED 10.0.0.1:5432')), EXPORT_ERROR_MESSAGES.generic);
  assert.equal(normalizeExportError(new AppError('No slides to export', 400)), 'No slides to export');
  assert.equal(normalizeExportError(new AppError('db exploded', 500)), EXPORT_ERROR_MESSAGES.generic);
});

test('stale check: a queued job that keeps beating is not stale', () => {
  const old = new Date(Date.now() - 10 * 60 * 1000);
  assert.equal(exportService.exportJobIsStale({ status: 'QUEUED', createdAt: old, updatedAt: new Date() }), false);
  assert.equal(exportService.exportJobIsStale({ status: 'QUEUED', createdAt: old, updatedAt: old }), true);
});

// ── processExport end to end (real headless browser, stubbed DB / S3) ───────────

test('PNG export of several slides: a working .zip, named .zip, files in deck order', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('b', 2, '#10B981'), slide('a', 1, '#2563EB'), slide('c', 3, '#F97316')]));
  const id = queueRow('PNG');
  await run(id);
  const row = rows.get(id);
  assert.equal(row.status, 'READY', row.error);
  assert.match(row.s3Key, /\.zip$/);
  const zip = await JSZip.loadAsync(uploads.get(row.s3Key), { checkCRC32: true });
  assert.deepEqual(Object.keys(zip.files), ['Q3 Plan-slide-01.png', 'Q3 Plan-slide-02.png', 'Q3 Plan-slide-03.png']);
  const png = await zip.file('Q3 Plan-slide-01.png').async('nodebuffer');
  assert.equal(png.readUInt32BE(16), 960, 'slide width');

  const status = await exportService.getExport({ workspaceId: 'w1', presentationId: 'p1', exportId: id });
  assert.equal(status.filename, 'Q3 Plan.zip');
  assert.match(status.presignedUrl, /filename="Q3 Plan\.zip"/);
});

test('PNG export of one slide: a single .png named after the deck', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981')]));
  const id = queueRow('PNG');
  await run(id, { slideId: 'b' });
  const row = rows.get(id);
  assert.equal(row.status, 'READY', row.error);
  assert.match(row.s3Key, /\.png$/);
  const status = await exportService.getExport({ workspaceId: 'w1', presentationId: 'p1', exportId: id });
  assert.equal(status.filename, 'Q3 Plan.png');
});

test('PDF export: one page per slide, heartbeats sent while rendering', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981'), slide('c', 3, '#F97316')]));
  const id = queueRow('PDF');
  statusLog.length = 0;
  await run(id);
  const row = rows.get(id);
  assert.equal(row.status, 'READY', row.error);
  const pdf = uploads.get(row.s3Key);
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
  assert.equal((pdf.toString('latin1').match(/\/Type\s*\/Page[^s]/g) || []).length, 3);
  const beatsWhileRendering = statusLog.filter((e) => e.id === id && e.beat && e.status === 'RENDERING').length;
  assert.ok(beatsWhileRendering >= 1, `heartbeats during render: ${beatsWhileRendering}`);
});

test('browser exports are capped at 2 at once; the rest wait as QUEUED and still finish', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981')]));
  const ids = [queueRow('PDF'), queueRow('PNG'), queueRow('JPEG'), queueRow('PDF')];
  let maxRunning = 0;
  let maxWaiting = 0;
  let queuedWhileOthersRender = false;
  const sample = setInterval(() => {
    const s = exportService.exportQueueStats();
    maxRunning = Math.max(maxRunning, s.running);
    maxWaiting = Math.max(maxWaiting, s.waiting);
    const statuses = ids.map((id) => rows.get(id).status);
    if (statuses.includes('QUEUED') && statuses.filter((x) => x === 'RENDERING').length === 2) {
      queuedWhileOthersRender = true;
    }
  }, 5);
  try {
    await Promise.all(ids.map((id) => run(id)));
  } finally {
    clearInterval(sample);
  }
  for (const id of ids) assert.equal(rows.get(id).status, 'READY', `${id}: ${rows.get(id).error}`);
  assert.equal(maxRunning, 2, 'never more than 2 browser exports at once');
  assert.equal(maxWaiting, 2, 'the other two waited');
  assert.ok(queuedWhileOthersRender, 'waiting jobs stay QUEUED while two render');
  assert.deepEqual(exportService.exportQueueStats(), { running: 0, waiting: 0, limit: 2 });
});

test('PPTX: a stock photo (not on S3) is embedded, not replaced by a grey box', async () => {
  const sharp = require('sharp');
  const http = require('http');
  const png = await sharp({ create: { width: 40, height: 30, channels: 3, background: '#ff0000' } }).png().toBuffer();
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'image/png' });
    res.end(png);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const originalGet = s3Service.getObjectBuffer;
  s3Service.getObjectBuffer = async (key) => {
    throw Object.assign(new Error(`NoSuchKey: ${key}`), { name: 'NoSuchKey' });
  };
  try {
    const s = slide('a', 1, '#2563EB');
    s.elements.elements.push({
      id: 'photo',
      type: 'image',
      layer: 3,
      placement: { x: 500, y: 80, width: 300, height: 200 },
      content: { url: `http://127.0.0.1:${server.address().port}/photos/pexels-1.png` },
    });
    decks.set('deck1', deckOf([s]));
    const id = queueRow('PPTX');
    await run(id);
    const row = rows.get(id);
    assert.equal(row.status, 'READY', row.error);
    const zip = await JSZip.loadAsync(uploads.get(row.s3Key), { checkCRC32: true });
    const xml = await zip.file('ppt/slides/slide1.xml').async('string');
    assert.equal((xml.match(/<p:pic>/g) || []).length, 1, 'the photo is a picture');
    assert.ok(!/<a:t>image<\/a:t>/.test(xml), 'no "image" placeholder');
  } finally {
    s3Service.getObjectBuffer = originalGet;
    server.close();
  }
});

test('a slide that never finishes loading fails the export (no partial zip)', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  const http = require('http');
  const hanging = http.createServer(() => {}); // never answers
  await new Promise((r) => hanging.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${hanging.address().port}/photo.jpg`;
  try {
    const stuck = slide('b', 2, '#10B981');
    stuck.elements.elements.push({
      id: 'img',
      type: 'image',
      layer: 3,
      placement: { x: 500, y: 80, width: 300, height: 200 },
      content: { url },
    });
    decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), stuck, slide('c', 3, '#F97316')]));
    const id = queueRow('PNG');
    const started = Date.now();
    await run(id);
    const row = rows.get(id);
    assert.equal(row.status, 'FAILED');
    assert.match(row.error, /timed out/);
    assert.equal(row.s3Key, undefined, 'nothing uploaded');
    assert.ok(Date.now() - started < 20_000, 'stops at the first failed slide');
  } finally {
    hanging.closeAllConnections?.();
    hanging.close();
  }
});

test('a failure stores a plain message (and frees the browser slot)', async () => {
  decks.set('deck1', new Error('connect ECONNREFUSED 10.0.0.1:5432'));
  const id = queueRow('PDF');
  await run(id);
  assert.equal(rows.get(id).status, 'FAILED');
  assert.equal(rows.get(id).error, EXPORT_ERROR_MESSAGES.generic);

  // The slot was released: two more PDF jobs can still start right away.
  decks.set('deck1', deckOf([]));
  const a = queueRow('PDF');
  const b = queueRow('PDF');
  await Promise.all([run(a), run(b)]);
  for (const x of [a, b]) assert.notEqual(rows.get(x).status, 'QUEUED');
});
