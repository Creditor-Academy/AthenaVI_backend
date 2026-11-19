'use strict';

// Fast heartbeats so the tests can see them during a real render.
process.env.PPT_EXPORT_HEARTBEAT_INTERVAL_MS = '40';
process.env.PPT_EXPORT_MAX_CONCURRENT_BROWSER = '2';
// Short render timeout so the "slide never loads" case fails quickly.
process.env.PPT_EXPORT_PUPPETEER_TIMEOUT_MS = '5000';

// Phase 6: a shared browser, replaced after 4 exports in these tests.
process.env.PPT_EXPORT_BROWSER_MAX_JOBS = '4';
// The queue runs in this process (no Redis in tests).
process.env.PPT_EXPORT_QUEUE = 'local';

const assert = require('assert');
const { test, before, after } = require('node:test');
const JSZip = require('jszip');

const {
  createSemaphore,
  withHeartbeat,
  pdfRenderTimeoutMs,
  exportFileExt,
  slideImageFilename,
  normalizeExportError,
  isRetryableExportError,
  exportProgress,
  exportJobTimeoutMs,
  queueVerdict,
  EXPORT_ERROR_MESSAGES,
} = require('../exportJob.util');
const exportMetrics = require('../exportMetrics');
const logger = require('../../../shared/utils/logger');
const AppError = require('../../../shared/utils/AppError');
const {
  checkExportBrowser,
  BrowserUnavailableError,
  ExportCancelledError,
  closeSharedBrowser,
  exportBrowserStats,
} = require('../../../shared/utils/exportBrowser');

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
  statusLog.push({ id, status: row.status, beat: false });
  return row;
};
// Conditional update (cancel, claim, finish, heartbeat). An empty update is a heartbeat.
presentationDao.updateExportIfStatus = async (id, statuses, data) => {
  const current = rows.get(id);
  if (!current || !statuses.includes(current.status)) return 0;
  const row = { ...current, ...data, updatedAt: new Date() };
  rows.set(id, row);
  statusLog.push({ id, status: row.status, beat: Object.keys(data).length === 0 });
  return 1;
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
s3Service.deleteFile = async (key) => {
  uploads.delete(key);
};
s3Service.getPresignedGetUrl = async (key, _sec, opts) => `https://s3.test/${key}#${opts?.responseContentDisposition}`;
const charges = [];
presentationCredit.chargeFlat = async (args) => {
  charges.push(args.idempotencyKey);
  return { skipped: true };
};
const notifications = [];
inboxService.notifyUser = async (n) => {
  notifications.push(n);
};
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

test('file names: zip exports are named .zip; slide images are named by page number, as Canva does', () => {
  assert.equal(exportFileExt({ format: 'PNG', s3Key: 'presentations/w/d/exports/e1.zip' }), 'zip');
  assert.equal(exportFileExt({ format: 'PNG', s3Key: 'presentations/w/d/exports/e1.png' }), 'png');
  assert.equal(exportFileExt({ format: 'JPEG' }), 'jpg');
  assert.equal(exportFileExt({ format: 'PDF', s3Key: null }), 'pdf');
  assert.equal(slideImageFilename('Q3 Plan: "final"', 3, 'png'), '3.png');
  assert.equal(slideImageFilename('', 12, 'jpg'), '12.jpg');
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
  assert.deepEqual(Object.keys(zip.files), ['1.png', '2.png', '3.png']);
  const png = await zip.file('1.png').async('nodebuffer');
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

// ── Phase 6: queue, shared browser, progress, cancel, retry ─────────────────────

const exportQueue = require('../exportQueue');

after(async () => {
  await closeSharedBrowser();
});

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(check, timeoutMs = 15_000, label = 'condition') {
  const started = Date.now();
  while (!check()) {
    if (Date.now() - started > timeoutMs) throw new Error(`Timed out waiting for ${label}`);
    await wait(10);
  }
}

/** A slide with a picture that never loads (the render waits for it until the 5s test timeout). */
async function hangingServer() {
  const http = require('http');
  const server = http.createServer(() => {});
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    url: `http://127.0.0.1:${server.address().port}/photo.jpg`,
    close() {
      server.closeAllConnections?.();
      server.close();
    },
  };
}
function stuckSlide(id, order, url) {
  const s = slide(id, order, '#10B981');
  s.elements.elements.push({ id: 'img', type: 'image', layer: 3, placement: { x: 500, y: 80, width: 300, height: 200 }, content: { url } });
  return s;
}

const jobData = (exportId, extra = {}) => ({
  exportId,
  workspaceId: 'w1',
  userId: 'u1',
  projectId: 'p1',
  projectName: 'Q3 Plan',
  ...extra,
});
const cancel = (exportId) => exportService.cancelExport({ workspaceId: 'w1', presentationId: 'p1', exportId, userId: 'u1' });

test('retry rule: only browser crashes are retried, never bad requests, timeouts or cancels', () => {
  assert.equal(isRetryableExportError(new Error('Protocol error (Page.captureScreenshot): Target closed')), true);
  assert.equal(isRetryableExportError(new Error('Navigating frame was detached: browser has disconnected')), true);
  assert.equal(isRetryableExportError(new AppError('No slides to export', 400)), false);
  assert.equal(isRetryableExportError(new Error('Navigation timeout of 180000 ms exceeded')), false);
  assert.equal(isRetryableExportError(new BrowserUnavailableError()), false);
  assert.equal(isRetryableExportError(new ExportCancelledError()), false);
  assert.equal(isRetryableExportError(new Error('connect ECONNREFUSED 10.0.0.1:5432')), false);
});

test('progress: percentages per format and stage', () => {
  assert.deepEqual(exportProgress('PNG', 'drawing', 2, 4), { stage: 'drawing', percent: 50, done: 2, total: 4 });
  assert.equal(exportProgress('PNG', 'queued').percent, 0);
  assert.equal(exportProgress('PDF', 'building').percent, 70);
  assert.equal(exportProgress('PPTX', 'building', 5, 5).percent, 92);
  assert.equal(exportProgress('JPEG', 'saving').percent, 95);
  assert.equal(exportProgress('PDF', 'done').percent, 100);
  assert.equal(exportProgress('PNG', 'drawing', 9, 4).percent, 90, 'never past the end of its step');
});

test('semaphore: a waiter that is cancelled leaves the line', async () => {
  const sem = createSemaphore(1);
  const release = await sem.acquire();
  const controller = new AbortController();
  const waiting = sem.acquire({ signal: controller.signal });
  assert.equal(sem.waiting, 1);
  controller.abort();
  await assert.rejects(waiting);
  assert.equal(sem.waiting, 0);
  release();
  assert.equal(sem.active, 0);
});

test('progress: a PNG export reports each slide, in order, up to 100%', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981'), slide('c', 3, '#F97316')]));
  const id = queueRow('PNG');
  const seen = [];
  const outcome = await exportService.runExportJob(jobData(id), { onProgress: (p) => seen.push(p) });
  assert.equal(outcome, 'READY');
  const percents = seen.map((p) => p.percent);
  assert.deepEqual([...percents].sort((a, b) => a - b), percents, `never goes backwards: ${percents}`);
  assert.deepEqual(
    seen.filter((p) => p.stage === 'drawing' && p.done > 0).map((p) => `${p.done}/${p.total}`),
    ['1/3', '2/3', '3/3']
  );
  assert.deepEqual(seen.at(-1), { stage: 'done', percent: 100, done: 0, total: 0 });
  assert.ok(seen.some((p) => p.stage === 'saving'));
});

test('status shows live progress while an export runs', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  const hang = await hangingServer();
  try {
    decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), stuckSlide('b', 2, hang.url)]));
    const id = queueRow('PNG');
    await exportQueue.enqueue(jobData(id));
    // Slide 1 is drawn; slide 2 waits for its picture.
    let status;
    for (let i = 0; i < 400 && !(status?.progress?.done === 1); i += 1) {
      status = await exportService.getExport({ workspaceId: 'w1', presentationId: 'p1', exportId: id });
      await wait(25);
    }
    assert.equal(status.status, 'RENDERING');
    assert.equal(status.progress.stage, 'drawing');
    assert.equal(status.progress.done, 1);
    assert.equal(status.progress.total, 2);
    assert.equal(status.progress.percent, 50);
    await cancel(id);
    await until(() => exportQueue.stats().runningHere === 0, 10_000, 'job to stop');
  } finally {
    hang.close();
  }
});

test('cancel a running export: it stops at once, nothing is uploaded or charged, no inbox message', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  const hang = await hangingServer();
  try {
    decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), stuckSlide('b', 2, hang.url), slide('c', 3, '#F97316')]));
    const id = queueRow('PNG');
    const chargesBefore = charges.length;
    const notificationsBefore = notifications.length;
    await exportQueue.enqueue(jobData(id));
    await until(() => rows.get(id).status === 'RENDERING', 10_000, 'RENDERING');
    await wait(300); // inside the render, waiting on slide 2's picture
    const startedAt = Date.now();
    const result = await cancel(id);
    assert.deepEqual(result, { exportId: id, format: 'PNG', status: 'CANCELLED', creditsCharged: 0 });
    await until(() => exportQueue.stats().runningHere === 0, 10_000, 'job to stop');
    assert.ok(Date.now() - startedAt < 2_000, `stopped in ${Date.now() - startedAt}ms (the hang lasts 5s)`);
    assert.equal(rows.get(id).status, 'CANCELLED');
    assert.equal(rows.get(id).s3Key, undefined, 'nothing uploaded');
    assert.equal(charges.length, chargesBefore, 'no credits charged');
    assert.equal(notifications.length, notificationsBefore, 'no inbox message');
    const status = await exportService.getExport({ workspaceId: 'w1', presentationId: 'p1', exportId: id });
    assert.equal(status.status, 'CANCELLED');
    assert.equal(status.progress, undefined);
  } finally {
    hang.close();
  }
  // The shared browser is still fine for the next export.
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB')]));
  const next = queueRow('PDF');
  assert.equal(await exportService.runExportJob(jobData(next)), 'READY');
});

test('cancel a queued export (waiting for a free browser): it never starts', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  const hang = await hangingServer();
  try {
    decks.set('deck1', deckOf([stuckSlide('b', 1, hang.url)]));
    const busy = [queueRow('PNG'), queueRow('PNG')];
    for (const id of busy) await exportQueue.enqueue(jobData(id));
    await until(() => busy.every((id) => rows.get(id).status === 'RENDERING'), 10_000, 'both slots busy');
    const waiting = queueRow('PDF');
    await exportQueue.enqueue(jobData(waiting));
    await until(() => exportService.exportQueueStats().waiting === 1, 5_000, 'third job waiting');
    assert.equal(rows.get(waiting).status, 'QUEUED');
    await cancel(waiting);
    await until(() => exportService.exportQueueStats().waiting === 0, 2_000, 'waiter to leave');
    assert.equal(rows.get(waiting).status, 'CANCELLED');
    assert.ok(!statusLog.some((e) => e.id === waiting && e.status === 'RENDERING'), 'it never rendered');
    for (const id of busy) await cancel(id);
    await until(() => exportQueue.stats().runningHere === 0, 10_000, 'jobs to stop');
    assert.deepEqual(exportService.exportQueueStats(), { running: 0, waiting: 0, limit: 2 });
  } finally {
    hang.close();
  }
});

test('cancel: a finished export cannot be cancelled; cancelling twice is harmless', async () => {
  const ready = queueRow('PDF');
  rows.set(ready, { ...rows.get(ready), status: 'READY', s3Key: 'k.pdf' });
  await assert.rejects(cancel(ready), (err) => err.statusCode === 409);
  const saving = queueRow('PDF');
  rows.set(saving, { ...rows.get(saving), status: 'SAVING' });
  await assert.rejects(cancel(saving), (err) => err.statusCode === 409);

  const queued = queueRow('PDF');
  assert.equal((await cancel(queued)).status, 'CANCELLED');
  assert.equal((await cancel(queued)).status, 'CANCELLED');
  // A job picked up after it was cancelled does nothing.
  assert.equal(await exportService.runExportJob(jobData(queued)), 'SKIPPED');
  assert.equal(rows.get(queued).status, 'CANCELLED');

  const otherDeck = queueRow('PDF', 'deck2');
  await assert.rejects(cancel(otherDeck), (err) => err.statusCode === 404);
});

test('a cancel that lands during the upload wins: the file is removed and nothing is charged', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB')]));
  const id = queueRow('PDF');
  const originalUpload = s3Service.uploadFileToKey;
  s3Service.uploadFileToKey = async (buffer, key) => {
    uploads.set(key, buffer);
    rows.set(id, { ...rows.get(id), status: 'CANCELLED' }); // the user pressed Cancel meanwhile
  };
  const chargesBefore = charges.length;
  try {
    assert.equal(await exportService.runExportJob(jobData(id)), 'CANCELLED');
  } finally {
    s3Service.uploadFileToKey = originalUpload;
  }
  await wait(20);
  assert.equal(rows.get(id).status, 'CANCELLED');
  assert.equal(charges.length, chargesBefore);
  assert.ok(![...uploads.keys()].some((k) => k.includes(id)), 'uploaded file removed');
});

test('shared browser: exports reuse one browser and a fresh one starts after PPT_EXPORT_BROWSER_MAX_JOBS', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  await closeSharedBrowser();
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB')]));
  const before = exportBrowserStats().launches;
  for (let i = 0; i < 4; i += 1) {
    assert.equal(await exportService.runExportJob(jobData(queueRow('PNG'))), 'READY');
  }
  assert.equal(exportBrowserStats().launches - before, 1, 'four exports, one browser');
  assert.equal(exportBrowserStats().servedByCurrent, 4);
  assert.equal(await exportService.runExportJob(jobData(queueRow('PNG'))), 'READY');
  assert.equal(exportBrowserStats().launches - before, 2, 'the fifth export starts a fresh browser');
  assert.equal(exportBrowserStats().active, 0);
});

test('a browser crash mid-export is retried once with a fresh browser and the export succeeds', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981'), slide('c', 3, '#F97316')]));
  const id = queueRow('PNG');
  const before = exportBrowserStats().launches;
  let killed = false;
  const outcome = await exportService.runExportJob(jobData(id), {
    onProgress: (p) => {
      // After the first slide, kill the browser process (as an out-of-memory kill would).
      if (!killed && p.stage === 'drawing' && p.done === 1) {
        killed = true;
        process.kill(exportBrowserStats().pid, 'SIGKILL');
      }
    },
  });
  assert.ok(killed, 'the browser was killed mid-export');
  assert.equal(outcome, 'READY', rows.get(id).error);
  assert.equal(rows.get(id).status, 'READY');
  assert.ok(exportBrowserStats().launches - before >= 1, 'a new browser was started');
  const zip = await JSZip.loadAsync(uploads.get(rows.get(id).s3Key));
  assert.deepEqual(Object.keys(zip.files), ['1.png', '2.png', '3.png']);
});

test('a second crash fails the export with a plain message (only one retry)', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981')]));
  const id = queueRow('PNG');
  let kills = 0;
  const outcome = await exportService.runExportJob(jobData(id), {
    onProgress: (p) => {
      if (p.stage === 'drawing' && p.done === 1) {
        kills += 1;
        process.kill(exportBrowserStats().pid, 'SIGKILL');
      }
    },
  });
  assert.equal(kills, 2, 'first try and the retry');
  assert.equal(outcome, 'FAILED');
  assert.equal(rows.get(id).error, EXPORT_ERROR_MESSAGES.crashed);
});

test('status: the queue decides while it tracks the job; the heartbeat only for jobs it cannot see', async () => {
  const minutesAgo = (m) => new Date(Date.now() - m * 60 * 1000);
  const original = { jobStatus: exportQueue.jobStatus, cancel: exportQueue.cancel };
  const removed = [];
  let queueState = null;
  exportQueue.jobStatus = async () => ({ state: queueState, progress: null });
  exportQueue.cancel = async (id) => {
    removed.push(id);
    return { aborted: false, removed: true };
  };
  const status = (id) => exportService.getExport({ workspaceId: 'w1', presentationId: 'p1', exportId: id });
  try {
    // Waiting in a backlog for 10 minutes: still fine (no heartbeat while waiting in BullMQ).
    queueState = 'waiting';
    let id = queueRow('PDF');
    rows.set(id, { ...rows.get(id), createdAt: minutesAgo(10), updatedAt: minutesAgo(10) });
    assert.equal((await status(id)).status, 'QUEUED');
    // Waiting 20 minutes: past the queue limit, given up and taken off the queue.
    rows.set(id, { ...rows.get(id), createdAt: minutesAgo(20), updatedAt: minutesAgo(20) });
    let s = await status(id);
    assert.equal(s.status, 'FAILED');
    assert.equal(s.error, EXPORT_ERROR_MESSAGES.queueWait);
    assert.deepEqual(removed, [id]);

    // Running with no heartbeat for 20 minutes, but the queue says it's active: no guessing.
    queueState = 'active';
    id = queueRow('PDF');
    rows.set(id, { ...rows.get(id), status: 'RENDERING', updatedAt: minutesAgo(20) });
    assert.equal((await status(id)).status, 'RENDERING');

    // The queue gave up on it (its server died twice): failed at once, even with a fresh beat.
    queueState = 'failed';
    id = queueRow('PDF');
    rows.set(id, { ...rows.get(id), status: 'RENDERING' });
    s = await status(id);
    assert.equal(s.status, 'FAILED');
    assert.equal(s.error, EXPORT_ERROR_MESSAGES.crashed);

    // The job completed between reading the row and asking the queue: the finished row wins.
    queueState = 'completed';
    id = queueRow('PDF');
    rows.set(id, { ...rows.get(id), status: 'RENDERING' });
    exportQueue.jobStatus = async (jobId) => {
      rows.set(jobId, { ...rows.get(jobId), status: 'READY', s3Key: `presentation-exports/w1/deck1/${jobId}.pdf` });
      return { state: 'completed', progress: null };
    };
    assert.equal((await status(id)).status, 'READY');
    exportQueue.jobStatus = async () => ({ state: queueState, progress: null });

    // Not known to the queue (in-process job on some server): the heartbeat decides, as before.
    queueState = null;
    id = queueRow('PDF');
    rows.set(id, { ...rows.get(id), status: 'RENDERING', updatedAt: minutesAgo(20) });
    s = await status(id);
    assert.equal(s.status, 'FAILED');
    assert.equal(s.error, EXPORT_ERROR_MESSAGES.crashed);
  } finally {
    exportQueue.jobStatus = original.jobStatus;
    exportQueue.cancel = original.cancel;
  }
});

// ── Phase 6.6–6.9 ─────────────────────────────────────────────────────────────

test('time limit: grows with the slides, more for big images, capped; env overrides', () => {
  assert.equal(exportJobTimeoutMs('PPTX', 1), 2 * 60 * 1000 + 20_000);
  assert.equal(exportJobTimeoutMs('PDF', 30), 2 * 60 * 1000 + 30 * 10_000);
  assert.ok(exportJobTimeoutMs('PNG', 10, { scale: 3 }) > exportJobTimeoutMs('PNG', 10, { scale: 1 }));
  assert.equal(exportJobTimeoutMs('JPEG', 10, { scale: 3 }), exportJobTimeoutMs('PNG', 10, { scale: 3 }));
  assert.equal(exportJobTimeoutMs('PPTX', 500), 30 * 60 * 1000, 'capped at 30 minutes');
  assert.ok(exportJobTimeoutMs('PDF', 0) > 2 * 60 * 1000, 'never below the base plus one slide');
  process.env.PPT_EXPORT_JOB_TIMEOUT_MAX_MS = '90000';
  try {
    assert.equal(exportJobTimeoutMs('PPTX', 50), 90_000);
  } finally {
    delete process.env.PPT_EXPORT_JOB_TIMEOUT_MAX_MS;
  }
});

test('queue verdict: waiting is fine until the queue limit, active is trusted, ended jobs are given up', () => {
  const now = Date.now();
  const row = (minutes) => ({ createdAt: new Date(now - minutes * 60 * 1000) });
  assert.deepEqual(queueVerdict(row(1), 'waiting', { now }), { ok: true });
  assert.deepEqual(queueVerdict(row(1), 'prioritized', { now }), { ok: true });
  assert.deepEqual(queueVerdict(row(16), 'waiting', { now }), { ok: false, error: EXPORT_ERROR_MESSAGES.queueWait });
  assert.deepEqual(queueVerdict(row(90), 'active', { now }), { ok: true });
  assert.deepEqual(queueVerdict(row(1), 'failed', { now }), { ok: false, error: EXPORT_ERROR_MESSAGES.crashed });
  assert.deepEqual(queueVerdict(row(1), 'completed', { now }), { ok: false, error: EXPORT_ERROR_MESSAGES.crashed });
  assert.deepEqual(queueVerdict(row(1), null, { now }), { ok: null }, 'not in the queue: heartbeat decides');
  assert.equal(isRetryableExportError(new (require('../exportJob.util').ExportTimeoutError)(1000)), false);
  assert.equal(normalizeExportError({ code: 'EXPORT_TIMEOUT', message: 'x' }), EXPORT_ERROR_MESSAGES.tooLong);
});

/** Log lines written while `fn` runs, by event name. */
async function captureLogs(fn) {
  const lines = [];
  const original = { info: logger.info, warn: logger.warn, error: logger.error };
  for (const level of ['info', 'warn', 'error']) {
    logger[level] = (event, data) => {
      lines.push({ level, event, data });
      return original[level].call(logger, event, data);
    };
  }
  try {
    await fn();
  } finally {
    Object.assign(logger, original);
  }
  return lines;
}

test('an export past its time limit stops, fails with a plain message, is not retried and tells the user', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981'), slide('c', 3, '#F97316')]));
  const id = queueRow('PNG');
  charges.length = 0;
  notifications.length = 0;
  exportMetrics.reset();
  process.env.PPT_EXPORT_JOB_TIMEOUT_MAX_MS = '150';
  let outcome;
  const started = Date.now();
  const logs = await captureLogs(async () => {
    try {
      outcome = await exportService.runExportJob(jobData(id, { queuedAt: Date.now() - 1000 }));
    } finally {
      delete process.env.PPT_EXPORT_JOB_TIMEOUT_MAX_MS;
    }
  });
  assert.equal(outcome, 'FAILED');
  assert.ok(Date.now() - started < 10_000, 'stopped promptly');
  assert.equal(rows.get(id).status, 'FAILED');
  assert.equal(rows.get(id).error, EXPORT_ERROR_MESSAGES.tooLong);
  assert.equal(rows.get(id).s3Key, undefined, 'nothing uploaded');
  assert.equal(charges.length, 0, 'nothing charged');
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].type, 'PRESENTATION_EXPORT_FAILED');
  assert.equal(logs.filter((l) => l.event === 'presentation_export_retrying').length, 0, 'not retried');
  const line = logs.find((l) => l.event === 'presentation_export_finished')?.data;
  assert.ok(line, 'one finished line');
  assert.equal(line.outcome, 'FAILED');
  assert.equal(line.timedOut, true);
  assert.equal(line.timeoutMs, 150);
  assert.equal(line.reason, EXPORT_ERROR_MESSAGES.tooLong);
  assert.equal(line.slideCount, 3);
  assert.equal(line.attempts, 1);
  assert.ok(line.queueMs >= 1000, 'time waiting in the queue');
  assert.equal(exportMetrics.snapshot().failed, 1);
});

test('a finished export: one log line with format, slides, size, duration and renderer; files under the export prefix', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB'), slide('b', 2, '#10B981')]));
  const id = queueRow('PNG');
  exportMetrics.reset();
  let outcome;
  const logs = await captureLogs(async () => {
    outcome = await exportService.runExportJob(jobData(id, { queuedAt: Date.now() }));
  });
  assert.equal(outcome, 'READY', rows.get(id).error);
  assert.match(rows.get(id).s3Key, new RegExp(`^presentation-exports/w1/deck1/${id}\\.zip$`));
  const finished = logs.filter((l) => l.event === 'presentation_export_finished');
  assert.equal(finished.length, 1);
  const line = finished[0].data;
  assert.equal(finished[0].level, 'info');
  assert.equal(line.outcome, 'READY');
  assert.equal(line.format, 'PNG');
  assert.equal(line.slideCount, 2);
  assert.equal(line.bytes, uploads.get(rows.get(id).s3Key).length);
  assert.ok(line.durationMs > 0 && line.renderMs > 0);
  assert.ok(line.rendererVersion != null, 'renderer version (or legacy)');
  assert.equal(line.reason, null);
  const snap = exportMetrics.snapshot();
  assert.equal(snap.ready, 1);
  assert.equal(snap.byFormat.PNG.ready, 1);
});

test('restart while saving: the next run finishes the saved file (charged once, READY, inbox) without making it again', async () => {
  const id = queueRow('PDF');
  const key = `presentation-exports/w1/deck1/${id}.pdf`;
  uploads.set(key, Buffer.from('%PDF-saved'));
  rows.set(id, { ...rows.get(id), status: 'SAVING', s3Key: key });
  charges.length = 0;
  notifications.length = 0;
  const uploadsBefore = uploads.size;
  const outcome = await exportService.runExportJob(jobData(id));
  assert.equal(outcome, 'READY');
  assert.equal(rows.get(id).status, 'READY');
  assert.equal(rows.get(id).s3Key, key);
  assert.deepEqual(charges, [`ppt:export:${id}`], 'the same idempotent charge key');
  assert.equal(uploads.size, uploadsBefore, 'nothing rendered or uploaded again');
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].type, 'PRESENTATION_EXPORT_COMPLETED');

  // A SAVING row without its file key (an older row) is not resumed.
  const other = queueRow('PDF');
  rows.set(other, { ...rows.get(other), status: 'SAVING' });
  assert.equal(await exportService.runExportJob(jobData(other)), 'SKIPPED');
});

test('the file key is stored with SAVING, so a restart after the upload can finish the export', async (t) => {
  if (!browserOk) return t.skip('no export browser on this machine');
  decks.set('deck1', deckOf([slide('a', 1, '#2563EB')]));
  const id = queueRow('PNG');
  statusLog.length = 0;
  const seen = [];
  const original = presentationDao.updateExportIfStatus;
  presentationDao.updateExportIfStatus = async (eid, statuses, data) => {
    if (data.status === 'SAVING') seen.push(data.s3Key);
    return original(eid, statuses, data);
  };
  try {
    assert.equal(await run(id), 'READY');
  } finally {
    presentationDao.updateExportIfStatus = original;
  }
  assert.deepEqual(seen, [rows.get(id).s3Key]);
});

test('a lost job (queue gave up) is failed once with a plain message, and the user is told', async () => {
  const id = queueRow('PPTX');
  rows.set(id, { ...rows.get(id), status: 'RENDERING' });
  notifications.length = 0;
  assert.equal(await exportService.failLostExport(jobData(id), new Error('job stalled more than allowable limit')), true);
  assert.equal(rows.get(id).status, 'FAILED');
  assert.equal(rows.get(id).error, EXPORT_ERROR_MESSAGES.crashed);
  assert.equal(notifications.length, 1);
  assert.equal(notifications[0].type, 'PRESENTATION_EXPORT_FAILED');
  // Again (or for an export that finished or was cancelled): nothing happens.
  assert.equal(await exportService.failLostExport(jobData(id), new Error('again')), false);
  const done = queueRow('PDF');
  rows.set(done, { ...rows.get(done), status: 'CANCELLED' });
  assert.equal(await exportService.failLostExport(jobData(done), new Error('x')), false);
  assert.equal(rows.get(done).status, 'CANCELLED');
  assert.equal(notifications.length, 1);
});

test('download links: a fresh link on every request, none once the file has expired (7 days)', async () => {
  const id = queueRow('PDF');
  const daysAgo = (d) => new Date(Date.now() - d * 24 * 60 * 60 * 1000);
  rows.set(id, { ...rows.get(id), status: 'READY', s3Key: `presentation-exports/w1/deck1/${id}.pdf`, updatedAt: daysAgo(6) });
  const status = () => exportService.getExport({ workspaceId: 'w1', presentationId: 'p1', exportId: id });
  let s = await status();
  assert.equal(s.status, 'READY');
  assert.match(s.presignedUrl, /presentation-exports\/w1\/deck1/);
  assert.equal(s.expiresIn, 3600, 'links last an hour');
  rows.set(id, { ...rows.get(id), updatedAt: daysAgo(8) });
  s = await status();
  assert.equal(s.status, 'EXPIRED');
  assert.equal(s.error, EXPORT_ERROR_MESSAGES.expired);
  assert.equal(s.presignedUrl, undefined);
});

test('inbox: finished and failed exports link to the deck with the export, so its dialog can show it', async () => {
  const id = queueRow('PDF');
  const key = `presentation-exports/w1/deck1/${id}.pdf`;
  rows.set(id, { ...rows.get(id), status: 'SAVING', s3Key: key });
  notifications.length = 0;
  await exportService.runExportJob(jobData(id));
  const url = new URL(notifications[0].metadata.actionUrl, 'https://app.test');
  assert.equal(url.pathname, '/dashboard/editor');
  assert.equal(url.searchParams.get('workspaceId'), 'w1');
  assert.equal(url.searchParams.get('presentationId'), 'p1');
  assert.equal(url.searchParams.get('title'), 'Q3 Plan');
  assert.equal(url.searchParams.get('export'), id);
  assert.equal(notifications[0].metadata.exportId, id);
});
