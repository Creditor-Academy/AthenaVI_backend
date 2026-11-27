'use strict';

const assert = require('assert');
const { test } = require('node:test');
const logger = require('../../shared/utils/logger');
const { describeSlideWrite, withSlideWriteLog, slideWriteContextMiddleware, shouldWarn } = require('./slideWriteLog');

const img = (id) => ({ id, type: 'image', content: { url: `https://b.s3.amazonaws.com/${id}.png` } });
const txt = (id) => ({ id, type: 'text', content: { text: id } });
const doc = (elements, extra = {}) => ({ version: 1, canvas: { width: 1920, height: 1080 }, elements, ...extra });

function captureLogs() {
  const lines = { info: [], warn: [] };
  const original = { info: logger.info, warn: logger.warn };
  logger.info = (msg) => lines.info.push(msg);
  logger.warn = (msg) => lines.warn.push(msg);
  return { lines, restore: () => Object.assign(logger, original) };
}

test('describeSlideWrite lists removed images, including images inside groups', () => {
  const before = doc([txt('t1'), img('a'), { id: 'g', type: 'group', children: [img('b')] }], { backgroundImage: 'x' });
  const after = doc([txt('t1'), img('a')]);
  const change = describeSlideWrite(before, after);
  assert.strictEqual(change.imagesBefore, 2);
  assert.strictEqual(change.imagesAfter, 1);
  assert.deepStrictEqual(change.removedImageIds, ['b']);
  assert.strictEqual(change.backgroundImageRemoved, true);
});

test('a write that removes an image logs a warning with the route and user', async () => {
  const logs = captureLogs();
  try {
    const req = { method: 'PUT', originalUrl: '/api/workspaces/w/presentations/p/slides/s1/canvas?x=1' };
    await new Promise((resolve, reject) => {
      slideWriteContextMiddleware(req, {}, () => {
        req.user = { id: 'user-1' }; // set later by the auth middleware
        withSlideWriteLog(
          's1',
          { elements: doc([txt('t1')]) },
          async () => ({ elements: doc([txt('t1'), img('a')]), deckId: 'd1' }),
          async () => ({ id: 's1', deckId: 'd1' })
        ).then(resolve, reject);
      });
    });
    assert.strictEqual(logs.lines.warn.length, 1);
    const entry = JSON.parse(logs.lines.warn[0].replace(/^slide_write removed images /, ''));
    assert.strictEqual(entry.route, 'PUT /api/workspaces/w/presentations/p/slides/s1/canvas');
    assert.strictEqual(entry.userId, 'user-1');
    assert.deepStrictEqual(entry.removedImageIds, ['a']);
    assert.strictEqual(entry.deckId, 'd1');
  } finally {
    logs.restore();
  }
});

test('a write that keeps every image logs info only', async () => {
  const logs = captureLogs();
  try {
    await withSlideWriteLog(
      's1',
      { elements: doc([img('a'), img('b')]) },
      async () => ({ elements: doc([img('a')]) }),
      async () => ({ id: 's1' })
    );
    assert.strictEqual(logs.lines.warn.length, 0);
    assert.strictEqual(logs.lines.info.length, 1);
  } finally {
    logs.restore();
  }
});

test('the save still happens when reading the old slide or logging fails', async () => {
  const logs = captureLogs();
  logger.info = () => {
    throw new Error('logger down');
  };
  try {
    const result = await withSlideWriteLog(
      's1',
      { elements: doc([]) },
      async () => {
        throw new Error('read failed');
      },
      async () => ({ id: 's1', saved: true })
    );
    assert.deepStrictEqual(result, { id: 's1', saved: true });
  } finally {
    logs.restore();
  }
});

test('a failing save still throws, and writes without elements are not read or logged', async () => {
  await assert.rejects(
    withSlideWriteLog('s1', { elements: doc([]) }, async () => null, async () => {
      throw new Error('db down');
    }),
    /db down/
  );
  let read = false;
  const logs = captureLogs();
  try {
    const result = await withSlideWriteLog(
      's1',
      { status: 'READY' },
      async () => {
        read = true;
      },
      async () => 'ok'
    );
    assert.strictEqual(result, 'ok');
    assert.strictEqual(read, false);
    assert.strictEqual(logs.lines.info.length + logs.lines.warn.length, 0);
  } finally {
    logs.restore();
  }
});

test('SLIDE_WRITE_LOG=off skips the read and the log', async () => {
  const before = process.env.SLIDE_WRITE_LOG;
  process.env.SLIDE_WRITE_LOG = 'off';
  let read = false;
  try {
    await withSlideWriteLog('s1', { elements: doc([]) }, async () => {
      read = true;
    }, async () => 'ok');
    assert.strictEqual(read, false);
  } finally {
    if (before === undefined) delete process.env.SLIDE_WRITE_LOG;
    else process.env.SLIDE_WRITE_LOG = before;
  }
});

test('no warning when an image only gets a new id (same count), as on a layout re-save', () => {
  const change = describeSlideWrite(doc([txt('t1'), img('img-old')]), doc([txt('t1'), img('img-new')]));
  assert.deepStrictEqual(change.removedImageIds, ['img-old']);
  assert.strictEqual(shouldWarn(change, 'PUT /api/workspaces/w/presentations/p/slides/s1/canvas'), false);
});

test("no warning for the user's own delete-element request; still warns on a canvas save that drops one", () => {
  const change = describeSlideWrite(doc([img('a'), img('b')]), doc([img('a')]));
  assert.strictEqual(shouldWarn(change, 'DELETE /api/workspaces/w/presentations/p/slides/s1/elements/b'), false);
  assert.strictEqual(shouldWarn(change, 'PUT /api/workspaces/w/presentations/p/slides/s1/canvas'), true);
  assert.strictEqual(shouldWarn(change, undefined), true);
});

test('always warns when the background image is removed', () => {
  const change = describeSlideWrite(doc([img('a')], { backgroundImage: 'x' }), doc([img('a')]));
  assert.strictEqual(shouldWarn(change, 'DELETE /api/workspaces/w/presentations/p/slides/s1/elements/z'), true);
  assert.strictEqual(shouldWarn(change, 'PATCH /api/workspaces/w/presentations/p/slides/s1'), true);
});
