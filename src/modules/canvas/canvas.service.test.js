const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const SRC = path.resolve(__dirname, '../..');

function stub(relPath, exports) {
  const file = require.resolve(path.join(SRC, relPath));
  require.cache[file] = { id: file, filename: file, loaded: true, exports };
}

const WS = '11111111-1111-1111-1111-111111111111';
const CANVAS = '22222222-2222-2222-2222-222222222222';
const FOLDER = '33333333-3333-3333-3333-333333333333';
const USER = 'user-1';

/** In-memory project table; `updatedAt` moves on every write like Prisma's @updatedAt. */
const db = { projects: new Map(), clock: 1000, failNextConditionalWrites: 0 };

function tick() {
  db.clock += 1;
  return new Date(db.clock);
}

stub('modules/project/project.dao.js', {
  findFolderById: async (id) => (id === FOLDER ? { id, workspaceId: WS } : null),
  findProjectById: async (workspaceId, id) => {
    const row = db.projects.get(id);
    return row && row.workspaceId === workspaceId ? { ...row } : null;
  },
  createProject: async (data) => {
    const row = { id: CANVAS, ...data, updatedAt: tick() };
    db.projects.set(row.id, row);
    return { ...row };
  },
  updateProject: async (id, data) => {
    const row = { ...db.projects.get(id), ...data, updatedAt: tick() };
    db.projects.set(id, row);
    return { ...row };
  },
  updateProjectIfUnchanged: async (id, expectedUpdatedAt, data) => {
    const row = db.projects.get(id);
    if (db.failNextConditionalWrites > 0) {
      db.failNextConditionalWrites -= 1;
      return false;
    }
    if (!row || row.updatedAt.getTime() !== expectedUpdatedAt.getTime()) return false;
    db.projects.set(id, { ...row, ...data, updatedAt: tick() });
    return true;
  },
});
stub('modules/project/projectStorage.service.js', { recalculateProjectStorage: async () => 0 });
stub('modules/project/project.format.js', {
  enrichProject: async (project) => project,
  enrichProjects: async (projects) => projects,
});

const canvasService = require('./canvas.service');
const {
  scrubLocalUrls,
  readRevision,
  isRevisionConflict,
  normalizeCanvasData,
} = require('./canvas.data');
const { saveCanvasDataSchema } = require('../validations/canvas.validations');

function page(elements = []) {
  return { id: 'canvas-1', width: 1080, height: 1080, background: '#FFFFFF', elements };
}

function image(url) {
  return {
    id: 'element-1',
    type: 'image',
    placement: { x: 0, y: 0, width: 100, height: 100 },
    content: { url, src: url },
  };
}

function doc(elements) {
  return { version: 1, docTitle: 'Poster', size: { width: 1080, height: 1080 }, canvases: [page(elements)] };
}

async function seedCanvas() {
  db.projects.clear();
  return canvasService.createCanvas(WS, USER, { name: 'Poster', folderId: FOLDER, data: doc([]) });
}

test('scrubLocalUrls nulls blob: URLs at any depth and leaves others untouched', () => {
  const input = [{ elements: [image('blob:http://localhost/abc')], backgroundImage: 'blob:x' }];
  const { value, count } = scrubLocalUrls(input);
  assert.equal(count, 3);
  assert.equal(value[0].elements[0].content.url, null);
  assert.equal(value[0].elements[0].content.src, null);
  assert.equal(value[0].backgroundImage, null);

  const clean = [{ elements: [image('https://cdn.example.com/a.png')] }];
  const result = scrubLocalUrls(clean);
  assert.equal(result.count, 0);
  assert.equal(result.value, clean, 'unchanged input keeps its identity');
});

test('readRevision treats missing or invalid revisions as 0', () => {
  assert.equal(readRevision(undefined), 0);
  assert.equal(readRevision({}), 0);
  assert.equal(readRevision({ revision: -3 }), 0);
  assert.equal(readRevision({ revision: 7 }), 7);
});

test('isRevisionConflict only fires when a base revision is given and differs', () => {
  assert.equal(isRevisionConflict(undefined, 4), false);
  assert.equal(isRevisionConflict(null, 4), false);
  assert.equal(isRevisionConflict(4, 4), false);
  assert.equal(isRevisionConflict(3, 4), true);
});

test('normalizeCanvasData stamps the server revision and scrubs blob URLs', () => {
  const normalized = normalizeCanvasData(
    { ...doc([image('blob:abc')]), revision: 999 },
    { revision: 5 }
  );
  assert.equal(normalized.revision, 5, 'client-supplied revision is ignored');
  assert.equal(normalized.canvases[0].elements[0].content.url, null);
});

test('saveCanvasDataSchema keeps baseRevision and enforces the element cap', () => {
  const params = { workspaceId: WS, canvasId: CANVAS };
  const ok = saveCanvasDataSchema.validate(
    { params, body: { data: doc([]), baseRevision: 3 } },
    { stripUnknown: true }
  );
  assert.equal(ok.error, undefined);
  assert.equal(ok.value.body.baseRevision, 3);

  const many = Array.from({ length: 201 }, (_, i) => ({ ...image('https://x/a.png'), id: `e${i}` }));
  const tooMany = saveCanvasDataSchema.validate({ params, body: { data: doc(many) } });
  assert.ok(tooMany.error, '201 elements on one page is rejected');
});

test('createCanvas starts the document at revision 1', async () => {
  const created = await seedCanvas();
  assert.equal(created.data.revision, 1);
});

test('saveCanvasData increments the revision on each save', async () => {
  await seedCanvas();
  const first = await canvasService.saveCanvasData(WS, CANVAS, USER, doc([]), { baseRevision: 1 });
  assert.equal(first.data.revision, 2);
  const second = await canvasService.saveCanvasData(WS, CANVAS, USER, doc([]), { baseRevision: 2 });
  assert.equal(second.data.revision, 3);
});

test('saveCanvasData refuses a stale base revision with 409', async () => {
  await seedCanvas();
  await canvasService.saveCanvasData(WS, CANVAS, USER, doc([]), { baseRevision: 1 });
  await assert.rejects(
    canvasService.saveCanvasData(WS, CANVAS, USER, doc([]), { baseRevision: 1 }),
    (error) => error.statusCode === 409
  );
});

test('saveCanvasData without a base revision keeps last-write-wins', async () => {
  await seedCanvas();
  await canvasService.saveCanvasData(WS, CANVAS, USER, doc([]), { baseRevision: 1 });
  const saved = await canvasService.saveCanvasData(WS, CANVAS, USER, doc([]));
  assert.equal(saved.data.revision, 3);
});

test('saveCanvasData retries when an unrelated write moved updatedAt', async () => {
  await seedCanvas();
  db.failNextConditionalWrites = 1;
  const saved = await canvasService.saveCanvasData(WS, CANVAS, USER, doc([]), { baseRevision: 1 });
  assert.equal(saved.data.revision, 2);
});

test('saveCanvasData gives up with 409 when the row keeps changing', async () => {
  await seedCanvas();
  db.failNextConditionalWrites = 10;
  await assert.rejects(
    canvasService.saveCanvasData(WS, CANVAS, USER, doc([]), { baseRevision: 1 }),
    (error) => error.statusCode === 409
  );
  db.failNextConditionalWrites = 0;
});

test('saveCanvasData never stores a blob: URL', async () => {
  await seedCanvas();
  const saved = await canvasService.saveCanvasData(
    WS,
    CANVAS,
    USER,
    doc([image('blob:http://localhost/dead')]),
    { baseRevision: 1 }
  );
  assert.equal(saved.data.canvases[0].elements[0].content.url, null);
});

test('saveCanvasData returns 404 for a project that is not a canvas', async () => {
  db.projects.set('video-1', { id: 'video-1', workspaceId: WS, type: 'VIDEO', data: {}, updatedAt: tick() });
  await assert.rejects(
    canvasService.saveCanvasData(WS, 'video-1', USER, doc([])),
    (error) => error.statusCode === 404
  );
});
