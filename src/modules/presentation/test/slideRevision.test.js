'use strict';

/**
 * Slide revisions (CANVAS_FIX_PLAN_25NOV2026, D-1). Runs the real slide editor, Media attach and
 * presentationDao.updateSlide against one slide kept in memory (Prisma calls faked), and replays
 * the sequences that removed users' images.
 */
const assert = require('assert');
const { test } = require('node:test');
const prisma = require('../../../shared/config/prismaClient');
const presentationDao = require('../presentation.dao');
const slideEditor = require('../slideEditor.service');
const { readSlideRevision } = require('../slideRevision');

const WS = '11111111-1111-1111-1111-111111111111';
const PRESENTATION = 'cabc123456789012345678901';
const ctx = { workspaceId: WS, presentationId: PRESENTATION, slideId: 's1' };
const copy = (v) => JSON.parse(JSON.stringify(v));

const textBox = {
  id: 'txt_title',
  type: 'text',
  layer: 1,
  placement: { x: 160, y: 120, width: 1600, height: 140, rotation: 0, opacity: 1 },
  content: { text: 'Quarterly review', fontSize: 64 },
};
const imageElement = {
  type: 'image',
  placement: { x: 200, y: 300, width: 800, height: 500 },
  content: { url: 'https://bucket.s3.us-east-1.amazonaws.com/w/assets/b.png', s3Key: 'w/assets/b.png', fit: 'cover' },
};

/**
 * One slide in memory behind the Prisma calls updateSlide makes (findUnique, updateMany with an
 * updatedAt guard, update). `beforeConditionalWrite` lets a test land another write in between.
 */
function inMemorySlide() {
  let clock = 1;
  let row = {
    id: 's1',
    deckId: 'deck1',
    order: 1,
    status: 'READY',
    updatedAt: new Date(clock),
    elements: { version: 1, canvas: { width: 1920, height: 1080 }, elements: [copy(textBox)] },
  };
  const restore = [];
  const stub = (obj, key, fn) => {
    const before = obj[key];
    obj[key] = fn;
    restore.push(() => {
      obj[key] = before;
    });
  };
  const state = { beforeConditionalWrite: null, conditionalWrites: 0 };
  const apply = (data) => {
    clock += 1;
    row = { ...row, ...copy(data), updatedAt: new Date(clock) };
  };

  stub(prisma.project, 'findUnique', async () => ({ id: PRESENTATION, workspaceId: WS, type: 'PRESENTATION' }));
  stub(presentationDao, 'findDeckByProjectId', async () => ({
    id: 'deck1',
    projectId: PRESENTATION,
    aspectRatio: '16:9',
    status: 'READY',
    slides: [copy(row)],
  }));
  stub(prisma.slide, 'findUnique', async ({ select } = {}) => {
    const out = copy(row);
    out.updatedAt = new Date(row.updatedAt);
    if (!select) return out;
    return Object.fromEntries(Object.keys(select).map((k) => [k, out[k]]));
  });
  stub(prisma.slide, 'updateMany', async ({ where, data }) => {
    state.conditionalWrites += 1;
    if (state.beforeConditionalWrite) {
      const fn = state.beforeConditionalWrite;
      state.beforeConditionalWrite = null;
      await fn(apply);
    }
    if (where.updatedAt.getTime() !== row.updatedAt.getTime()) return { count: 0 };
    apply(data);
    return { count: 1 };
  });
  stub(prisma.slide, 'update', async ({ data }) => {
    apply(data);
    return copy(row);
  });

  return {
    state,
    /** What a browser tab holds after loading the deck. */
    load: () => copy(row.elements),
    doc: () => copy(row.elements),
    restore: () => restore.reverse().forEach((fn) => fn()),
  };
}

const imageIds = (doc) => doc.elements.filter((el) => el.type === 'image').map((el) => el.id);

test('every elements write bumps the revision', async () => {
  const db = inMemorySlide();
  try {
    assert.strictEqual(readSlideRevision(db.doc()), 0);
    await slideEditor.addElement({ ...ctx, element: copy(imageElement) });
    assert.strictEqual(readSlideRevision(db.doc()), 1);
    const doc = db.load();
    doc.elements[0].content.text = 'Edited';
    await slideEditor.putCanvas({ ...ctx, canvas: doc });
    assert.strictEqual(readSlideRevision(db.doc()), 2);
  } finally {
    db.restore();
  }
});

test('two tabs: a canvas save from the older copy gets 409 and the other tab’s image stays', async () => {
  const db = inMemorySlide();
  try {
    const tabA = db.load();
    const tabARevision = readSlideRevision(tabA);
    const added = await slideEditor.addElement({ ...ctx, element: copy(imageElement) }); // tab B
    tabA.elements[0].content.text = 'Quarterly review (edited)';
    await assert.rejects(
      slideEditor.putCanvas({ ...ctx, canvas: tabA, baseRevision: tabARevision }),
      (err) => err.statusCode === 409
    );
    assert.deepStrictEqual(imageIds(db.doc()), [added.element.id]);
  } finally {
    db.restore();
  }
});

test('a canvas save from the current revision goes through', async () => {
  const db = inMemorySlide();
  try {
    await slideEditor.addElement({ ...ctx, element: copy(imageElement) });
    const doc = db.load();
    doc.elements[0].content.text = 'Edited on the latest copy';
    const out = await slideEditor.putCanvas({ ...ctx, canvas: doc, baseRevision: readSlideRevision(doc) });
    assert.strictEqual(out.slide.elements.elements[0].content.text, 'Edited on the latest copy');
    assert.strictEqual(imageIds(db.doc()).length, 1);
  } finally {
    db.restore();
  }
});

test('older clients (no baseRevision) keep last-write-wins', async () => {
  const db = inMemorySlide();
  try {
    const stale = db.load();
    await slideEditor.addElement({ ...ctx, element: copy(imageElement) });
    await slideEditor.putCanvas({ ...ctx, canvas: stale });
    assert.deepStrictEqual(imageIds(db.doc()), [], 'unchanged behaviour for clients that send no revision');
  } finally {
    db.restore();
  }
});

test('an element edit racing another write is re-applied, not lost', async () => {
  const db = inMemorySlide();
  try {
    // While the element add is writing, another save adds a second text box.
    db.state.beforeConditionalWrite = async (apply) => {
      const doc = db.doc();
      doc.elements.push({ ...copy(textBox), id: 'txt_other', content: { text: 'From the other save' } });
      doc.revision = readSlideRevision(doc) + 1;
      apply({ elements: doc });
    };
    await slideEditor.addElement({ ...ctx, element: copy(imageElement) });
    const ids = db.doc().elements.map((el) => el.id);
    assert.ok(ids.includes('txt_other'), 'the other save is kept');
    assert.strictEqual(imageIds(db.doc()).length, 1, 'the added image is kept');
  } finally {
    db.restore();
  }
});

test('a Media attach racing a canvas save is re-applied on top of it', async () => {
  const db = inMemorySlide();
  const slideMedia = require('../slideMedia.service');
  const assetDao = require('../../asset/asset.dao');
  const s3Service = require('../../s3/s3.service');
  const restore = [];
  const stub = (obj, key, fn) => {
    const before = obj[key];
    obj[key] = fn;
    restore.push(() => {
      obj[key] = before;
    });
  };
  try {
    const asset = { id: 'asset-1', workspaceId: WS, type: 'IMAGE', mimeType: 'image/png', key: 'w/assets/m.png', url: 'https://bucket.s3.us-east-1.amazonaws.com/w/assets/m.png' };
    for (const name of ['findAssetById', 'findById', 'getAssetById', 'findAssetInWorkspace']) {
      if (typeof assetDao[name] === 'function') stub(assetDao, name, async () => asset);
    }
    if (typeof s3Service.getPresignedGetUrl === 'function') stub(s3Service, 'getPresignedGetUrl', async (key) => `https://signed/${key}`);
    if (prisma.asset && typeof prisma.asset.findFirst === 'function') stub(prisma.asset, 'findFirst', async () => asset);
    if (prisma.asset && typeof prisma.asset.findUnique === 'function') stub(prisma.asset, 'findUnique', async () => asset);

    db.state.beforeConditionalWrite = async (apply) => {
      const doc = db.doc();
      doc.elements[0] = { ...doc.elements[0], content: { ...doc.elements[0].content, text: 'Saved meanwhile' } };
      doc.revision = readSlideRevision(doc) + 1;
      apply({ elements: doc });
    };
    await slideMedia.attachAsset({ ...ctx, assetId: 'asset-1' });
    const doc = db.doc();
    assert.strictEqual(doc.elements[0].content.text, 'Saved meanwhile', 'the canvas save is kept');
    assert.strictEqual(imageIds(doc).length, 1, 'the attached image is kept');
  } finally {
    restore.reverse().forEach((fn) => fn());
    db.restore();
  }
});

test('page-close save from an older copy (clientMerge): keeps the image added elsewhere and the client’s edit', async () => {
  const db = inMemorySlide();
  try {
    const stale = db.load();
    const staleRevision = readSlideRevision(stale);
    const added = await slideEditor.addElement({ ...ctx, element: copy(imageElement) }); // other tab
    stale.elements[0].content.text = 'Edited, then the tab closed';
    await slideEditor.putCanvas({
      ...ctx,
      baseRevision: staleRevision,
      canvas: { ...stale, clientMerge: { knownElementIds: stale.elements.map((el) => el.id) } },
    });
    const doc = db.doc();
    assert.strictEqual(doc.elements.find((el) => el.id === 'txt_title').content.text, 'Edited, then the tab closed');
    assert.deepStrictEqual(imageIds(doc), [added.element.id], 'the other tab’s image is kept');
    assert.strictEqual(doc.clientMerge, undefined, 'merge instructions are not stored');
  } finally {
    db.restore();
  }
});

test('page-close merge: an element the client knew and removed stays removed', async () => {
  const db = inMemorySlide();
  try {
    await slideEditor.addElement({ ...ctx, element: copy(imageElement) });
    const loaded = db.load(); // has text + image
    const loadedRevision = readSlideRevision(loaded);
    await slideEditor.addElement({ ...ctx, element: { ...copy(imageElement), content: { ...imageElement.content, url: 'https://bucket.s3.us-east-1.amazonaws.com/w/assets/c.png' } } });
    const knownIds = loaded.elements.map((el) => el.id);
    const withoutFirstImage = { ...loaded, elements: loaded.elements.filter((el) => el.type !== 'image') };
    await slideEditor.putCanvas({
      ...ctx,
      baseRevision: loadedRevision,
      canvas: { ...withoutFirstImage, clientMerge: { knownElementIds: knownIds } },
    });
    const ids = imageIds(db.doc());
    assert.strictEqual(ids.length, 1, 'the image the client removed is gone; the one added elsewhere stays');
    assert.ok(!knownIds.includes(ids[0]));
  } finally {
    db.restore();
  }
});

test('switching layout keeps the images the user added (no slot), on the server too', () => {
  const previous = {
    elements: [
      { id: 'slot-TITLE', slotId: 'TITLE', type: 'text', layer: 1, content: { text: 'Old title' } },
      { id: 'el_f326b4f73738', type: 'image', layer: 5, content: { url: 'https://b/dropped.png' } },
      { id: 'el_0a1b2c3d4e5f', type: 'text', layer: 3, content: { text: 'generated, slot-less' } },
    ],
    backgroundImage: 'https://b/bg.png',
  };
  const compiled = { version: 1, elements: [{ id: 'slot-HEADING', slotId: 'HEADING', type: 'text', layer: 1 }] };
  const out = slideEditor.carryOverUserContent(compiled, previous);
  assert.deepStrictEqual(out.elements.map((el) => el.id), ['slot-HEADING', 'el_f326b4f73738']);
  assert.strictEqual(out.backgroundImage, 'https://b/bg.png');
});
