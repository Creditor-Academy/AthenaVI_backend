'use strict';

/**
 * Smoke test for the "images gone the next day" report (CANVAS_FIX_PLAN_25NOV2026, D-0 / D-1).
 *
 * It replays, through the real slide save code, the sequences suspected of removing images, with
 * the database replaced by one in-memory slide. Each test asserts what SHOULD happen:
 *   - a FAILING test confirms the data-loss path exists today;
 *   - a PASSING test rules that path out.
 * Not in `npm test` on purpose (the first two are expected to fail until D-1 ships).
 * Run: node --test src/modules/presentation/test/slideSaveDataLoss.smoke.test.js
 */

const assert = require('assert');
const { test } = require('node:test');
const prisma = require('../../../shared/config/prismaClient');
const presentationDao = require('../presentation.dao');
const slideEditor = require('../slideEditor.service');

const WS = '11111111-1111-1111-1111-111111111111';
const PRESENTATION = 'cabc123456789012345678901';
const BUCKET = 'athena-smoke-bucket';
const REGION = 'us-east-1';
const bucketUrl = (key) => `https://${BUCKET}.s3.${REGION}.amazonaws.com/${key}`;

const textBox = {
  id: 'txt_title',
  type: 'text',
  layer: 1,
  placement: { x: 160, y: 120, width: 1600, height: 140, rotation: 0, opacity: 1 },
  content: { text: 'Quarterly review', fontSize: 64 },
};

function imageContent(key) {
  return { url: bucketUrl(key), src: bucketUrl(key), fit: 'cover', assetId: `asset-${key}` };
}

/** One slide kept in memory; every read returns a fresh copy, every write replaces it. */
function inMemoryDeck() {
  let stored = {
    id: 's1',
    order: 1,
    status: 'READY',
    elements: { version: 1, canvas: { width: 1920, height: 1080 }, elements: [textBox] },
  };
  const writes = [];
  const restore = [];
  const stub = (obj, key, fn) => {
    const before = obj[key];
    obj[key] = fn;
    restore.push(() => {
      obj[key] = before;
    });
  };
  const copy = (v) => JSON.parse(JSON.stringify(v));

  stub(prisma.project, 'findUnique', async () => ({ id: PRESENTATION, workspaceId: WS, type: 'PRESENTATION' }));
  stub(presentationDao, 'findDeckByProjectId', async () => ({
    id: 'deck1',
    aspectRatio: '16:9',
    status: 'READY',
    slides: [copy(stored)],
  }));
  stub(presentationDao, 'findSlideById', async () => copy(stored));
  stub(presentationDao, 'updateSlide', async (slideId, data) => {
    stored = { ...stored, ...copy(data) };
    writes.push(copy(data.elements?.elements || []).map((el) => el.id));
    return copy(stored);
  });

  return {
    /** What a browser tab holds after loading the deck. */
    load: () => copy(stored.elements),
    current: () => copy(stored.elements),
    writes,
    restore: () => restore.reverse().forEach((fn) => fn()),
  };
}

const ctx = { workspaceId: WS, presentationId: PRESENTATION, slideId: 's1' };
const imageIds = (doc) => doc.elements.filter((el) => el.type === 'image').map((el) => el.id);

test('two tabs: an autosave from the other tab must not remove an image added in this tab', async () => {
  const db = inMemoryDeck();
  try {
    // Tab A and tab B both open the deck.
    const tabA = db.load();
    db.load();

    // Tab B adds an image (an element request, as handleInsertElement sends).
    const added = await slideEditor.addElement({
      ...ctx,
      element: { type: 'image', placement: { x: 200, y: 300, width: 800, height: 500 }, content: imageContent('workspace/w/assets/b.png') },
    });
    const imageId = added.element.id;
    assert.deepStrictEqual(imageIds(db.current()), [imageId], 'precondition: the image is on the server');

    // Tab A edits its title and autosaves its whole copy of the slide (PUT …/canvas).
    tabA.elements[0].content.text = 'Quarterly review (edited)';
    let conflict = null;
    try {
      await slideEditor.putCanvas({ ...ctx, canvas: tabA });
    } catch (err) {
      conflict = err;
    }

    const survived = imageIds(db.current()).includes(imageId);
    assert.ok(
      survived || conflict?.statusCode === 409 || conflict?.status === 409,
      `DATA LOSS CONFIRMED: tab A's stale autosave replaced the slide and removed the image tab B added ` +
        `(server writes, element ids per write: ${JSON.stringify(db.writes)})`
    );
  } finally {
    db.restore();
  }
});

test('one tab: an autosave built before the server added an image must not remove it', async () => {
  // The Media-panel click path: the server adds the image (attach), the editor drops the reply
  // because another edit is still saving, then the queued canvas save sends the copy without it.
  const db = inMemoryDeck();
  try {
    const editorCopy = db.load();

    const attached = await slideEditor.addElement({
      ...ctx,
      element: { type: 'image', placement: { x: 200, y: 300, width: 800, height: 500 }, content: imageContent('workspace/w/assets/media.png') },
    });
    const imageId = attached.element.id;

    // The user moved the title meanwhile; that edit's queued save goes out now.
    editorCopy.elements[0].placement.x = 240;
    let conflict = null;
    try {
      await slideEditor.putCanvas({ ...ctx, canvas: editorCopy });
    } catch (err) {
      conflict = err;
    }

    const survived = imageIds(db.current()).includes(imageId);
    assert.ok(
      survived || conflict?.statusCode === 409 || conflict?.status === 409,
      'DATA LOSS CONFIRMED: a canvas save from the editor’s older copy removed the image the server had just added'
    );
  } finally {
    db.restore();
  }
});

test('control: saves in order from one up-to-date copy keep every image', async () => {
  const db = inMemoryDeck();
  try {
    const doc = db.load();
    doc.elements.push({
      id: 'img_local',
      type: 'image',
      layer: 2,
      placement: { x: 200, y: 300, width: 800, height: 500, rotation: 0, opacity: 1 },
      content: imageContent('workspace/w/assets/local.png'),
    });
    await slideEditor.putCanvas({ ...ctx, canvas: doc });
    doc.elements[0].content.text = 'Second save';
    await slideEditor.putCanvas({ ...ctx, canvas: doc });
    assert.deepStrictEqual(imageIds(db.current()), ['img_local']);
  } finally {
    db.restore();
  }
});

test('control: an uploaded image with no s3Key is still re-signed on load (links are not the cause)', async () => {
  const before = { bucket: process.env.AWS_S3_BUCKET, region: process.env.AWS_REGION };
  process.env.AWS_S3_BUCKET = BUCKET;
  process.env.AWS_REGION = REGION;
  const s3Service = require('../../s3/s3.service');
  const original = s3Service.getPresignedGetUrl;
  s3Service.getPresignedGetUrl = async (key) => `${bucketUrl(key)}?X-Amz-Signature=fresh`;
  try {
    const { attachPresignedMedia } = require('../presignSlideMedia');
    const key = 'workspace/w/assets/upload.png';
    const slide = {
      id: 's1',
      elements: {
        version: 1,
        canvas: { width: 1920, height: 1080 },
        // Saved yesterday: the signed link that has since expired, and no s3Key.
        elements: [{ id: 'img1', type: 'image', content: { url: `${bucketUrl(key)}?X-Amz-Expires=3600&X-Amz-Signature=old` } }],
        backgroundImage: `${bucketUrl('workspace/w/assets/bg.png')}?X-Amz-Signature=old`,
      },
    };
    const signed = await attachPresignedMedia(slide);
    const img = signed.elements.elements[0].content;
    assert.strictEqual(img.s3Key, key, 'the key is worked out from the stored link');
    assert.ok(img.url.endsWith('X-Amz-Signature=fresh'), 'the image gets a fresh link');
    assert.ok(signed.elements.backgroundImage.endsWith('X-Amz-Signature=fresh'), 'the background gets a fresh link');
  } finally {
    s3Service.getPresignedGetUrl = original;
    process.env.AWS_S3_BUCKET = before.bucket;
    process.env.AWS_REGION = before.region;
  }
});
