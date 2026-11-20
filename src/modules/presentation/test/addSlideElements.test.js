'use strict';

/**
 * QA P-1: a slide added from a layout must never be blank on the server. The editor sends the
 * layout it compiled as `elements` with the add-slide request, and the server stores it.
 */

const assert = require('assert');
const { test } = require('node:test');
const prisma = require('../../../shared/config/prismaClient');
const presentationDao = require('../presentation.dao');
const slideEditor = require('../slideEditor.service');
const { addSlideSchema } = require('../../validations/presentation.validations');

const WS = '11111111-1111-1111-1111-111111111111';
const PRESENTATION = 'cabc123456789012345678901';

const layoutDoc = {
  version: 1,
  canvas: { width: 1920, height: 1080 },
  elements: [
    {
      id: 'txt_title',
      type: 'text',
      layer: 1,
      placement: { x: 160, y: 400, width: 1600, height: 140 },
      content: { text: 'Minimal title slide', fontSize: 48 },
    },
    {
      id: 'txt_tagline',
      type: 'text',
      layer: 2,
      placement: { x: 160, y: 560, width: 1600, height: 80 },
      content: { text: 'Optional tagline', fontSize: 24 },
    },
  ],
};

function stubDeck() {
  const saved = {};
  const restore = [];
  const stub = (obj, key, fn) => {
    const before = obj[key];
    obj[key] = fn;
    restore.push(() => {
      obj[key] = before;
    });
  };
  const deck = { id: 'deck1', aspectRatio: '16:9', status: 'READY', slides: [{ id: 's1', order: 1 }] };
  stub(presentationDao, 'findDeckByProjectId', async () => deck);
  stub(prisma.project, 'findUnique', async () => ({ id: PRESENTATION, workspaceId: WS, type: 'PRESENTATION' }));
  stub(presentationDao, 'shiftSlideOrders', async () => {});
  stub(presentationDao, 'createOneSlide', async (data) => {
    saved.slide = data;
    return { id: 's2', ...data };
  });
  return { saved, restore: () => restore.reverse().forEach((fn) => fn()) };
}

test('add-slide accepts the editor’s canvas as `elements`', () => {
  const { error, value } = addSlideSchema.validate(
    {
      params: { workspaceId: WS, presentationId: PRESENTATION },
      body: { afterSlideId: 's1', layoutId: 'title_minimal_v1', title: 'Minimal title slide', elements: layoutDoc },
      query: {},
    },
    { stripUnknown: true }
  );
  assert.equal(error, undefined);
  assert.equal(value.body.elements.elements.length, 2);
});

test('a slide added with `elements` is stored with them (not blank)', async () => {
  const { saved, restore } = stubDeck();
  try {
    await slideEditor.addSlide({
      workspaceId: WS,
      presentationId: PRESENTATION,
      afterSlideId: 's1',
      layoutId: 'title_minimal_v1',
      content: { title: 'Minimal title slide' },
      elements: layoutDoc,
    });
    const texts = saved.slide.elements.elements.map((el) => el.content?.text);
    assert.deepEqual(texts, ['Minimal title slide', 'Optional tagline']);
    assert.equal(saved.slide.order, 2);
    assert.equal(saved.slide.layoutId, 'title_minimal_v1');
  } finally {
    restore();
  }
});

test('without `elements` or a template, the slide is still a blank canvas (as before)', async () => {
  const { saved, restore } = stubDeck();
  try {
    await slideEditor.addSlide({ workspaceId: WS, presentationId: PRESENTATION, content: {} });
    assert.ok(Array.isArray(saved.slide.elements.elements));
    assert.ok(saved.slide.elements.elements.every((el) => !el.content?.text));
  } finally {
    restore();
  }
});
