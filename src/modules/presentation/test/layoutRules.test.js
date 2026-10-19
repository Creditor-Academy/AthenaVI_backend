'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { filterTemplatesForSlideOrder, TITLE_SPLIT_LAYOUT_IDS } = require('../layoutSelector.service');
const { ensureCompatibleLayout } = require('../deckLayout/ensureLayoutPick');
const { findAdjacentDuplicates } = require('../deckLayout/adjacency');
const { toSlideContentProfile } = require('../deckLayout/toSlideContentProfile');
const { findExistingIconElements } = require('../../graphics/graphics.service');

const CATALOG = (Array.isArray(SEED) ? SEED : SEED.layouts || []).map((t) => ({
  id: t.schema?.layout_id,
  contentType: t.contentType,
  variant: t.variant,
  schema: t.schema,
}));
const loadAll = (whitelist) =>
  Promise.resolve(Array.isArray(whitelist) && whitelist.length ? CATALOG.filter((t) => whitelist.includes(t.id)) : CATALOG);

test('cover slide only allows split left/right title layouts', () => {
  const ids = filterTemplatesForSlideOrder(CATALOG, 1, 10).map((t) => t.id);
  assert.ok(ids.length > 0);
  assert.ok(ids.every((id) => TITLE_SPLIT_LAYOUT_IDS.includes(id)), ids.join(', '));
  assert.ok(!ids.includes('title_fullbleed_v1'));
});

test('cover fallback stays split even when the pack whitelist has none and content is unusual', async () => {
  const hit = await ensureCompatibleLayout({
    profile: toSlideContentProfile({ title: 'Deck', chart: { labels: ['a'], series: [{ values: [1] }] } }),
    loadAllTemplates: loadAll,
    filterForOrder: (list) => filterTemplatesForSlideOrder(list, 1, 10),
    layoutIdWhitelist: ['bullet_list_dense_v1'],
    strictOrderFilter: true,
    slideNumber: 1,
  });
  assert.ok(TITLE_SPLIT_LAYOUT_IDS.includes(hit.layoutId), hit.layoutId);
});

test('fallback keeps the outline slide type when a compatible layout of that type exists', async () => {
  const hit = await ensureCompatibleLayout({
    profile: toSlideContentProfile({
      title: 'Roadmap',
      timeline: [{ label: 'Q1', detail: 'a' }, { label: 'Q2', detail: 'b' }, { label: 'Q3', detail: 'c' }],
    }),
    loadAllTemplates: loadAll,
    filterForOrder: (list) => filterTemplatesForSlideOrder(list, 5, 10),
    preferContentType: 'timeline',
  });
  assert.strictEqual(hit.template.contentType, 'timeline');
});

test('neighbour layouts are never reused, even on the universal fallback', async () => {
  const profile = toSlideContentProfile({ title: 'X', chart: { labels: ['a'], series: [{ values: [1] }] } });
  const textOnly = CATALOG.filter((t) => ['bullet_list_dense_v1', 'text_only_centered_v1', 'bullet_list_two_column_v1'].includes(t.id));
  const hit = await ensureCompatibleLayout({
    profile,
    loadAllTemplates: () => Promise.resolve(textOnly),
    hardExcludeLayoutIds: ['bullet_list_dense_v1'],
  });
  assert.notStrictEqual(hit.layoutId, 'bullet_list_dense_v1');
});

test('findAdjacentDuplicates reports back-to-back repeats and skips locked slides', () => {
  const dups = findAdjacentDuplicates([
    { id: 'a', order: 1, layoutId: 'title_hero_left_fade_v1' },
    { id: 'b', order: 2, layoutId: 'agenda_three_columns_v1' },
    { id: 'c', order: 3, layoutId: 'agenda_three_columns_v1' },
    { id: 'd', order: 4, layoutId: 'bullet_list_dense_v1' },
    { id: 'e', order: 5, layoutId: 'bullet_list_dense_v1', layoutLocked: true },
  ]);
  assert.deepStrictEqual(dups.map((d) => d.slide.id), ['c']);
  assert.strictEqual(dups[0].nextLayoutId, 'bullet_list_dense_v1');
});

test('existing layout icons are detected so they are updated instead of duplicated', () => {
  const icons = findExistingIconElements([
    { type: 'text', slotId: 'STEP_1_TITLE' },
    { type: 'graphic', slotId: 'STEP_2_ICON', placement: { x: 0, y: 0 } },
    { type: 'graphic', slotId: 'STEP_1_ICON', placement: { x: 0, y: 0 } },
    { type: 'shape', slotId: 'INSIGHT_ICON_1' },
    { type: 'graphic', slotId: 'LIST_ICON_1' },
    { type: 'graphic', content: { iconKey: 'document' } },
    { type: 'shape', slotId: 'CARD_1_BG' },
  ]);
  assert.deepStrictEqual(
    icons.map((el) => el.slotId || el.content?.iconKey),
    ['document', 'STEP_1_ICON', 'INSIGHT_ICON_1', 'STEP_2_ICON']
  );
});
