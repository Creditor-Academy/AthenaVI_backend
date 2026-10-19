'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { toSlideContentProfile } = require('../deckLayout/toSlideContentProfile');
const { toDeckLayout } = require('../deckLayout/toDeckLayout');
const { evaluateLayoutCompatibility } = require('../deckLayout/layoutCompatibility');
const { ensureCompatibleLayout, UNIVERSAL_TEXT_LAYOUT_IDS } = require('../deckLayout/ensureLayoutPick');
const { filterTemplatesForSlideOrder } = require('../layoutSelector.service');

const CATALOG = (Array.isArray(SEED) ? SEED : SEED.layouts || []).map((t) => ({
  id: t.schema?.layout_id,
  contentType: t.contentType,
  variant: t.variant,
  schema: t.schema,
  isActive: true,
}));

const byType = (type) => CATALOG.filter((t) => t.contentType === type);
const loadAll = (whitelist) =>
  Promise.resolve(
    Array.isArray(whitelist) && whitelist.length
      ? CATALOG.filter((t) => whitelist.includes(t.schema.layout_id))
      : CATALOG
  );

function capturingLogger() {
  const events = [];
  return { events, warn: (message, data) => events.push({ message, data }) };
}

const chartCardsProfile = toSlideContentProfile({
  title: 'Diagnostic accuracy trend',
  chart: { type: 'bar', labels: ['A', 'B', 'C'], series: [{ name: 'S', values: [1, 2, 3] }] },
  cards: [
    { title: 'Imaging', body: 'Pattern recognition in scans' },
    { title: 'Triage', body: 'Prioritise urgent studies' },
    { title: 'Support', body: 'Decision support for clinicians' },
  ],
});

test('narrow pool that hard-rejects everything widens to the full catalog', async () => {
  const narrow = byType('diagram').slice(0, 7);
  const rejected = narrow.filter(
    (t) => evaluateLayoutCompatibility(chartCardsProfile, toDeckLayout(t)).status === 'hardReject'
  );
  assert.ok(rejected.length >= 1, 'fixture: diagram layouts reject chart content');

  const hit = await ensureCompatibleLayout({ profile: chartCardsProfile, loadAllTemplates: loadAll });
  assert.ok(hit?.template?.schema, 'a layout is always returned');
  assert.notStrictEqual(
    evaluateLayoutCompatibility(chartCardsProfile, toDeckLayout(hit.template)).status,
    'hardReject'
  );
});

test('pack whitelist with no compatible layout is bypassed and logged', async () => {
  const whitelist = byType('diagram').slice(0, 7).map((t) => t.schema.layout_id);
  const logger = capturingLogger();
  const hit = await ensureCompatibleLayout({
    profile: chartCardsProfile,
    loadAllTemplates: loadAll,
    layoutIdWhitelist: whitelist,
    logger,
  });
  assert.ok(hit?.template?.schema);
  assert.ok(!whitelist.includes(hit.layoutId) || hit.source === 'catalog_whitelist');
  if (!whitelist.includes(hit.layoutId)) {
    assert.ok(logger.events.some((e) => e.message === 'presentation_layout_whitelist_bypassed'));
  }
});

test('when nothing in the catalog is compatible, a universal text layout is used', async () => {
  const textOnly = CATALOG.filter((t) => UNIVERSAL_TEXT_LAYOUT_IDS.includes(t.schema.layout_id));
  const logger = capturingLogger();
  const hit = await ensureCompatibleLayout({
    profile: chartCardsProfile, // charts are hard-rejected by every text layout
    loadAllTemplates: () => Promise.resolve(textOnly),
    logger,
  });
  assert.strictEqual(hit.source, 'universal_fallback');
  assert.ok(UNIVERSAL_TEXT_LAYOUT_IDS.includes(hit.layoutId));
  assert.ok(logger.events.some((e) => e.message === 'presentation_layout_universal_fallback'));
});

test('catalog sweep: every content profile gets a layout for middle and closing slides', async () => {
  const profiles = {
    cards2: { title: 'Two', cards: [{ title: 'a', body: 'b' }, { title: 'c', body: 'd' }] },
    cards6: {
      title: 'Six',
      cards: Array.from({ length: 6 }, (_, i) => ({ title: `Card ${i}`, body: 'Detail text' })),
    },
    cards8: {
      title: 'Eight',
      cards: Array.from({ length: 8 }, (_, i) => ({ title: `Card ${i}`, body: 'Detail text' })),
    },
    chart: { title: 'Chart', chart: { type: 'line', labels: ['a', 'b'], series: [{ values: [1, 2] }] } },
    table: { title: 'Table', table: { headers: ['a', 'b', 'c'], rows: [['1', '2', '3']] } },
    comparison: { title: 'Compare', comparison: { left: { title: 'A', points: ['x'] }, right: { title: 'B', points: ['y'] } } },
    timeline: { title: 'Roadmap', timeline: [{ label: '1', detail: 'a' }, { label: '2', detail: 'b' }, { label: '3', detail: 'c' }, { label: '4', detail: 'd' }] },
    image: { title: 'Hero', imageRef: { url: 'https://example.com/a.jpg' }, visual_need: 'photo' },
    longBody: { title: 'Context', body: 'Healthcare systems face growing demand. '.repeat(20) },
    quote: { title: 'Voice', quote: 'AI should augment clinicians, not replace them.', attribution: 'Clinical lead' },
    stats: { title: 'Stats', stats: [{ value: '3', label: 'a' }, { value: '4', label: 'b' }, { value: '5', label: 'c' }] },
  };
  for (const [name, content] of Object.entries(profiles)) {
    const profile = toSlideContentProfile(content);
    for (const order of [3, 10]) {
      // eslint-disable-next-line no-await-in-loop
      const hit = await ensureCompatibleLayout({
        profile,
        loadAllTemplates: loadAll,
        filterForOrder: (list) => filterTemplatesForSlideOrder(list, order, 10),
      });
      assert.ok(hit?.template?.schema, `${name} @ slide ${order} must get a layout`);
    }
  }
});
