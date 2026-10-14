'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { compileSlide } = require('../slideCompiler.service');
const { harmonizeDeckTiers, DECK_TIER_FLOORS, isExemptLayout } = require('../artDirection/deckHeadingSize');

const LAYOUTS = Array.isArray(SEED) ? SEED : SEED.layouts || [];
const textEl = (slotId, size, tier) => ({ type: 'text', slotId, content: { text: 'x', fontSize: size, deckTier: tier } });
const slide = (id, els) => ({ id, elements: { elements: els } });

test('each tier gets one deck-wide size (smallest fitted, never grows)', () => {
  const { tiers, updates } = harmonizeDeckTiers([
    slide('a', [textEl('CARD_1_TITLE', 26, 2), textEl('CARD_1_BODY', 18, 3)]),
    slide('b', [textEl('CARD_1_TITLE', 22, 2), textEl('CARD_1_BODY', 16, 3), textEl('CAPTION', 13, 4)]),
  ]);
  assert.deepStrictEqual(tiers, { t2: 22, t3: 16, t4: 13 });
  const a = updates.find((u) => u.slideId === 'a').elements.elements;
  assert.deepStrictEqual(a.map((el) => el.content.fontSize), [22, 16]);
  assert.ok(!updates.some((u) => u.slideId === 'b'), 'slide already at deck size untouched');
});

test('floors stop one cramped slide from shrinking the deck; ratios are kept', () => {
  const { tiers } = harmonizeDeckTiers([
    slide('a', [textEl('T', 24, 2), textEl('B', 18, 3)]),
    slide('b', [textEl('T', 11, 2), textEl('B', 9, 3)]),
  ]);
  assert.strictEqual(tiers.t2, DECK_TIER_FLOORS[2]);
  assert.ok(tiers.t3 <= Math.floor(tiers.t2 / 1.2), 'body stays ≥1.2× smaller than card titles');
  assert.ok(tiers.t3 >= 9);
});

test('regenerated slides reuse the deck tier sizes', async () => {
  const theme = {
    typeScale: { title: 42, subtitle: 26, body: 18, caption: 14, deckTiers: { t2: 20, t3: 15, t4: 12 } },
    palette: { primary: '#1E3A8A', text: '#0F172A' },
  };
  const content = {
    title: 'AI in Hospital Operations',
    columns: [
      { title: 'Scheduling', body: 'Balance staff demand.' },
      { title: 'Docs', body: 'Draft notes.' },
      { title: 'Flow', body: 'Beds.' },
    ],
  };
  let checked = 0;
  for (const id of ['bullet_list_cards_v1', 'three_cards_image_text_v1', 'diagram_process_steps_v1']) {
    const schema = LAYOUTS.find((t) => t.schema?.layout_id === id)?.schema;
    if (!schema || isExemptLayout(schema)) continue;
    // eslint-disable-next-line no-await-in-loop
    const { elementsDoc } = await compileSlide({ layoutSchema: schema, content, themeTokens: theme, skipContentRepair: true, themeRecolor: true });
    for (const el of elementsDoc.elements || []) {
      if (el.content?.deckTier === 2) assert.ok(el.content.fontSize <= 20, `${id} ${el.slotId} ${el.content.fontSize}`);
      if (el.content?.deckTier === 3) assert.ok(el.content.fontSize <= 15, `${id} ${el.slotId} ${el.content.fontSize}`);
      if (el.content?.deckTier) checked += 1;
    }
  }
  assert.ok(checked > 0, 'tiered text found');
});
