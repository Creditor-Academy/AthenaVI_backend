'use strict';

const assert = require('assert');
const { test } = require('node:test');
const {
  closingLayoutPoolForCtx,
  resolveClosingPreferredLayoutId,
  ARCHETYPES,
} = require('../slideArrangementPlan.service');
const { scoreLayout } = require('../deckLayout/scoreLayout');

test('closingLayoutPoolForCtx excludes split-hero family and fullbleed when title is hero fade', () => {
  const ctx = { outline: { arrangementArchetype: 'general' } };
  const pool = closingLayoutPoolForCtx(ctx, 'title_hero_left_fade_v1');
  assert.ok(pool.length >= 2);
  assert.ok(!pool.includes('title_hero_left_fade_v1'));
  assert.ok(!pool.some((id) => /fullbleed/i.test(String(id))));
});

test('resolveClosingPreferredLayoutId varies by deck hash — not always closing_thank_you_v1', () => {
  const titleLayoutId = 'title_hero_left_fade_v1';
  const ids = new Set();
  for (let i = 0; i < 12; i += 1) {
    const ctx = {
      outline: {
        arrangementArchetype: 'general',
        title: `Deck topic ${i}`,
      },
      userPrompt: `Prompt ${i}`,
    };
    const id = resolveClosingPreferredLayoutId({
      ctx,
      usedLayoutIds: new Set(),
      slideOrder: 10,
      titleLayoutId,
      contactIntent: false,
    });
    assert.ok(id, 'expected a closing layout id');
    ids.add(id);
  }
  assert.ok(ids.size >= 2, `expected variety, got only: ${[...ids].join(', ')}`);
});

test('contact intent narrows pool to contact/cta layouts', () => {
  const ctx = { outline: { arrangementArchetype: 'pitch' } };
  const id = resolveClosingPreferredLayoutId({
    ctx,
    usedLayoutIds: new Set(),
    slideOrder: 8,
    titleLayoutId: 'title_centered_v1',
    contactIntent: true,
  });
  assert.ok(/contact|cta/i.test(String(id)), `expected contact/cta layout, got ${id}`);
});

test('scoreLayout deprioritizes fullbleed closing when deprioritizeFullBleedClosing set', () => {
  const slide = {
    slideNumber: 10,
    suggestedContentType: 'closing',
    purpose: 'conclusion',
    titleLength: 20,
    contentTypes: ['title'],
    bodyLength: 0,
    bulletCount: 0,
    imageCount: 0,
    metricCount: 0,
    cardCount: 0,
    hasChart: false,
    hasTable: false,
    hasQuote: false,
    density: 'low',
  };
  const thankYou = {
    id: 'closing_thank_you_v1',
    slidePurposes: ['conclusion'],
    supportedElements: { title: true },
    composition: { structure: 'centered' },
  };
  const fullBleed = {
    id: 'closing_thank_you_fullbleed_v1',
    slidePurposes: ['conclusion'],
    supportedElements: { title: true },
    composition: { structure: 'full-image', visualWeight: 'image-heavy' },
  };
  const normal = scoreLayout(slide, thankYou, {});
  const penalized = scoreLayout(slide, fullBleed, { deprioritizeFullBleedClosing: true });
  assert.ok(
    normal.score > penalized.score,
    `thank_you ${normal.score} should beat fullbleed ${penalized.score} when deprioritized`
  );
});

test('pitch archetype general pool includes multiple closing layouts', () => {
  const pitchClosing = ARCHETYPES.pitch.preferredLayouts.closing;
  assert.ok(pitchClosing.length >= 3);
});
