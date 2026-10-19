'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { toDeckLayout } = require('../deckLayout/toDeckLayout');
const { rankLayouts } = require('../deckLayout/rankLayouts');
const { toSlideContentProfile } = require('../deckLayout/toSlideContentProfile');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function seedRow(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry, `missing seed for ${layoutId}`);
  return entry;
}

function deckLayoutFromSeed(layoutId) {
  return toDeckLayout(seedRow(layoutId));
}

test('timeline_process_horizontal_v1 derives roadmap topics and journey aliases', () => {
  const layout = deckLayoutFromSeed('timeline_process_horizontal_v1');
  assert.ok(layout.layoutTopics.includes('roadmap'));
  assert.ok(layout.keywords.includes('journey'));
  assert.ok(layout.keywords.includes('milestones'));
});

test('comparison_table_v1 derives comparison topics and versus aliases', () => {
  const layout = deckLayoutFromSeed('comparison_table_v1');
  assert.ok(layout.layoutTopics.includes('comparison'));
  assert.ok(layout.keywords.includes('versus'));
  assert.ok(layout.keywords.includes('pros'));
});

test('catalog sweep: derived keywords on every seed layout', () => {
  let missingTopics = 0;
  let shortKeywords = 0;
  for (const row of seedLayouts) {
    const layout = toDeckLayout(row);
    if (!Array.isArray(layout.layoutTopics) || layout.layoutTopics.length < 1) missingTopics += 1;
    if (!Array.isArray(layout.keywords) || layout.keywords.length < 8) shortKeywords += 1;
  }
  assert.equal(missingTopics, 0, 'layouts missing layoutTopics');
  assert.equal(shortKeywords, 0, 'layouts with fewer than 8 keywords');
});

test('roadmap copy ranks timeline above generic bullet layout', () => {
  const timeline = deckLayoutFromSeed('timeline_process_horizontal_v1');
  const bullet = deckLayoutFromSeed('bullet_list_dense_v1');
  const profile = toSlideContentProfile({
    title: 'Product roadmap 2026',
    summary: 'Q1 milestones and rollout phases',
    suggestedContentType: 'timeline',
    slideNumber: 3,
    titleLength: 20,
    bodyLength: 40,
    bulletCount: 0,
    imageCount: 0,
    metricCount: 0,
    cardCount: 0,
  });
  const ranked = rankLayouts(profile, [bullet, timeline], {
    topN: 2,
    searchText: 'roadmap milestones quarters',
  });
  assert.equal(ranked[0].layoutId, timeline.id);
});

test('comparison copy ranks comparison layout above quote layout', () => {
  const comparison = deckLayoutFromSeed('comparison_pros_cons_v1');
  const quote = deckLayoutFromSeed('quote_portrait_v1');
  const profile = toSlideContentProfile({
    title: 'React vs Vue comparison',
    summary: 'Side by side pros and cons for our stack',
    suggestedContentType: 'comparison',
    slideNumber: 4,
    titleLength: 24,
    bodyLength: 50,
    bulletCount: 0,
    imageCount: 0,
    metricCount: 0,
    cardCount: 0,
  });
  const ranked = rankLayouts(profile, [quote, comparison], {
    topN: 2,
    searchText: 'React vs Vue comparison pros cons',
  });
  assert.equal(ranked[0].layoutId, comparison.id);
});
