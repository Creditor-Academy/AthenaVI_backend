'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { toDeckLayout } = require('../deckLayout/toDeckLayout');
const { rankLayouts } = require('../deckLayout/rankLayouts');
const { scoreLayout } = require('../deckLayout/scoreLayout');
const { toSlideContentProfile } = require('../deckLayout/toSlideContentProfile');
const { evaluateLayoutCompatibility, hasComparisonRequired } = require('../deckLayout/layoutCompatibility');
const { candidateContentTypes } = require('../deckLayout/resolveLayoutCandidates');
const { applyVisualPolicy } = require('../deckGeneration.service');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function deckLayoutFromSeed(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry, `missing seed for ${layoutId}`);
  return toDeckLayout(entry);
}

test('toSlideContentProfile sets hasComparison for versus copy', () => {
  const profile = toSlideContentProfile({
    title: 'Cloud vs on-prem',
    suggestedContentType: 'comparison',
  });
  assert.equal(profile.hasComparison, true);
  assert.equal(profile.contentStructure, 'comparison');
});

test('comparison-required slide hard-rejects quote-only layout', () => {
  const profile = toSlideContentProfile({
    title: 'Option A vs Option B',
    suggestedContentType: 'comparison',
  });
  assert.equal(hasComparisonRequired(profile), true);
  const quote = deckLayoutFromSeed('quote_portrait_v1');
  const compat = evaluateLayoutCompatibility(profile, quote);
  assert.equal(compat.status, 'hardReject');
});

test('soft compatibility penalties reduce score', () => {
  const layout = deckLayoutFromSeed('bullet_list_dense_v1');
  const baseSlide = {
    purpose: 'features',
    contentTypes: ['title', 'bullets'],
    titleLength: 20,
    subtitleLength: 0,
    bodyLength: 0,
    cardCount: 0,
    imageCount: 0,
    metricCount: 0,
    hasChart: false,
    hasTable: false,
    hasQuote: false,
    density: 'medium',
  };
  const heavySlide = { ...baseSlide, bulletCount: 5 };
  const lightSlide = { ...baseSlide, bulletCount: 1 };
  const heavy = scoreLayout(heavySlide, layout, {});
  const light = scoreLayout(lightSlide, layout, {});
  assert.ok(heavy.score < light.score);
  assert.ok((heavy.breakdown.softCompatibilityPenalty || 0) < 0);
});

test('ranking returns empty when primary and widened pools hard-reject', () => {
  const profile = toSlideContentProfile({
    title: 'Revenue chart',
    suggestedContentType: 'chart',
    hasChart: true,
    chart: { labels: ['Q1'], series: [{ data: [1] }] },
  });
  const bullet = deckLayoutFromSeed('bullet_list_dense_v1');
  const ranked = rankLayouts(profile, [bullet], { topN: 1, widenedLayouts: [] });
  assert.equal(ranked.length, 0);
});

test('candidateContentTypes widens comparison slides', () => {
  const profile = toSlideContentProfile({ suggestedContentType: 'comparison', hasComparison: true });
  const types = candidateContentTypes(profile, { suggestedContentType: 'comparison' }, 'bullet_list');
  assert.ok(types.includes('comparison'));
  assert.ok(types.includes('bullet_list'));
});

test('applyVisualPolicy preserves comparison layoutContentType when preferVisuals', () => {
  const policy = applyVisualPolicy({
    visualNeed: 'photo',
    contentType: 'comparison',
    preferVisuals: true,
    baseTemplateBias: null,
    respectOutlineType: false,
  });
  assert.equal(policy.layoutContentType, 'comparison');
});

test('scoreDomainIntent boosts comparison layout for comparison profile', () => {
  const profile = toSlideContentProfile({
    title: 'Build vs buy',
    suggestedContentType: 'comparison',
  });
  const comparison = deckLayoutFromSeed('comparison_side_by_side_v1');
  const quote = deckLayoutFromSeed('quote_portrait_v1');
  const compScore = scoreLayout(profile, comparison, {}).score;
  const quoteScore = scoreLayout(profile, quote, {}).score;
  assert.ok(compScore > quoteScore);
});
