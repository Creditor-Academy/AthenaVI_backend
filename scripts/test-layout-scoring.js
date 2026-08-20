/**
 * Layout scoring engine checks.
 * Run: node scripts/test-layout-scoring.js
 */
const assert = require('assert');

const {
  listDeckLayouts,
  toSlideContentProfile,
  rankLayouts,
  scoreLayout,
  evaluateLayoutCompatibility,
} = require('../src/modules/presentation/deckLayout');

const layouts = listDeckLayouts();
assert.ok(layouts.length >= 120, `expected 120+ layouts, got ${layouts.length}`);

function byId(id) {
  return layouts.find((l) => l.id === id);
}

function indexOf(ranked, id) {
  return ranked.findIndex((r) => r.layoutId === id);
}

function scoreOf(ranked, id) {
  return ranked.find((r) => r.layoutId === id)?.score;
}

const textOnly = byId('title_centered_v1') || byId('text_only_centered_v1');
assert.ok(textOnly, 'catalog has a text-only title layout');

const splitHero = byId('title_hero_right_fade_v1');
assert.ok(splitHero, 'catalog has title_hero_right_fade_v1');

/* --- missing metadata must not throw --- */
const sparseLayout = { id: 'sparse_test' };
const sparseProfile = toSlideContentProfile({ title: 'Hello' });
assert.doesNotThrow(() => scoreLayout(sparseProfile, sparseLayout));
assert.doesNotThrow(() => rankLayouts(sparseProfile, [sparseLayout, ...layouts.slice(0, 3)], { topN: 3 }));

/* --- Test 1: Statistics --- */
const statsSlide = toSlideContentProfile({
  purpose: 'statistics',
  metricCount: 3,
  contentTypes: ['title', 'metrics'],
  title: 'Q3 traction',
  stats: [{ value: '12%' }, { value: '40' }, { value: '3x' }],
});
const statsRanked = rankLayouts(statsSlide, layouts, { topN: 40 });
assert.ok(statsRanked.length, 'statistics ranking returned layouts');
assert.ok(statsRanked[0].reasons.length, 'top hit has reasons');
assert.ok(statsRanked[0].score >= 0 && statsRanked[0].score <= 100);
assert.ok(statsRanked[0].breakdown && 'purposeMatch' in statsRanked[0].breakdown);

const statsTop = layouts.find((l) => l.id === statsRanked[0].layoutId);
assert.ok(
  statsTop.supportedElements.metrics === true ||
    statsTop.category === 'data' ||
    statsTop.category === 'chart',
  `statistics top layout should be metrics/data, got ${statsTop.id} (${statsTop.category})`
);

const statsAll = rankLayouts(statsSlide, layouts, { topN: layouts.length });
const textStatsIdx = indexOf(statsAll, textOnly.id);
const metricsIdx = statsAll.findIndex((r) => {
  const l = byId(r.layoutId);
  return l && (l.supportedElements.metrics || l.category === 'data');
});
assert.ok(metricsIdx >= 0, 'a metrics layout appears in statistics ranking');
if (textStatsIdx >= 0) {
  assert.ok(metricsIdx < textStatsIdx, 'metrics layout ranks above text-heavy title layout');
}

/* --- Test 2: Three cards --- */
const cardsSlide = toSlideContentProfile({
  purpose: 'features',
  cardCount: 3,
  contentTypes: ['title', 'cards'],
  title: 'Three reasons customers choose us',
});
const cardsAll = rankLayouts(cardsSlide, layouts, { topN: layouts.length });
assert.ok(cardsAll.length, 'cards ranking returned layouts');
const threeCard = cardsAll.find((r) => {
  const l = byId(r.layoutId);
  return l && l.supportedElements.cards && (l.contentCapacity.maxCards || 0) >= 3;
});
const zeroCard = cardsAll.find((r) => {
  const l = byId(r.layoutId);
  return l && (l.contentCapacity.maxCards || 0) === 0 && l.supportedElements.cards !== true;
});
assert.ok(threeCard, 'a 3-card layout is ranked');
if (zeroCard) {
  assert.ok(threeCard.score > zeroCard.score, '3-card layout ranks above maxCards=0');
} else {
  const rejectedZero = layouts.filter(
    (l) => (l.contentCapacity.maxCards || 0) === 0 && l.supportedElements.cards !== true
  );
  assert.ok(rejectedZero.length, 'zero-card layouts exist');
  assert.ok(
    rejectedZero.every((l) => evaluateLayoutCompatibility(cardsSlide, l).status === 'hardReject'),
    'zero-card layouts are hard-rejected for required cards'
  );
}

/* --- Test 3: Image-heavy hero --- */
const heroSlide = toSlideContentProfile({
  purpose: 'cover',
  imageCount: 1,
  contentTypes: ['title', 'subtitle', 'image'],
  title: 'Acme',
  subtitle: 'The future of ops',
});
const heroRanked = rankLayouts(heroSlide, layouts, { topN: 15 });
const heroIds = heroRanked.map((r) => r.layoutId);
assert.ok(
  heroIds.includes('title_hero_right_fade_v1') ||
    byId(heroRanked[0].layoutId)?.category === 'hero' ||
    byId(heroRanked[0].layoutId)?.supportedElements.image,
  'hero/image layout ranks highly'
);
assert.notStrictEqual(heroRanked[0].layoutId, textOnly.id, 'text-only layout is not first for cover+image');

/* --- Test 4: Chart --- */
const chartSlide = toSlideContentProfile({
  purpose: 'statistics',
  hasChart: true,
  contentTypes: ['title', 'chart'],
  title: 'Revenue by quarter',
  chart: { labels: ['Q1', 'Q2'], series: [{ values: [1, 2] }] },
});
const chartRanked = rankLayouts(chartSlide, layouts, { topN: layouts.length });
assert.ok(chartRanked.length, 'chart ranking returned layouts');
for (const row of chartRanked) {
  const l = byId(row.layoutId);
  if (!l?.supportedElements || typeof l.supportedElements.chart !== 'boolean') continue;
  assert.strictEqual(
    l.supportedElements.chart,
    true,
    `${row.layoutId} must support charts after hard filter`
  );
}

/* --- Test 5: Repetition --- */
const reusedId = statsRanked[0].layoutId;
const reusedLayout = byId(reusedId);
const once = scoreLayout(statsSlide, reusedLayout, { previousLayoutIds: [reusedId] });
const twice = scoreLayout(statsSlide, reusedLayout, { previousLayoutIds: [reusedId, reusedId] });
const thrice = scoreLayout(statsSlide, reusedLayout, { previousLayoutIds: [reusedId, reusedId, reusedId] });
assert.strictEqual(once.breakdown.repetitionPenalty, -5);
assert.strictEqual(twice.breakdown.repetitionPenalty, -12);
assert.strictEqual(thrice.breakdown.repetitionPenalty, -20);
assert.ok(twice.score < once.score || twice.score === 0, 'repeat use lowers score');

/* --- Test 6: Capacity --- */
const sixCardSlide = toSlideContentProfile({
  purpose: 'team',
  cardCount: 6,
  contentTypes: ['title', 'cards'],
  title: 'Six team members',
});
const sixCapable = layouts.find((l) => (l.contentCapacity.maxCards || 0) >= 6 && l.supportedElements.cards);
assert.ok(sixCapable, 'catalog has a layout with maxCards >= 6');
const threeCapable = layouts.find(
  (l) =>
    (l.contentCapacity.maxCards || 0) === 3 &&
    l.supportedElements.cards &&
    l.category === sixCapable.category
);
assert.ok(threeCapable, 'catalog has a same-category layout with maxCards === 3');
const sixScore = scoreLayout(sixCardSlide, sixCapable);
const threeScore = scoreLayout(sixCardSlide, threeCapable);
assert.ok(
  sixScore.score > threeScore.score,
  `maxCards>=6 (${sixCapable.id}=${sixScore.score}) should beat maxCards=3 (${threeCapable.id}=${threeScore.score})`
);
assert.ok(
  threeScore.warnings.some((w) => /card/i.test(w)) ||
    evaluateLayoutCompatibility(sixCardSlide, threeCapable).penalties.length,
  '3-card layout warns or penalizes overflow'
);

console.log('ok: layout scoring engine');
console.log(
  `  stats top: ${statsRanked[0].layoutId} (${statsRanked[0].score} ${statsRanked[0].confidence})`
);
console.log(`  hero top: ${heroRanked[0].layoutId} (${heroRanked[0].score})`);
console.log(`  chart candidates: ${chartRanked.length}`);
