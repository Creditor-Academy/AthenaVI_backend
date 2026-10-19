/**
 * Chart density cap regression tests.
 * Run: node scripts/test-chart-density-cap.js
 */
const assert = require('assert');
const policy = require('../src/modules/presentation/layoutCatalogPolicy');

assert.strictEqual(policy.maxChartSlidesForDeck(8), 2);
assert.strictEqual(policy.maxChartSlidesForDeck(10), 2);
assert.strictEqual(policy.maxChartSlidesForDeck(12), 3);
assert.strictEqual(policy.maxChartSlidesForDeck(16), 3);
assert.strictEqual(policy.maxChartSlidesForDeck(20), 4);

function makeDeck(n, chartOrders) {
  return Array.from({ length: n }, (_, i) => {
    const order = i + 1;
    const isChart = chartOrders.includes(order);
    return {
      order,
      title: isChart
        ? order === 5
          ? 'Market Share Rise'
          : order === 6
            ? 'Quarterly Growth'
            : `Vision Slide ${order}`
        : `Slide ${order}`,
      summary: isChart
        ? order === 5 || order === 6
          ? 'Revenue growth and market share percent by quarter'
          : 'Brand lifestyle concept with soft atmosphere'
        : 'Key point',
      suggestedContentType:
        order === 1 ? 'title' : order === n ? 'closing' : isChart ? 'chart' : 'image+text',
      visual_need: isChart ? 'chart' : 'photo',
      layoutId: isChart ? 'chart_bar_v1' : null,
    };
  });
}

const eight = policy.enforceChartDensityCap(makeDeck(8, [2, 5, 6]));
const eightCharts = eight.filter((s) => s.suggestedContentType === 'chart');
assert.strictEqual(eightCharts.length, 2, '8-slide deck keeps at most 2 charts');
assert.strictEqual(eight[0].suggestedContentType, 'title', 'title never demoted');
assert.strictEqual(eight[7].suggestedContentType, 'closing', 'closing never demoted');
const demoted = eight.filter((s) => String(s.layoutWhy || '').includes('chart budget'));
assert.ok(demoted.length >= 1, 'surplus charts are demoted with budget note');
assert.ok(
  demoted.every((s) => s.suggestedContentType === 'image+text'),
  'demoted charts become image+text'
);
assert.ok(
  demoted.every((s) => s.visual_need !== 'chart'),
  'demoted chart visual_need cleared from chart'
);
assert.ok(
  eightCharts.every((s) => /market|growth|revenue|share|quarter/i.test(`${s.title} ${s.summary}`)),
  'kept charts prefer quantitative slides'
);

const twenty = policy.enforceChartDensityCap(makeDeck(20, [3, 5, 7, 9, 11]));
const twentyCharts = twenty.filter((s) => s.suggestedContentType === 'chart');
assert.strictEqual(twentyCharts.length, 4, '20-slide with 5 charts keeps 4');

const locked = makeDeck(8, [2, 5, 6]);
locked[1].layoutLocked = true;
locked[1].layoutId = 'chart_locked_v1';
const lockedResult = policy.enforceChartDensityCap(locked);
assert.strictEqual(lockedResult[1].suggestedContentType, 'chart', 'layoutLocked chart is not demoted');
// Still only 2 demotable charts kept among unlocked + the locked one may mean 3 charts total
const lockedCharts = lockedResult.filter((s) => s.suggestedContentType === 'chart');
assert.ok(lockedCharts.length >= 2, 'locked chart preserved alongside budget keepers');

console.log('ok: chart density caps', {
  max8: policy.maxChartSlidesForDeck(8),
  max20: policy.maxChartSlidesForDeck(20),
  eightCharts: eightCharts.length,
  twentyCharts: twentyCharts.length,
  lockedCharts: lockedCharts.length,
});
