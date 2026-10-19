'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { compileSlide } = require('../slideCompiler.service');
const { isCatalogPlaceholderText } = require('../catalogPlaceholder');
const { timelineItemIndex } = require('../diagrams/timelineItemCount');
const { textForSlot } = require('../../../../packages/athena-contracts/slotText');

const LAYOUTS = Array.isArray(SEED) ? SEED : SEED.layouts || [];
const schemaFor = (id) => LAYOUTS.find((t) => t.schema?.layout_id === id)?.schema;

const textOf = (el) =>
  String(el?.content?.text || (el?.content?.runs || []).map((r) => r.text || '').join('') || '').trim();

const THREE_MILESTONES = {
  title: 'Implementation roadmap',
  timeline: [
    { label: 'Q1', title: 'Assess readiness', detail: 'Audit data quality and clinical workflows.' },
    { label: 'Q2', title: 'Controlled pilot', detail: 'Run a supervised pilot in one department.' },
    { label: 'Q3', title: 'Validate outcomes', detail: 'Review safety, accuracy and clinician feedback.' },
  ],
};

const TIMELINE_IDS = LAYOUTS.map((t) => t.schema?.layout_id).filter((id) => /^timeline_/.test(id || ''));

for (const layoutId of TIMELINE_IDS) {
  test(`${layoutId}: 3 entries render 3 cards with no placeholder copy`, async () => {
    const { elementsDoc } = await compileSlide({
      layoutSchema: schemaFor(layoutId),
      content: THREE_MILESTONES,
      skipContentRepair: true,
    });
    const elements = elementsDoc?.elements || [];
    const beyond = elements.filter((el) => (timelineItemIndex(el.slotId) || 0) > 3).map((el) => el.slotId);
    assert.deepStrictEqual(beyond, [], `cards 4+ must be removed: ${beyond.join(', ')}`);
    const placeholders = elements.filter((el) => textOf(el) && isCatalogPlaceholderText(textOf(el)));
    assert.deepStrictEqual(placeholders.map((el) => `${el.slotId}=${textOf(el)}`), []);
  });
}

test('milestone slots resolve num/title/card and never fall back to the slide title', () => {
  const content = {
    title: 'Roadmap',
    timeline: [{ label: 'Phase A', year: '2025', title: 'Pilot', summary: 'Short card', detail: 'Details' }],
  };
  assert.strictEqual(textForSlot('milestone_1_num', content), '2025');
  assert.strictEqual(textForSlot('milestone_1_title', content), 'Pilot');
  assert.strictEqual(textForSlot('milestone_1_card', content), 'Short card');
  assert.strictEqual(textForSlot('milestone_2_title', content), '', 'missing entry must stay empty');
});

test('grid_insights_chart_v1 keeps the generated chart and copy (no dummy bars or sample text)', async () => {
  const content = {
    title: 'Diagnostic support signals',
    insights: ['Faster triage', 'Fewer missed findings', 'Consistent reads'],
    chart: {
      title: 'Illustrative review time by stage',
      type: 'bar',
      labels: ['Intake', 'Imaging', 'Review', 'Report'],
      series: [{ name: 'Minutes', values: [12, 30, 18, 9] }],
      isIllustrative: true,
    },
    caption: 'Illustrative values',
    takeaway: { title: 'Augment, not replace', body: 'Clinicians stay accountable for every decision.' },
  };
  for (const layoutId of ['grid_insights_chart_v1', 'grid_insights_chart_split_v1']) {
    // eslint-disable-next-line no-await-in-loop
    const { elementsDoc } = await compileSlide({ layoutSchema: schemaFor(layoutId), content, skipContentRepair: true });
    const elements = elementsDoc?.elements || [];
    const chart = elements.find((el) => el.type === 'chart');
    assert.ok(chart, `${layoutId}: real chart element kept`);
    const labels = chart.content?.labels || chart.content?.data?.labels || [];
    assert.deepStrictEqual(labels, content.chart.labels, `${layoutId}: chart uses generated labels`);
    assert.ok(!elements.some((el) => /^GICS?_CHART_BARS$/.test(el.slotId || '')), `${layoutId}: no decorative bars`);
    const texts = elements.map(textOf).filter(Boolean);
    for (const sample of ['Insight 1', 'Revenue growth', 'Monthly performance', 'Key takeaway']) {
      assert.ok(!texts.includes(sample), `${layoutId}: sample copy "${sample}" leaked`);
    }
    assert.ok(texts.includes('Faster triage'), `${layoutId}: insight label rendered`);
  }
});
