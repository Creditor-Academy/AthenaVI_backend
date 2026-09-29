const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { prepareContentForCompile } = require('../src/modules/presentation/contentRepair.service');
const { compileSlide } = require('../src/modules/presentation/slideCompiler.service');
const { validateContentForLayoutSoft } = require('@athena/contracts/contentContract.js');
const blueprintSeed = require('../src/modules/presentation/blueprintSeed');

const seedPath = path.join(
  __dirname,
  '../src/modules/presentation/templates/seed-layouts.json'
);
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function schemaForLayoutId(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry?.schema, `missing seed schema for ${layoutId}`);
  return entry.schema;
}

const BENCHMARKS = [
  {
    layoutId: 'four_images_text_v1',
    badContent: {
      title: 'Azure Cliff Residence',
      columns: [
        { title: 'Azure Cliff Residence', body: 'One' },
        { title: 'Azure Cliff Residence', body: 'Two' },
      ],
      slotImageUrls: {
        IMAGE_1: 'https://cdn.example/a.jpg',
        IMAGE_2: 'https://cdn.example/b.jpg',
      },
    },
  },
  {
    layoutId: 'three_cards_image_text_v1',
    badContent: { title: 'Services', columns: [{ title: 'Only one', body: 'x' }] },
  },
  {
    layoutId: 'chart_three_cards_v1',
    badContent: {
      title: 'Metrics',
      chart: { labels: ['A'], series: [{ values: [1] }] },
      columns: [{ title: 'c1', body: 'b1' }],
    },
  },
  {
    layoutId: 'metric_three_cards_v1',
    badContent: {
      title: 'KPIs',
      stats: [{ value: '99%', label: 'One' }],
    },
  },
  {
    layoutId: 'grid_device_mockups_v1',
    badContent: { title: 'App', bullets: ['Fast', 'Secure'] },
  },
  {
    layoutId: 'grid_device_mockups_feature_v1',
    badContent: { title: 'Product', body: 'Overview only' },
  },
  {
    layoutId: 'agenda_three_cards_v1',
    badContent: { title: 'Agenda', body: 'Morning and afternoon sessions' },
  },
  {
    layoutId: 'bullet_list_cards_v1',
    badContent: {
      title: 'Points',
      bullets: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'],
    },
  },
  {
    layoutId: 'timeline_roadmap_v1',
    badContent: { title: 'Roadmap', timeline: [{ label: '2024', detail: 'Launch' }] },
  },
  {
    layoutId: 'team_speaker_bio_v1',
    badContent: { title: 'Team', members: [{ name: 'Alex', role: 'CEO' }] },
  },
];

async function runBenchmark(caseDef) {
  const layoutSchema = schemaForLayoutId(caseDef.layoutId);
  const prepared = await prepareContentForCompile({
    content: caseDef.badContent,
    layoutSchema,
    context: { title: caseDef.badContent.title },
  });
  const soft = validateContentForLayoutSoft(prepared.content, layoutSchema);
  assert.ok(soft.valid, `${caseDef.layoutId} contract: ${JSON.stringify(soft.errors)}`);

  const compiled = await compileSlide({
    layoutSchema,
    content: prepared.content,
    canvasSize: { width: 1920, height: 1080 },
    skipContentRepair: true,
  });

  const weak = (compiled.elementsDoc?.elements || []).some((el) => {
    if (el.type !== 'text' && el.type !== 'textbox') return false;
    const role = String(el.role || '').toLowerCase();
    if (!['heading', 'title', 'body'].includes(role)) return false;
    return blueprintSeed.isWeakText(el.content?.text);
  });
  assert.ok(!weak, `${caseDef.layoutId} has weak required text after compile`);
}

(async () => {
  for (const bench of BENCHMARKS) {
    try {
      await runBenchmark(bench);
      console.log(`ok: ${bench.layoutId}`);
    } catch (err) {
      if (err.message?.includes('missing seed schema')) {
        console.warn(`skip: ${bench.layoutId} (${err.message})`);
        continue;
      }
      throw err;
    }
  }
  console.log('ok: content repair benchmarks');
})();
