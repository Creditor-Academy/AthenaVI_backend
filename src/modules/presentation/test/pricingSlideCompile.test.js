'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const blueprintSeed = require('../blueprintSeed');
const { compileSlide } = require('../slideCompiler.service');
const { rebindContentToElements, finalizeElementsDoc } = require('../layoutToElements');
const { prepareContentForCompile } = require('../contentRepair.service');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function schemaForLayoutId(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry?.schema, `missing seed schema for ${layoutId}`);
  return entry.schema;
}

function planLabelText(elementsDoc, n = 1) {
  const el = (elementsDoc?.elements || []).find(
    (e) => String(e.slotId || e.id || '').toUpperCase() === `PLAN_${n}_LABEL`
  );
  return el?.content?.text;
}

const SAMPLE_PLANS = [
  { label: 'Basic', price: '$29', period: '/mo', items: ['Gym floor access', 'Locker'] },
  {
    label: 'Pro',
    price: '$59',
    period: '/mo',
    items: ['All Basic perks', 'Classes'],
    highlighted: true,
  },
  { label: 'Elite', price: '$99', period: '/mo', items: ['Personal training', 'Spa'] },
];

test('pricing compile pads plans and fills PLAN_1_LABEL', async () => {
  const layoutSchema = schemaForLayoutId('pricing_three_plans_v1');
  const prepared = await prepareContentForCompile({
    content: { title: 'Flexible Memberships' },
    layoutSchema,
    context: {},
  });
  assert.ok(!blueprintSeed.contentMissingPricingPlans(prepared.content, layoutSchema));
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content: prepared.content,
    skipContentRepair: true,
  });
  const label = planLabelText(elementsDoc, 1);
  assert.ok(label && !blueprintSeed.isWeakText(label), `expected PLAN_1_LABEL, got ${label}`);
});

test('rebind restores empty PLAN slots from plans[]', async () => {
  const layoutSchema = schemaForLayoutId('pricing_three_highlight_v1');
  const content = { title: 'Membership tiers', plans: SAMPLE_PLANS };
  const { elementsDoc: compiled } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const stripped = {
    ...compiled,
    elements: compiled.elements.map((el) => {
      const sid = String(el.slotId || el.id || '').toUpperCase();
      if (/^PLAN_\d+_(LABEL|PRICE|ITEM_)/.test(sid)) {
        return { ...el, content: { ...(el.content || {}), text: '' } };
      }
      return el;
    }),
  };
  let rebound = rebindContentToElements(stripped, content, null, { layoutSchema });
  rebound = finalizeElementsDoc(rebound, layoutSchema, content, null, { width: 1920, height: 1080 });
  const label = planLabelText(rebound, 1);
  assert.equal(label, 'Basic');
  assert.ok(!blueprintSeed.compiledHasWeakPricingElements(rebound, layoutSchema));
});

test('PulseFit-style pricing content compiles on pricing_three_plans_v1', async () => {
  const layoutSchema = schemaForLayoutId('pricing_three_plans_v1');
  const content = {
    title: 'Flexible Memberships for Every Fitness Goal',
    plans: [
      {
        label: 'Essentials',
        price: '$39',
        period: '/mo',
        items: ['Open gym access', 'Locker room', '1 guest pass / month'],
        cta: 'Join Essentials',
      },
      {
        label: 'Pulse',
        price: '$69',
        period: '/mo',
        items: ['Unlimited classes', 'Sauna & recovery', 'Nutrition check-in'],
        highlighted: true,
        cta: 'Start Pulse',
      },
      {
        label: 'Studio+',
        price: '$119',
        period: '/mo',
        items: ['Small-group coaching', 'Priority booking', 'Monthly body scan'],
        cta: 'Go Studio+',
      },
    ],
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  assert.equal(planLabelText(elementsDoc, 1), 'Essentials');
  assert.equal(planLabelText(elementsDoc, 2), 'Pulse');
  assert.ok(!blueprintSeed.compiledHasWeakPricingElements(elementsDoc, layoutSchema));
});

test('pricing_three_plans graphics bind theme sequence not catalog hex', async () => {
  const layoutSchema = schemaForLayoutId('pricing_three_plans_v1');
  const paletteA = {
    primary: '#AA0000',
    accent: '#BB1100',
    secondary: '#CC2200',
    chart1: '#DD3300',
    muted: '#999999',
    cardBg: '#EEEEEE',
  };
  const paletteB = {
    primary: '#0011AA',
    accent: '#0022BB',
    secondary: '#0033CC',
    chart1: '#0044DD',
    muted: '#666666',
    cardBg: '#F4F4F4',
  };
  const { elementsDoc: docA } = await compileSlide({
    layoutSchema,
    content: { title: 'Plans' },
    themeTokens: { palette: paletteA },
    skipContentRepair: true,
  });
  const { elementsDoc: docB } = await compileSlide({
    layoutSchema,
    content: { title: 'Plans' },
    themeTokens: { palette: paletteB },
    skipContentRepair: true,
  });
  const { resolveGraphicDisplayColor } = require('@athena/contracts/graphicTheme.js');
  const starA = (docA.elements || []).find((e) => e.slotId === 'PRICING_TP_1_STAR');
  const starB = (docB.elements || []).find((e) => e.slotId === 'PRICING_TP_1_STAR');
  assert.ok(starA?.content?.sequenceIndex === 0);
  assert.ok(starB?.content?.sequenceIndex === 0);
  assert.notEqual(
    resolveGraphicDisplayColor(starA.content, paletteA),
    resolveGraphicDisplayColor(starB.content, paletteB)
  );
  const catalogHex = '#2EC4D6';
  const stale = (docA.elements || []).some(
    (e) => e.type === 'graphic' && e.content?.fill === catalogHex
  );
  assert.ok(!stale, 'expected no baked catalog hex on pricing graphics');
});

test('filterTemplatesForAiPricingIntent prefers tier-card layouts', () => {
  const { filterTemplatesForAiPricingIntent } = require('../deckLayout/pricingLayoutPolicy');
  const templates = [
    { schema: { layout_id: 'pricing_three_highlight_v1' } },
    { schema: { layout_id: 'pricing_three_plans_v1' } },
    { schema: { layout_id: 'pricing_comparison_table_v1' } },
  ];
  const filtered = filterTemplatesForAiPricingIntent(templates);
  const ids = filtered.map((t) => t.schema.layout_id);
  assert.ok(ids.includes('pricing_three_plans_v1'));
  assert.ok(!ids.includes('pricing_three_highlight_v1'));
});
