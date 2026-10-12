'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { compileSlide } = require('../slideCompiler.service');
const { prepareContentForCompile } = require('../contentRepair.service');
const {
  collectTextFromElementsDoc,
  scanCompiledContentIntegrity,
} = require('../contentIntegrity.util');
const { isSyntheticRepairFingerprint } = require('@athena/contracts/slotText.js');
const { collectRawArrayOverflowErrors } = require('@athena/contracts/contentContract.js');
const { buildPptxBuffer } = require('../export.service');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function schemaForLayoutId(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry?.schema, `missing seed schema for ${layoutId}`);
  return entry.schema;
}

function joinedText(elementsDoc) {
  return collectTextFromElementsDoc(elementsDoc).join('\n');
}

test('dual-chart layout without illustrative flag does not inject sample Q1 series', async () => {
  const layoutSchema = schemaForLayoutId('chart_two_v1');
  const content = {
    title: 'Revenue mix',
    chart: {
      type: 'bar',
      labels: ['Product A', 'Product B', 'Product C', 'Product D'],
      series: [{ name: 'Share', values: [40, 30, 20, 10] }],
    },
  };
  const { elementsDoc, audit } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const text = joinedText(elementsDoc);
  assert.ok(!text.includes('Q1'), `unexpected sample chart labels: ${text}`);
  assert.ok(
    (audit.integrity?.issues || []).some((i) => i.code === 'MISSING_CHART_SLOT'),
    'expected missing secondary chart issue'
  );
});

test('illustrative dual-chart may render sample data for empty secondary slot', async () => {
  const layoutSchema = schemaForLayoutId('chart_two_v1');
  const content = {
    title: 'Demo metrics',
    isIllustrative: true,
    chart: {
      type: 'bar',
      labels: ['A', 'B', 'C', 'D'],
      series: [{ name: 'One', values: [10, 20, 30, 40] }],
      isIllustrative: true,
    },
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const charts = (elementsDoc.elements || []).filter((el) => el.type === 'chart');
  assert.ok(charts.length >= 2, 'expected illustrative sample on second chart slot');
});

test('underfilled card layout does not invent Focus area titles', async () => {
  const layoutSchema = schemaForLayoutId('two_cards_image_text_v1');
  const content = { title: 'Strategy', columns: [{ title: 'Only', body: 'One card' }] };
  const prepared = await prepareContentForCompile({ content, layoutSchema, context: {} });
  assert.ok(!String(prepared.content.columns?.[0]?.title || '').includes('Focus area'));
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content: prepared.content,
    skipContentRepair: true,
  });
  const text = joinedText(elementsDoc);
  assert.ok(!/Focus area \d/i.test(text), text);
  assert.ok(
    prepared.audit.issues.some((i) => i.code === 'GROUP_UNDERFILL' || i.rule === 'group_underfill'),
    'expected underfill issue'
  );
});

test('timeline pre-shape does not fabricate 2010-era milestone years', async () => {
  const layoutSchema = schemaForLayoutId('timeline_horizontal_v1');
  const content = {
    title: 'Roadmap',
    timeline: [{ label: 'Launch', detail: 'Go live' }],
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const text = joinedText(elementsDoc);
  assert.ok(!/\b201[0-9]\b/.test(text), `fabricated year in: ${text}`);
});

test('prepareContentForCompile preserves raw ARRAY_OVERFLOW on original counts', async () => {
  const layoutSchema = schemaForLayoutId('two_cards_image_text_v1');
  const raw = {
    title: 'Cards',
    columns: [
      { title: '1', body: 'a' },
      { title: '2', body: 'b' },
      { title: '3', body: 'c' },
      { title: '4', body: 'd' },
      { title: '5', body: 'overflow' },
    ],
  };
  assert.ok(collectRawArrayOverflowErrors(raw, layoutSchema).length >= 1);
  const prepared = await prepareContentForCompile({ content: raw, layoutSchema, context: {} });
  assert.ok(
    prepared.audit.issues.some((i) => i.code === 'ARRAY_OVERFLOW' && i.repairable === false),
    JSON.stringify(prepared.audit.issues)
  );
  assert.equal(prepared.content.columns.length, 5, 'overflow must not be silently sliced during repair');
});

test('compile reconcile strips catalog placeholder title from elements', async () => {
  const layoutSchema = schemaForLayoutId('bullet_list_split_v1');
  const content = { title: 'Option A', bullets: ['Real point one', 'Real point two'] };
  const outlineSlide = { title: 'Seeded title', beats: ['Beat one', 'Beat two'] };
  const { elementsDoc, audit } = await compileSlide({
    layoutSchema,
    content,
    outlineSlide,
    skipContentRepair: true,
  });
  const titleEl = (elementsDoc?.elements || []).find((el) =>
    /title|heading/i.test(String(el.role || el.slotId || ''))
  );
  const titleText = titleEl?.content?.text || '';
  assert.ok(!/option a/i.test(titleText), `catalog placeholder survived: ${titleText}`);
  assert.ok(
    audit.reseedBlockedReason === 'content_integrity' ||
      (audit.warnings || []).includes('BLUEPRINT_RESEED_BLOCKED') ||
      !audit.emptySlotFallback,
    'reseed should not mask placeholder title'
  );
});

test('export path text excludes synthetic repair fingerprints', async () => {
  const layoutSchema = schemaForLayoutId('title_centered_v1');
  const content = { title: 'Export check', subtitle: 'Sub' };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    skipContentRepair: true,
  });
  const deck = {
    themeTokens: { palette: { bg: '#fff', text: '#111', primary: '#333' } },
    slides: [{ order: 1, elements: elementsDoc, content, imageRef: null }],
  };
  const buffer = await buildPptxBuffer(deck);
  assert.ok(buffer && buffer.length > 100);
  for (const text of collectTextFromElementsDoc(elementsDoc)) {
    assert.ok(!isSyntheticRepairFingerprint(text), text);
  }
});
