'use strict';

const assert = require('assert');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { compileSlide } = require('../slideCompiler.service');
const { collectTextFromElementsDoc } = require('../contentIntegrity.util');
const { isCatalogPlaceholderText } = require('../catalogPlaceholder');
const { isSyntheticRepairFingerprint } = require('@athena/contracts/slotText.js');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function richFixtureContent() {
  return {
    title: '__SLIDE_TITLE_MARKER__',
    subtitle: '__SUBTITLE__',
    body: '__BODY__',
    summary: '__SUMMARY__',
    isIllustrative: true,
    chart: {
      type: 'bar',
      labels: ['A', 'B', 'C', 'D'],
      series: [{ name: 'Series', values: [10, 20, 30, 40] }],
      isIllustrative: true,
    },
    chart2: {
      type: 'bar',
      labels: ['E', 'F', 'G', 'H'],
      series: [{ name: 'Series 2', values: [11, 22, 33, 44] }],
      isIllustrative: true,
    },
    left: {
      title: '__LEFT_TITLE__',
      bullets: ['__LEFT_B1__', '__LEFT_B2__', '__LEFT_B3__'],
    },
    right: {
      title: '__RIGHT_TITLE__',
      bullets: ['__RIGHT_B1__', '__RIGHT_B2__', '__RIGHT_B3__'],
    },
    columns: Array.from({ length: 8 }, (_, i) => ({
      title: `__COL_T_${i + 1}__`,
      body: `__COL_B_${i + 1}__`,
    })),
    timeline: [
      { label: '2024', detail: '__STEP1_D__' },
      { label: '2025', detail: '__STEP2_D__' },
      { label: '2026', detail: '__STEP3_D__' },
    ],
    stats: [
      { value: '10', label: '__MA_L__' },
      { value: '20', label: '__MB_L__' },
    ],
    bullets: ['__B1__', '__B2__', '__B3__', '__B4__', '__B5__', '__B6__'],
    steps: Array.from({ length: 6 }, (_, i) => ({
      title: `__STEP_${i + 1}_T__`,
      body: `__STEP_${i + 1}_B__`,
    })),
    diagram: {
      cells: Array.from({ length: 6 }, (_, i) => ({
        title: `__STEP_${i + 1}_T__`,
        body: `__STEP_${i + 1}_B__`,
      })),
    },
  };
}

test('all 246 active seeded layouts compile without catalog placeholders or synthetic repair text', async () => {
  const active = seedLayouts.filter((row) => row?.schema?.layout_id);
  assert.equal(active.length, 246);

  const violations = [];
  let checked = 0;

  for (const entry of active) {
    const layoutSchema = entry.schema;
    const layoutId = layoutSchema.layout_id;
    checked += 1;
    const { elementsDoc } = await compileSlide({
      layoutSchema,
      content: richFixtureContent(),
      skipContentRepair: true,
      canvasSize: { width: 1920, height: 1080 },
    });
    for (const text of collectTextFromElementsDoc(elementsDoc)) {
      if (isCatalogPlaceholderText(text)) {
        violations.push({ layoutId, kind: 'catalog', text });
      }
      if (isSyntheticRepairFingerprint(text)) {
        violations.push({ layoutId, kind: 'synthetic', text });
      }
    }
  }

  assert.equal(checked, 246, `expected 246 layouts checked, got ${checked}`);
  assert.deepStrictEqual(
    violations,
    [],
    violations.slice(0, 5).map((v) => `${v.layoutId} ${v.kind}: ${v.text}`).join('; ')
  );
});
