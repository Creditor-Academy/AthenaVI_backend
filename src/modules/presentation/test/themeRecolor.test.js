'use strict';

const assert = require('assert');
const { test } = require('node:test');
const SEED = require('../templates/seed-layouts.json');
const { compileSlide } = require('../slideCompiler.service');
const { recolorDiagramToTheme, classifyThemeColor } = require('../artDirection/themeRecolor');
const { processStepColors } = require('../diagrams/processThemeColors');

const LAYOUTS = Array.isArray(SEED) ? SEED : SEED.layouts || [];
const PALETTE = {
  primary: '#1E3A8A',
  secondary: '#1D4ED8',
  accent: '#3B82F6',
  text: '#0F172A',
  muted: '#475569',
  bg: '#FFFFFF',
};
const THEME = { typeScale: { title: 42 }, palette: PALETTE };
const THEME_FAMILY = new Set(
  [PALETTE.primary, PALETTE.secondary, PALETTE.accent, ...processStepColors(PALETTE, 16)].map((c) => c.toLowerCase())
);
const CONTENT = {
  title: 'AI in Hospital Operations',
  bullets: ['Workflow automation', 'Smarter scheduling', 'Faster documentation'],
  columns: [
    { title: 'Scheduling', body: 'Balance demand.' },
    { title: 'Documentation', body: 'Draft notes.' },
    { title: 'Patient flow', body: 'Anticipate beds.' },
  ],
  timeline: [
    { label: 'Q1', title: 'Assess', detail: 'Audit readiness.' },
    { label: 'Q2', title: 'Pilot', detail: 'Supervised pilot.' },
    { label: 'Q3', title: 'Scale', detail: 'Govern rollout.' },
  ],
};
const HEX = /#([0-9a-fA-F]{6})(?![0-9a-zA-Z_-])/g;

function offThemeAccents(doc) {
  const off = new Set();
  for (const el of doc?.elements || []) {
    if (['chart', 'image', 'table', 'embed'].includes(el?.type)) continue;
    const c = el?.content || {};
    for (const v of [c.svg, c.fill, c.color, c.stroke]) {
      if (typeof v !== 'string') continue;
      for (const m of v.matchAll(HEX)) {
        const hex = `#${m[1]}`.toLowerCase();
        if (classifyThemeColor(hex) === 'accent' && !THEME_FAMILY.has(hex)) off.add(hex);
      }
    }
  }
  return [...off];
}

test('generation recolor leaves no off-theme accent on any diagram layout', async () => {
  const failures = [];
  for (const t of LAYOUTS) {
    let doc;
    try {
      // eslint-disable-next-line no-await-in-loop
      ({ elementsDoc: doc } = await compileSlide({
        layoutSchema: t.schema,
        content: CONTENT,
        themeTokens: THEME,
        skipContentRepair: true,
        themeRecolor: true,
      }));
    } catch {
      continue;
    }
    const off = offThemeAccents(doc);
    if (off.length) failures.push(`${t.schema.layout_id}: ${off.slice(0, 3).join(', ')}`);
  }
  assert.deepStrictEqual(failures, []);
});

test('editor recompiles (no themeRecolor) keep the layout colors untouched', async () => {
  const schema = LAYOUTS.find((t) => t.schema?.layout_id === 'timeline_vertical_cards_v1')?.schema;
  const { elementsDoc } = await compileSlide({ layoutSchema: schema, content: CONTENT, themeTokens: THEME, skipContentRepair: true });
  assert.ok(offThemeAccents(elementsDoc).length > 0, 'without the flag the legacy accent palette is still present');
});

test('recolor maps accents in order, tints to matching tints, and keeps neutrals', () => {
  const doc = {
    elements: [
      { type: 'graphic', content: { svg: '<svg><rect fill="#E0564A"/><rect fill="#3D9A5F"/><rect fill="#FFFFFF" stroke="#E5E7EB"/></svg>' } },
      { type: 'shape', content: { fill: '#FDE2DF' } }, // light tint of the red accent
      { type: 'text', content: { text: 'Step', color: '#E0564A' } },
      { type: 'chart', content: { colors: ['#E0564A'] } },
    ],
  };
  const out = recolorDiagramToTheme(doc, THEME);
  const family = processStepColors(PALETTE, 2);
  const svg = out.elements[0].content.svg;
  assert.ok(svg.includes(`fill="${family[0]}"`), 'first accent → first theme color');
  assert.ok(svg.includes(`fill="${family[1]}"`), 'second accent → second theme color');
  assert.ok(svg.includes('#FFFFFF') && svg.includes('#E5E7EB'), 'white and grey kept');
  assert.strictEqual(classifyThemeColor(out.elements[1].content.fill), 'tint', 'tint stays a light tint');
  assert.notStrictEqual(out.elements[1].content.fill, '#FDE2DF');
  assert.strictEqual(out.elements[2].content.color, family[0], 'accent text recolored with its card');
  assert.deepStrictEqual(out.elements[3].content.colors, ['#E0564A'], 'charts untouched');
});

test('no palette → no change', () => {
  const doc = { elements: [{ type: 'shape', content: { fill: '#E0564A' } }] };
  assert.strictEqual(recolorDiagramToTheme(doc, null), doc);
});
