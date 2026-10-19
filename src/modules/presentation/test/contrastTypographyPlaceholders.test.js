'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('fs');
const path = require('path');
const { test } = require('node:test');
const { compileSlide } = require('../slideCompiler.service');
const {
  resolveSlotTextSurface,
  isImageOverlaySurface,
} = require('../artDirection/textSurface');
const { resolveHeadingTypography } = require('../artDirection/resolveHeadingTypography');
const { isLayoutEngineDefaultText } = require('../catalogPlaceholder');
const { layoutChartDonutContext } = require('../diagrams/chartDonutContext');
const { collectTextFromElementsDoc } = require('../contentIntegrity.util');
const { resolveColor } = require('../export.service');

const seedPath = path.join(__dirname, '../templates/seed-layouts.json');
const seedLayouts = JSON.parse(readFileSync(seedPath, 'utf8'));

function schemaForLayoutId(layoutId) {
  const entry = seedLayouts.find(
    (row) => String(row?.schema?.layout_id || row?.variant || '') === layoutId
  );
  assert.ok(entry?.schema, `missing seed schema for ${layoutId}`);
  return entry.schema;
}

const themeTokens = {
  typeScale: { display: 56, title: 40, subtitle: 28, body: 18, caption: 14, stat: 48 },
  palette: {
    text: '#0F172A',
    muted: '#64748B',
    textOnImage: '#FFFFFF',
    textOnImageMuted: '#E2E8F0',
    bg: '#FFFFFF',
    primary: '#2563EB',
  },
};

test('split-hero title heading slots classify as image overlay surface', () => {
  const layoutSchema = schemaForLayoutId('title_hero_left_fade_v1');
  const mainSlot = layoutSchema.slots.find((s) => s.id === 'MAIN_TITLE');
  assert.ok(mainSlot, 'MAIN_TITLE slot expected');
  const surface = resolveSlotTextSurface(mainSlot, layoutSchema, null, themeTokens);
  assert.ok(isImageOverlaySurface(surface), surface);
});

test('centered title on light theme stays solid light surface', () => {
  const layoutSchema = schemaForLayoutId('title_centered_v1');
  const mainSlot = layoutSchema.slots.find((s) => s.id === 'MAIN_TITLE');
  const surface = resolveSlotTextSurface(mainSlot, layoutSchema, null, themeTokens);
  assert.equal(surface, 'solidLight');
});

test('heading typography prefers typeScale over oversized seed fontSize', () => {
  const layoutSchema = { layout_id: 'section_heading_v1', content_type: 'content' };
  const slot = {
    id: 'HEADING',
    role: 'heading',
    typography: { fontSize: 68, colorRole: 'text' },
  };
  const headingTy = resolveHeadingTypography({
    slot,
    layoutSchema,
    themeTokens,
    placement: { width: 800, height: 120 },
    canvasWidth: 1920,
    canvasFontSizeForTextSlot: () => 72,
    resolveTypeScaleFontSize: () => null,
    styleForSlotFallback: () => ({ fontSize: 68 }),
  });
  assert.equal(headingTy.fontSize, 40);
});

test('chart donut context compile uses slide stats not CDC defaults', async () => {
  const layoutSchema = schemaForLayoutId('chart_donut_context_v1');
  const content = {
    title: 'Channel mix',
    body: 'Delivery growth outpaced dine-in last quarter.',
    stats: [
      { label: 'Dine-in', value: 32, body: 'Core footprint' },
      { label: 'Delivery', value: 28, body: 'Fastest growth' },
      { label: 'Catering', value: 22, body: 'Enterprise' },
      { label: 'Retail', value: 18, body: 'Grab-and-go' },
    ],
    chart: {
      labels: ['Dine-in', 'Delivery', 'Catering', 'Retail'],
      series: [{ values: [32, 28, 22, 18] }],
    },
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    themeTokens,
    skipContentRepair: true,
  });
  const text = collectTextFromElementsDoc(elementsDoc).join('\n');
  assert.ok(!/metric [a-d]/i.test(text), text);
  assert.ok(!isLayoutEngineDefaultText('Metric A') || !text.includes('Metric A'), text);
  assert.ok(text.includes('Dine-in'), text);
});

test('layoutChartDonutContext with content never injects MARKET SHARE badge default', () => {
  const layoutSchema = schemaForLayoutId('chart_donut_context_v1');
  const content = {
    title: 'Share',
    stats: [
      { label: 'A', value: 40, body: 'One' },
      { label: 'B', value: 30, body: 'Two' },
      { label: 'C', value: 20, body: 'Three' },
      { label: 'D', value: 10, body: 'Four' },
    ],
  };
  const seedEls = [
    { id: 't1', type: 'text', slotId: 'HEADING', role: 'heading', content: { text: 'Old' } },
  ];
  const out = layoutChartDonutContext(seedEls, layoutSchema, themeTokens.palette, {
    width: 1920,
    height: 1080,
    slideContent: content,
  });
  const joined = out.map((el) => el.content?.text || '').join(' ');
  assert.ok(!joined.includes('Metric A'), joined);
});

test('title hero compile assigns light-on-image color roles for main title', async () => {
  const layoutSchema = schemaForLayoutId('title_hero_left_fade_v1');
  const content = {
    title: 'GreenRoute Logistics',
    subtitle: 'Smarter last-mile delivery',
  };
  const coverTokens = {
    backgroundStyle: 'image',
    textContrast: 'high',
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    themeTokens,
    slideDesignPlan: { designTokens: coverTokens },
    skipContentRepair: true,
  });
  const main = (elementsDoc.elements || []).find(
    (el) => String(el.slotId || '').toUpperCase() === 'MAIN_TITLE'
  );
  assert.ok(main, 'MAIN_TITLE element expected');
  const role = main.content?.colorRole || main.content?.runs?.[0]?.colorRole;
  assert.ok(role === 'textOnImage' || String(main.content?.color || '').toUpperCase() === '#FFFFFF', JSON.stringify(main.content));
});

test('export resolveColor maps textOnImage role to light palette hex', () => {
  const hex = resolveColor('textOnImage', themeTokens.palette, '000000');
  assert.equal(hex.toUpperCase(), 'FFFFFF');
});

test('grid device mockups compile uses feature columns not GDM defaults', async () => {
  const layoutSchema = schemaForLayoutId('grid_device_mockups_v1');
  const content = {
    title: 'Mobile experience',
    columns: [
      { title: 'Route optimizer', body: 'Live traffic-aware routing for drivers.' },
      { title: 'Customer app', body: 'Real-time tracking and ETA notifications.' },
    ],
  };
  const { elementsDoc } = await compileSlide({
    layoutSchema,
    content,
    themeTokens,
    skipContentRepair: true,
  });
  const text = collectTextFromElementsDoc(elementsDoc).join('\n');
  assert.ok(!/describe this feature/i.test(text), text);
  assert.ok(text.includes('Route optimizer'), text);
});
