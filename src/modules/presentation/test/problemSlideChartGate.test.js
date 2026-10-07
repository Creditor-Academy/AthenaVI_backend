'use strict';

const assert = require('assert');
const { test } = require('node:test');
const {
  guardNarrativeContentType,
  isProblemNarrativeSlide,
} = require('../narrativeContentTypeGuard');
const { demoteSpuriousChart, chartsHaveDuplicateSeries } = require('../chartStory.util');
const { filterTemplatesForProblemIntent } = require('../deckLayout/problemLayoutPolicy');

const PULSEFIT_CHART_CONTENT = {
  title: 'Why Traditional Gyms Fail to Deliver Consistent Results',
  bullets: ['Lack of structure', 'No progress tracking', 'Overcrowding'],
  chart: {
    type: 'bar',
    labels: ['Lack of Structure', 'No Progress Tracking', 'Overcrowding', 'Low Motivation', 'Equipment Wait Time'],
    series: [{ name: 'Pain', values: [68, 75, 82, 60, 55] }],
    isIllustrative: true,
  },
  chart2: {
    type: 'bar',
    labels: ['Q1', 'Q2', 'Q3', 'Q4'],
    series: [{ name: 'Pain', values: [68, 75, 82, 60] }],
    isIllustrative: true,
  },
};

const PROBLEM_OUTLINE = {
  purpose: 'problem',
  narrativeRole: 'problem_statement',
  suggestedContentType: 'bullet_list',
  title: 'Why Traditional Gyms Fail to Deliver Consistent Results',
  beats: ['Lack of structure', 'No progress tracking', 'Overcrowding'],
};

test('isProblemNarrativeSlide detects problem_statement role', () => {
  assert.ok(isProblemNarrativeSlide(PROBLEM_OUTLINE));
  assert.ok(!isProblemNarrativeSlide({ narrativeRole: 'research_data' }));
});

test('guardNarrativeContentType demotes chart and strips chart fields', () => {
  const content = { ...PULSEFIT_CHART_CONTENT };
  const result = guardNarrativeContentType(PROBLEM_OUTLINE, 'chart', content, {
    outlineExplicit: true,
    visualNeed: 'chart',
  });
  assert.ok(result.adjusted);
  assert.notEqual(result.contentType, 'chart');
  assert.equal(result.contentType, 'bullet_list');
  assert.equal(content.chart, undefined);
  assert.equal(content.chart2, undefined);
});

test('demoteSpuriousChart demotes PulseFit-style invented dual chart on problem slide', () => {
  const demoted = demoteSpuriousChart({
    contentType: 'chart',
    visualNeed: 'chart',
    content: { ...PULSEFIT_CHART_CONTENT },
    outlineSlide: PROBLEM_OUTLINE,
    preferVisuals: true,
  });
  assert.ok(demoted.demoted);
  assert.equal(demoted.contentType, 'bullet_list');
});

test('chartsHaveDuplicateSeries detects mirrored chart + chart2 values', () => {
  assert.ok(chartsHaveDuplicateSeries(PULSEFIT_CHART_CONTENT));
});

test('filterTemplatesForProblemIntent removes chart layouts', () => {
  const templates = [
    { schema: { layout_id: 'chart_two_v1' } },
    { schema: { layout_id: 'bullet_split_image_v1' } },
    { schema: { layout_id: 'two_para_right_image_v1' } },
  ];
  const filtered = filterTemplatesForProblemIntent(templates, { outlineSlide: PROBLEM_OUTLINE });
  const ids = filtered.map((t) => t.schema.layout_id);
  assert.ok(!ids.includes('chart_two_v1'));
  assert.ok(ids.includes('bullet_split_image_v1'));
});
