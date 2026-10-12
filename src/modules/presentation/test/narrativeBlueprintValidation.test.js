'use strict';

const assert = require('assert');
const { test, describe } = require('node:test');
const {
  applyProtectedBookends,
  syncAgendaFromOutline,
  normalizeRole,
} = require('../narrativeSlideBlueprints');
const {
  validateNarrativeBlueprint,
  assertAllowedSlideCount,
} = require('../narrativeBlueprintValidate.service');
const {
  filterTemplatesForSlideOrder,
  isClosingIncompatibleLayout,
} = require('../layoutSelector.service');
const layoutCatalogPolicy = require('../layoutCatalogPolicy');
const { guardContentTypeForSlideOrder } = require('../deckGeneration.service');

const MIDDLE_ROLES = [
  'introduction',
  'problem_statement',
  'key_insight',
  'solution_overview',
  'process_workflow',
  'comparison_options',
  'feature_breakdown',
  'case_study',
];

function stubSlides(count) {
  const slides = [];
  for (let o = 1; o <= count; o += 1) {
    let suggested = 'image+text';
    let role = MIDDLE_ROLES[(o - 3) % MIDDLE_ROLES.length];
    if (o === 1) {
      suggested = 'title';
      role = 'hero_title';
    } else if (o === 2) {
      suggested = 'agenda';
      role = 'agenda_overview';
    } else if (o === count) {
      suggested = 'closing';
      role = 'summary_cta';
    } else if (count >= 6 && o === count - 1) {
      suggested = 'bullet_list';
      role = 'key_takeaways';
    }
    slides.push({
      order: o,
      title: `Slide ${o} headline`,
      summary: 'Argument for this slide.',
      beats: o === 2 ? [] : ['a', 'b'],
      suggestedContentType: suggested,
      narrativeRole: role,
    });
  }
  return applyProtectedBookends(slides, count, { sourceText: 'Quarterly metrics and strategy' });
}

describe('narrative blueprint validation', () => {
  for (const n of [5, 8, 10, 12, 20]) {
    test(`N=${n} bookends and flexible middle preserved`, () => {
      const slides = stubSlides(n);
      const targetOrder = n === 5 ? 3 : 6;
      slides.find((s) => s.order === targetOrder).narrativeRole = 'comparison_options';
      const layered = applyProtectedBookends(slides, n, { sourceText: 'test' });
      assert.strictEqual(
        normalizeRole(layered.find((s) => s.order === targetOrder)?.narrativeRole),
        'comparison_options'
      );
      const outline = {
        slideCount: n,
        slides: syncAgendaFromOutline(layered, n),
      };
      if (n === 20) {
        assert.strictEqual(
          normalizeRole(outline.slides.find((s) => s.order === 1)?.narrativeRole),
          'hero_title'
        );
        assert.strictEqual(
          String(outline.slides.find((s) => s.order === 20)?.suggestedContentType),
          'closing'
        );
      } else {
        const result = validateNarrativeBlueprint(outline);
        assert.strictEqual(result.ok, true, result.errors.join('; '));
      }
    });
  }

  test('N=5 has two middle slides and no synthesis order', () => {
    const slides = syncAgendaFromOutline(stubSlides(5), 5);
    assert.strictEqual(slides.length, 5);
    const syn = slides.find((s) => s.order === 4);
    assert.ok(syn);
    assert.notStrictEqual(normalizeRole(syn.narrativeRole), 'summary_cta');
    const agenda = slides.find((s) => s.order === 2);
    assert.ok(agenda.beats.some((b) => /Slide 3/.test(b)));
    assert.ok(agenda.beats.some((b) => /Slide 4/.test(b)));
  });

  test('N>=6 penultimate synthesis and agenda excludes synthesis slide', () => {
    const slides = syncAgendaFromOutline(stubSlides(8), 8);
    const syn = slides.find((s) => s.order === 7);
    assert.strictEqual(normalizeRole(syn.narrativeRole), 'key_takeaways');
    const agenda = slides.find((s) => s.order === 2);
    assert.ok(!agenda.beats.some((b) => /Slide 7/.test(b)));
    assert.ok(agenda.beats.some((b) => /Slide 3/.test(b)));
  });

  test('outline title change on slide 4 updates agenda beats', () => {
    let slides = syncAgendaFromOutline(stubSlides(8), 8);
    slides = slides.map((s) =>
      s.order === 4 ? { ...s, title: 'Renamed content block' } : s
    );
    slides = syncAgendaFromOutline(slides, 8);
    const agenda = slides.find((s) => s.order === 2);
    assert.ok(agenda.beats.includes('Renamed content block'));
  });

  test('enforceSlideCount does not pad when allowPad false', () => {
    const one = [{ order: 1, title: 'Only', summary: 's', suggestedContentType: 'title' }];
    const trimmed = layoutCatalogPolicy.enforceSlideCount(one, 5, { allowPad: false });
    assert.strictEqual(trimmed.length, 1);
    const padded = layoutCatalogPolicy.enforceSlideCount(one, 5, { allowPad: true });
    assert.strictEqual(padded.length, 5);
  });

  test('validator rejects slide count mismatch', () => {
    const outline = { slideCount: 8, slides: stubSlides(5) };
    const result = validateNarrativeBlueprint(outline);
    assert.strictEqual(result.ok, false);
    assert.ok(result.errors.some((e) => /slides\.length/.test(e)));
  });

  test('assertAllowedSlideCount rejects 15', () => {
    assert.ok(assertAllowedSlideCount(15));
    assert.strictEqual(assertAllowedSlideCount(8), null);
  });

  test('guardContentTypeForSlideOrder: slide 2 agenda, penultimate demotes chart', () => {
    assert.strictEqual(guardContentTypeForSlideOrder('bullet_list', 2, 8, {}), 'agenda');
    assert.strictEqual(guardContentTypeForSlideOrder('chart', 7, 8, {}), 'bullet_list');
    assert.strictEqual(guardContentTypeForSlideOrder('chart', 7, 8, { layoutLocked: true }), 'chart');
    assert.strictEqual(guardContentTypeForSlideOrder('closing', 8, 8, {}), 'closing');
  });
});

describe('closing layout filter', () => {
  test('last slide pool excludes chart/diagram layout ids', () => {
    const templates = [
      { contentType: 'closing', schema: { layout_id: 'closing_thank_you_v1', content_type: 'closing', slots: [] } },
      { contentType: 'chart', schema: { layout_id: 'chart_two_v1', content_type: 'chart', slots: [{ type: 'chart', id: 'chart_a' }] } },
      { contentType: 'closing', schema: { layout_id: 'diagram_process_v1', content_type: 'closing', slots: [] } },
      { contentType: 'closing', schema: { layout_id: 'centered_text_cta_v1', content_type: 'closing', slots: [{ type: 'text', id: 'title' }] } },
    ];
    assert.strictEqual(isClosingIncompatibleLayout(templates[1]), true);
    assert.strictEqual(isClosingIncompatibleLayout(templates[2]), true);
    const filtered = filterTemplatesForSlideOrder(templates, 4, 4);
    const ids = filtered.map((t) => t.schema.layout_id);
    assert.ok(!ids.includes('chart_two_v1'));
    assert.ok(!ids.includes('diagram_process_v1'));
    assert.ok(ids.includes('closing_thank_you_v1') || ids.includes('centered_text_cta_v1'));
  });
});
