/**
 * Path B vs process layouts — policy regression tests.
 * Run: node scripts/test-path-b-vs-layouts.js
 */
const assert = require('assert');
const {
  looksLikeLinearProcessSlide,
  looksLikePathBTopology,
  hasUsablePathBSpec,
  preferredProcessLayoutId,
  resolveDiagramVisualPolicy,
} = require('../src/modules/presentation/diagramPathPolicy.util');
const {
  applyDeckImageStrategyToVisualNeed,
} = require('../src/modules/presentation/artDirection/imageDistribution');
const { applyVisualPolicy } = require('../src/modules/presentation/deckGeneration.service');
const {
  enrichOutlineWithArrangement,
} = require('../src/modules/presentation/slideArrangementPlan.service');

// --- NovaFlow-style how-it-works → process layout path (not Path B)
const nova = {
  title: 'How NovaFlow Works',
  summary: 'Upload → Extract → Validate → Post to ERP',
  beats: ['Upload', 'Extract', 'Validate', 'Post'],
};
assert.strictEqual(looksLikeLinearProcessSlide(nova), true, 'NovaFlow is linear process');
assert.strictEqual(looksLikePathBTopology(nova), false, 'NovaFlow is not Path B topology');

const novaPolicy = resolveDiagramVisualPolicy({
  visualNeed: 'photo',
  contentType: 'grid',
  content: { title: nova.title, bullets: nova.beats },
  outlineSlide: { title: nova.title, summary: nova.summary, beats: nova.beats },
});
assert.strictEqual(novaPolicy.visualNeed, 'diagram_template', 'NovaFlow → diagram_template');
assert.strictEqual(novaPolicy.contentType, 'diagram', 'NovaFlow → diagram content type');
assert.strictEqual(
  preferredProcessLayoutId(4),
  'diagram_process_steps_v1',
  '4-step prefers process steps layout'
);

// --- Architecture/ERD → Path B topology signal
const arch = {
  title: 'Platform architecture',
  summary: 'Client → API Gateway → Workers with branching to Cache and ERD schema map',
  beats: ['API Gateway', 'Workers', 'Postgres ERD', 'Redis cache'],
};
assert.strictEqual(looksLikePathBTopology(arch), true, 'architecture is Path B topology');
assert.strictEqual(looksLikeLinearProcessSlide(arch), false, 'architecture not linear process');

// --- Empty pathBSpec falls back to diagram_template
const emptyPathB = resolveDiagramVisualPolicy({
  visualNeed: 'path_b',
  contentType: 'diagram',
  content: { title: 'Systems', pathBSpec: null },
});
assert.strictEqual(emptyPathB.visualNeed, 'diagram_template', 'empty pathBSpec → diagram_template');
assert.strictEqual(hasUsablePathBSpec(null), false);
assert.strictEqual(hasUsablePathBSpec({ panels: [] }), false);
assert.strictEqual(
  hasUsablePathBSpec({
    panels: [{ title: 'Ingest', steps: ['Client', 'API', 'Queue'] }],
  }),
  true,
  'usable pathBSpec detected'
);

const keepPathB = resolveDiagramVisualPolicy({
  visualNeed: 'path_b',
  contentType: 'diagram',
  content: {
    title: 'Architecture',
    pathBSpec: {
      panels: [
        { title: 'Edge', content: 'CDN → API Gateway' },
        { title: 'Core', steps: ['Auth', 'Billing', 'Ledger'] },
      ],
    },
  },
  outlineSlide: arch,
});
assert.strictEqual(keepPathB.visualNeed, 'path_b', 'usable pathBSpec keeps path_b');

// --- imageDistribution preserves path_b and diagram_template
assert.strictEqual(
  applyDeckImageStrategyToVisualNeed({
    currentVisualNeed: 'path_b',
    usage: 'required',
    preferVisuals: true,
  }),
  'path_b',
  'rhythm required must not wipe path_b'
);
assert.strictEqual(
  applyDeckImageStrategyToVisualNeed({
    currentVisualNeed: 'diagram_template',
    usage: 'required',
    preferVisuals: true,
  }),
  'diagram_template',
  'rhythm required must not wipe diagram_template'
);

// --- applyVisualPolicy preserves specialized modes
assert.strictEqual(
  applyVisualPolicy({
    visualNeed: 'path_b',
    contentType: 'diagram',
    preferVisuals: true,
  }).visualNeed,
  'path_b'
);
assert.strictEqual(
  applyVisualPolicy({
    visualNeed: 'diagram_template',
    contentType: 'grid',
    preferVisuals: true,
  }).visualNeed,
  'diagram_template'
);
assert.strictEqual(
  applyVisualPolicy({
    visualNeed: 'diagram_template',
    contentType: 'grid',
    preferVisuals: true,
  }).layoutContentType,
  'diagram',
  'diagram_template forces diagram layout type'
);

// --- Outline enrichment promotes how-it-works to diagram
const enriched = enrichOutlineWithArrangement({
  slides: [
    { order: 1, title: 'NovaFlow', suggestedContentType: 'title', summary: 'Cover' },
    {
      order: 2,
      title: 'How it works',
      summary: 'Upload Extract Validate Post',
      beats: ['Upload', 'Extract', 'Validate', 'Post'],
      suggestedContentType: 'grid',
    },
    { order: 3, title: 'Thanks', suggestedContentType: 'closing', summary: 'End' },
  ],
});
assert.strictEqual(
  enriched.slides[1].suggestedContentType,
  'diagram',
  'outline how-it-works promoted to diagram'
);
assert.strictEqual(
  enriched.slides[1].visual_need,
  'diagram_template',
  'outline how-it-works gets diagram_template visual_need'
);

console.log('ok: path B vs process layouts policy', {
  novaLayout: preferredProcessLayoutId(4),
  novaVisual: novaPolicy.visualNeed,
  pathBKept: keepPathB.visualNeed,
});
