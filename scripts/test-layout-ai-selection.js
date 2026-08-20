/**
 * OpenAI final layout selector (mocked chatJson, no live API).
 * Run: node scripts/test-layout-ai-selection.js
 */
const assert = require('assert');
const {
  selectBestLayoutWithAI,
  resetLayoutAiSelectionCache,
} = require('../src/modules/presentation/deckLayout/selectBestLayoutWithAI');

const slide = {
  purpose: 'solution',
  contentTypes: ['title', 'paragraph', 'image'],
  titleLength: 40,
  subtitleLength: 0,
  bodyLength: 80,
  bulletCount: 0,
  cardCount: 0,
  imageCount: 1,
  metricCount: 0,
  hasChart: false,
  hasTable: false,
  hasQuote: false,
  density: 'medium',
  slideNumber: 5,
};

const candidates = [
  {
    layoutId: 'layout_042',
    score: 94,
    breakdown: {
      purposeMatch: 25,
      contentTypeMatch: 24,
      capacityMatch: 15,
      compositionMatch: 10,
      styleMatch: 9,
      industryMatch: 5,
      repetitionPenalty: 0,
    },
    reasons: ['Exact match for solution slide purpose'],
  },
  {
    layoutId: 'layout_018',
    score: 91,
    breakdown: {
      purposeMatch: 25,
      contentTypeMatch: 22,
      capacityMatch: 15,
      compositionMatch: 9,
      styleMatch: 8,
      industryMatch: 5,
      repetitionPenalty: 0,
    },
    reasons: ['Related purpose match'],
  },
  {
    layoutId: 'layout_076',
    score: 86,
    breakdown: {
      purposeMatch: 18,
      contentTypeMatch: 20,
      capacityMatch: 14,
      compositionMatch: 8,
      styleMatch: 8,
      industryMatch: 5,
      repetitionPenalty: 0,
    },
    reasons: [],
  },
];

const ctx = {
  title: 'AI Healthcare Revolution',
  purpose: 'Investor pitch',
  audience: 'Technology investors',
  industry: 'healthcare',
  tone: 'Premium / innovative',
  slideNumber: 5,
  totalSlides: 10,
  previousSlides: [{ slideNumber: 4, purpose: 'market', layoutId: 'layout_018' }],
  nextSlide: { purpose: 'product' },
};

function baseOpts(chatJson, extra = {}) {
  return {
    slide,
    candidates,
    presentationContext: ctx,
    previousLayoutIds: ['layout_018'],
    layoutsById: {
      layout_042: { name: 'Image + Text Split', category: 'content', slidePurposes: ['solution'] },
      layout_018: { name: 'Text Heavy', category: 'content' },
      layout_076: { name: 'Cards', category: 'content' },
    },
    chatJson,
    config: { cacheTtlMs: 0, timeoutMs: 5000, aiSelectionMinConfidence: 70 },
    ...extra,
  };
}

async function main() {
  /* Test 1 — valid candidate */
  resetLayoutAiSelectionCache();
  let result = await selectBestLayoutWithAI(
    baseOpts(async () => ({
      data: {
        selectedLayoutId: 'layout_018',
        confidence: 88,
        reason: 'Better narrative bridge into the product demo.',
        alternativeLayoutId: 'layout_042',
      },
    }))
  );
  assert.ok(candidates.some((c) => c.layoutId === result.selectedLayoutId));
  assert.strictEqual(result.selectedLayoutId, 'layout_018');
  assert.strictEqual(result.source, 'ai');
  assert.strictEqual(result.usedFallback, false);

  /* Test 2 — invalid layout ID */
  resetLayoutAiSelectionCache();
  result = await selectBestLayoutWithAI(
    baseOpts(async () => ({
      data: { selectedLayoutId: 'layout_999', confidence: 99, reason: 'Invented' },
    }))
  );
  assert.strictEqual(result.selectedLayoutId, candidates[0].layoutId);
  assert.strictEqual(result.usedFallback, true);

  /* Test 3 — low confidence */
  resetLayoutAiSelectionCache();
  result = await selectBestLayoutWithAI(
    baseOpts(async () => ({
      data: { selectedLayoutId: 'layout_018', confidence: 55, reason: 'Unsure' },
    }))
  );
  assert.strictEqual(result.selectedLayoutId, candidates[0].layoutId);
  assert.strictEqual(result.source, 'deterministic');
  assert.strictEqual(result.usedFallback, true);

  /* Test 4 — API failure */
  resetLayoutAiSelectionCache();
  result = await selectBestLayoutWithAI(
    baseOpts(async () => {
      throw new Error('rate limit');
    })
  );
  assert.strictEqual(result.selectedLayoutId, candidates[0].layoutId);
  assert.strictEqual(result.source, 'fallback');

  /* Test 5 — previous layout IDs in prompt */
  resetLayoutAiSelectionCache();
  let capturedUser = '';
  result = await selectBestLayoutWithAI(
    baseOpts(async ({ user }) => {
      capturedUser = user;
      return {
        data: {
          selectedLayoutId: 'layout_042',
          confidence: 90,
          reason: 'Fit',
        },
      };
    })
  );
  assert.ok(capturedUser.includes('layout_018'), 'prompt includes previous layout ids');
  assert.ok(capturedUser.includes('Allowed layout IDs'));
  assert.strictEqual(result.selectedLayoutId, 'layout_042');

  /* Test 6 — single candidate skips OpenAI */
  resetLayoutAiSelectionCache();
  let called = 0;
  result = await selectBestLayoutWithAI({
    ...baseOpts(async () => {
      called += 1;
      return { data: { selectedLayoutId: 'layout_042', confidence: 90, reason: 'x' } };
    }),
    candidates: [candidates[0]],
  });
  assert.strictEqual(called, 0);
  assert.strictEqual(result.source, 'single_candidate');
  assert.strictEqual(result.selectedLayoutId, 'layout_042');

  /* Test 7 — AI disabled uses deterministic winner */
  resetLayoutAiSelectionCache();
  called = 0;
  result = await selectBestLayoutWithAI(
    baseOpts(async () => {
      called += 1;
      return { data: { selectedLayoutId: 'layout_018', confidence: 95, reason: 'x' } };
    }, { config: { cacheTtlMs: 0, timeoutMs: 5000, aiSelectionMinConfidence: 70, aiEnabled: false } })
  );
  assert.strictEqual(called, 0);
  assert.strictEqual(result.selectedLayoutId, candidates[0].layoutId);
  assert.strictEqual(result.source, 'deterministic');

  /* Test 8 — planning phase skips OpenAI */
  resetLayoutAiSelectionCache();
  called = 0;
  result = await selectBestLayoutWithAI(
    baseOpts(async () => {
      called += 1;
      return { data: { selectedLayoutId: 'layout_018', confidence: 95, reason: 'x' } };
    }, { phase: 'planning' })
  );
  assert.strictEqual(called, 0);
  assert.strictEqual(result.selectedLayoutId, candidates[0].layoutId);
  assert.strictEqual(result.source, 'deterministic');

  /* Test 9 — locked layout bypasses AI */
  resetLayoutAiSelectionCache();
  called = 0;
  result = await selectBestLayoutWithAI(
    baseOpts(async () => {
      called += 1;
      return { data: { selectedLayoutId: 'layout_018', confidence: 95, reason: 'x' } };
    }, { layoutLocked: true, lockedLayoutId: 'layout_076' })
  );
  assert.strictEqual(called, 0);
  assert.strictEqual(result.selectedLayoutId, 'layout_076');
  assert.strictEqual(result.source, 'locked');

  /* Cache hit skips second call */
  resetLayoutAiSelectionCache();
  called = 0;
  const chatJson = async () => {
    called += 1;
    return {
      data: { selectedLayoutId: 'layout_076', confidence: 92, reason: 'Cached pick' },
    };
  };
  const opts = baseOpts(chatJson, {
    config: { cacheTtlMs: 60_000, timeoutMs: 5000, aiSelectionMinConfidence: 70 },
  });
  const first = await selectBestLayoutWithAI(opts);
  const second = await selectBestLayoutWithAI(opts);
  assert.strictEqual(first.selectedLayoutId, 'layout_076');
  assert.strictEqual(second.selectedLayoutId, 'layout_076');
  assert.strictEqual(called, 1, 'second identical request uses cache');

  console.log('ok: layout AI selection (mocked)');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
