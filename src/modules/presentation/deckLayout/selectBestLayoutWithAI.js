const crypto = require('crypto');
const { chatJson: defaultChatJson } = require('../../../shared/services/ai');
const { getLayoutAiSelectionConfig, AI_LAYOUT_SELECTION_SCHEMA } = require('./layoutAiSelection.config');
const {
  AI_LAYOUT_SELECTOR_SYSTEM_PROMPT,
  buildLayoutAiUserPrompt,
} = require('./layoutAiSelection.prompt');

/** @type {Map<string, { expiresAt: number, value: object }>} */
const cache = new Map();

function resetLayoutAiSelectionCache() {
  cache.clear();
}

function hashKey(payload) {
  return crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
}

function cacheGet(key, ttlMs) {
  if (!ttlMs) return null;
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() > hit.expiresAt) {
    cache.delete(key);
    return null;
  }
  return hit.value;
}

function cacheSet(key, value, ttlMs, maxEntries) {
  if (!ttlMs) return;
  if (cache.size >= maxEntries) {
    const first = cache.keys().next().value;
    if (first) cache.delete(first);
  }
  cache.set(key, { value, expiresAt: Date.now() + ttlMs });
}

function candidateIds(candidates) {
  return (Array.isArray(candidates) ? candidates : [])
    .map((c) => String(c?.layoutId || '').trim())
    .filter(Boolean);
}

function fallbackResult(candidates, layoutsById, reason, source = 'fallback') {
  const ids = candidateIds(candidates);
  const firstCandidate = ids[0] || null;
  const layoutKeys = layoutsById && typeof layoutsById === 'object' ? Object.keys(layoutsById) : [];
  const selectedLayoutId = firstCandidate || layoutKeys[0] || '';
  return {
    selectedLayoutId,
    confidence: firstCandidate ? Number(candidates[0]?.score) || 0 : 0,
    reason,
    source,
    usedFallback: true,
  };
}

function normalizePhase(phase) {
  const p = String(phase || '').trim().toLowerCase();
  if (p === 'planning' || p === 'plan') return 'planning';
  if (p === 'pre_content' || p === 'precontent' || p === 'pre') return 'pre_content';
  return 'final';
}

function clampConfidence(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.min(100, Math.max(0, n));
}

function withTimeout(promise, ms) {
  if (!ms || ms <= 0) return promise;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      const err = new Error('OpenAI layout selection timed out');
      err.code = 'ETIMEDOUT';
      reject(err);
    }, ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      }
    );
  });
}

function logDebug(debug, slide, candidates, aiPick, final) {
  if (!debug) return;
  const lines = [
    `Slide: ${slide?.slideNumber ?? ''}`,
    `Purpose: ${slide?.purpose || ''}`,
    '',
    'Candidates:',
    ...(Array.isArray(candidates) ? candidates.map((c) => `${c.layoutId} → ${c.score}`) : []),
    '',
    `AI selected: ${aiPick?.selectedLayoutId || '(none)'}`,
    `Confidence: ${aiPick?.confidence ?? ''}`,
    `Reason: ${String(aiPick?.reason || '').slice(0, 240)}`,
    '',
    `Final: ${final?.selectedLayoutId || ''}`,
  ];
  console.log(lines.join('\n'));
}

/**
 * Ask OpenAI to pick one of the scored candidate layout IDs.
 * Never throws; always returns a valid fallback when possible.
 */
async function selectBestLayoutWithAI(input = {}) {
  const {
    slide,
    candidates,
    presentationContext,
    theme,
    previousLayoutIds = [],
    layoutsById = {},
    slideCopy,
    layoutLocked = false,
    lockedLayoutId = null,
    phase = 'final',
    debug = false,
    chatJson = defaultChatJson,
    config: configOverrides,
  } = input;

  const config = getLayoutAiSelectionConfig(configOverrides);
  const list = Array.isArray(candidates) ? candidates.filter((c) => c && c.layoutId) : [];
  const runPhase = normalizePhase(phase);

  if (layoutLocked && lockedLayoutId) {
    const id = String(lockedLayoutId).trim();
    if (id) {
      const lockedResult = {
        selectedLayoutId: id,
        confidence: 100,
        reason: 'Layout locked by outline',
        source: 'locked',
        usedFallback: false,
      };
      logDebug(debug, slide, list, null, lockedResult);
      return lockedResult;
    }
  }

  if (!list.length) {
    return fallbackResult(list, layoutsById, 'No scored candidates; using first available layout');
  }

  if (list.length === 1) {
    const only = list[0];
    const result = {
      selectedLayoutId: only.layoutId,
      confidence: 100,
      reason: 'Only one compatible layout candidate',
      source: 'single_candidate',
      usedFallback: false,
    };
    logDebug(debug, slide, list, null, result);
    return result;
  }

  if (!config.aiEnabled || runPhase !== 'final') {
    const result = {
      selectedLayoutId: list[0].layoutId,
      confidence: Number(list[0].score) || 0,
      reason: !config.aiEnabled
        ? 'AI layout selection disabled; using deterministic winner'
        : 'Non-final phase; using deterministic winner',
      source: 'deterministic',
      usedFallback: false,
    };
    logDebug(debug, slide, list, null, result);
    return result;
  }

  const allowed = new Set(candidateIds(list));
  const cacheKey = hashKey({
    slide,
    candidateIds: list.map((c) => ({ id: c.layoutId, score: c.score })),
    context: {
      title: presentationContext?.title,
      purpose: presentationContext?.purpose,
      audience: presentationContext?.audience,
      industry: presentationContext?.industry,
      slideNumber: presentationContext?.slideNumber,
      totalSlides: presentationContext?.totalSlides,
      nextPurpose: presentationContext?.nextSlide?.purpose,
    },
    previousLayoutIds,
    slideCopy: slideCopy
      ? { title: slideCopy.title, subtitle: slideCopy.subtitle, body: slideCopy.body }
      : null,
  });

  const cached = cacheGet(cacheKey, config.cacheTtlMs);
  if (cached) {
    logDebug(debug, slide, list, cached, cached);
    return { ...cached, source: cached.source || 'ai' };
  }

  const user = buildLayoutAiUserPrompt({
    slide,
    candidates: list,
    presentationContext,
    previousLayoutIds,
    slideCopy,
    layoutsById,
    theme,
  });

  let data;
  try {
    const response = await withTimeout(
      chatJson({
        system: AI_LAYOUT_SELECTOR_SYSTEM_PROMPT,
        user,
        model: config.model,
        temperature: config.temperature,
        schemaHint: AI_LAYOUT_SELECTION_SCHEMA,
      }),
      config.timeoutMs
    );
    data = response?.data;
  } catch {
    const result = fallbackResult(
      list,
      layoutsById,
      'OpenAI layout selection failed; using deterministic winner',
      'fallback'
    );
    logDebug(debug, slide, list, null, result);
    return result;
  }

  if (!data || typeof data !== 'object') {
    const result = fallbackResult(list, layoutsById, 'Malformed OpenAI response; using deterministic winner');
    logDebug(debug, slide, list, data, result);
    return result;
  }

  const selectedLayoutId = String(data.selectedLayoutId || '').trim();
  const confidence = clampConfidence(data.confidence);
  let alternativeLayoutId = String(data.alternativeLayoutId || '').trim() || undefined;
  if (alternativeLayoutId && !allowed.has(alternativeLayoutId)) {
    alternativeLayoutId = undefined;
  }

  const aiPick = {
    selectedLayoutId,
    confidence,
    reason: String(data.reason || '').trim(),
    alternativeLayoutId,
  };

  if (!allowed.has(selectedLayoutId)) {
    const result = {
      ...fallbackResult(list, layoutsById, 'AI returned an unknown layout ID; using deterministic winner'),
      alternativeLayoutId,
    };
    logDebug(debug, slide, list, aiPick, result);
    return result;
  }

  if (confidence == null || confidence < config.aiSelectionMinConfidence) {
    const result = {
      selectedLayoutId: list[0].layoutId,
      confidence: confidence == null ? 0 : confidence,
      reason: aiPick.reason || 'AI confidence below threshold; using deterministic winner',
      alternativeLayoutId: selectedLayoutId !== list[0].layoutId ? selectedLayoutId : alternativeLayoutId,
      source: 'deterministic',
      usedFallback: true,
    };
    logDebug(debug, slide, list, aiPick, result);
    return result;
  }

  const result = {
    selectedLayoutId,
    confidence,
    reason: aiPick.reason || 'Selected by OpenAI from scored candidates',
    alternativeLayoutId,
    source: 'ai',
    usedFallback: false,
  };
  cacheSet(cacheKey, result, config.cacheTtlMs, config.cacheMaxEntries);
  logDebug(debug, slide, list, aiPick, result);
  return result;
}

module.exports = {
  selectBestLayoutWithAI,
  resetLayoutAiSelectionCache,
};
