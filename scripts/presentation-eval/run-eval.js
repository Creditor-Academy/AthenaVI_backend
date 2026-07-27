#!/usr/bin/env node
/**
 * Presentation module offline eval (default) + optional live stub.
 *
 * Offline (default): layout coverage, theme contrast, prompt exports, pricing exports.
 * Live: set PPT_EVAL_LIVE=1 — requires PPT_EVAL_BASE_URL + PPT_EVAL_TOKEN for HTTP;
 *       otherwise only documents/loads deckGeneration and skips real calls.
 *
 * Usage: npm run eval:presentation
 *        PPT_EVAL_LIVE=1 npm run eval:presentation
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../..');
const GOLDEN_PATH = path.join(__dirname, 'golden-prompts.json');
const SEED_LAYOUTS_PATH = path.join(
  ROOT,
  'src/modules/presentation/templates/seed-layouts.json'
);
const THEME_CATALOG_PATH = path.join(ROOT, 'src/modules/presentation/themes/catalog.json');
const MIN_LAYOUTS_PER_TYPE = 3;
const MIN_CONTRAST_RATIO = 3.0;

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

/** Relative luminance (sRGB), WCAG-style. */
function relLuminance(hex) {
  const h = String(hex || '')
    .replace('#', '')
    .trim();
  if (!/^[0-9a-fA-F]{6}$/.test(h)) return null;
  const channels = [0, 2, 4].map((i) => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(hexA, hexB) {
  const a = relLuminance(hexA);
  const b = relLuminance(hexB);
  if (a == null || b == null) return null;
  const lighter = Math.max(a, b);
  const darker = Math.min(a, b);
  return (lighter + 0.05) / (darker + 0.05);
}

function checkGoldenPrompts() {
  const prompts = loadJson(GOLDEN_PATH);
  const ok =
    Array.isArray(prompts) &&
    prompts.length >= 15 &&
    prompts.every(
      (p) =>
        p &&
        typeof p.id === 'string' &&
        typeof p.persona === 'string' &&
        typeof p.prompt === 'string' &&
        typeof p.slideCount === 'number' &&
        typeof p.density === 'string'
    );
  const personas = new Set((prompts || []).map((p) => p.persona));
  const required = ['founder', 'pm', 'educator', 'marketer'];
  const missingPersonas = required.filter((r) => !personas.has(r));
  return {
    name: 'golden_prompts',
    ok: Boolean(ok && missingPersonas.length === 0),
    detail: {
      count: Array.isArray(prompts) ? prompts.length : 0,
      personas: [...personas],
      missingPersonas,
    },
  };
}

function checkLayoutCoverage() {
  const layouts = loadJson(SEED_LAYOUTS_PATH);
  const byType = {};
  for (const layout of layouts) {
    const ct = layout.contentType || 'unknown';
    byType[ct] = (byType[ct] || 0) + 1;
  }
  const shortfalls = Object.entries(byType)
    .filter(([, n]) => n < MIN_LAYOUTS_PER_TYPE)
    .map(([contentType, count]) => ({ contentType, count }));
  const ok = shortfalls.length === 0 && Object.keys(byType).length > 0;
  return {
    name: 'seed_layout_coverage',
    ok,
    detail: {
      contentTypes: byType,
      minRequired: MIN_LAYOUTS_PER_TYPE,
      shortfalls,
      layoutCount: layouts.length,
    },
  };
}

function checkThemeContrast() {
  const themes = loadJson(THEME_CATALOG_PATH);
  const failures = [];
  for (const theme of themes) {
    const palette = theme.themeTokens?.palette || {};
    const pairs = [
      ['bg', 'text'],
      ['surface', 'text'],
      ['bg', 'muted'],
    ];
    for (const [a, b] of pairs) {
      if (!palette[a] || !palette[b]) continue;
      const ratio = contrastRatio(palette[a], palette[b]);
      if (ratio == null || ratio < MIN_CONTRAST_RATIO) {
        failures.push({
          themeId: theme.id,
          pair: `${a}/${b}`,
          ratio: ratio == null ? null : Number(ratio.toFixed(2)),
          min: MIN_CONTRAST_RATIO,
        });
      }
    }
  }
  return {
    name: 'theme_catalog_contrast',
    ok: failures.length === 0 && themes.length > 0,
    detail: {
      themeCount: themes.length,
      minContrastRatio: MIN_CONTRAST_RATIO,
      failures,
    },
  };
}

function checkPromptModules() {
  const promptsIndex = require(path.join(ROOT, 'src/modules/presentation/prompts/index.js'));
  const modules = [
    ['outlinePrompt', promptsIndex.outlinePrompt],
    ['slideContentPrompt', promptsIndex.slideContentPrompt],
    ['classifyPrompt', promptsIndex.classifyPrompt],
    ['imageBriefPrompt', promptsIndex.imageBriefPrompt],
    ['pathBPrompt', promptsIndex.pathBPrompt],
    ['visionRelevancePrompt', promptsIndex.visionRelevancePrompt],
  ];
  const missing = [];
  for (const [label, mod] of modules) {
    if (!mod || typeof mod.buildSystem !== 'function' || typeof mod.buildUser !== 'function') {
      missing.push(label);
    }
  }
  return {
    name: 'prompt_modules_export',
    ok: missing.length === 0 && typeof promptsIndex.PROMPT_BUNDLE_VERSION === 'string',
    detail: {
      promptBundleVersion: promptsIndex.PROMPT_BUNDLE_VERSION || null,
      modulesChecked: modules.map(([l]) => l),
      missingBuildFns: missing,
    },
  };
}

function checkCreditPricing() {
  const pricing = require(path.join(ROOT, 'src/shared/config/presentationCreditPricing.js'));
  const required = [
    'PPT_FEATURE',
    'estimateOutlineAc',
    'reconcileOutlineAc',
    'getFlatAc',
    'toAcCost',
  ];
  const missing = required.filter((k) => pricing[k] == null);
  let estimateOk = false;
  try {
    const est = pricing.estimateOutlineAc();
    estimateOk = est && typeof est.athenaCredits === 'number';
  } catch {
    estimateOk = false;
  }
  return {
    name: 'presentation_credit_pricing',
    ok: missing.length === 0 && estimateOk,
    detail: { exports: required, missing, estimateOk },
  };
}

/**
 * Live stub: does not call OpenAI or HTTP by default.
 * With PPT_EVAL_LIVE=1 + PPT_EVAL_BASE_URL + PPT_EVAL_TOKEN, would POST golden prompts
 * against the running API; without tokens, only require deckGeneration and skip.
 */
async function runLiveStub() {
  const live = String(process.env.PPT_EVAL_LIVE || '') === '1';
  if (!live) {
    return {
      name: 'live_eval',
      ok: true,
      skipped: true,
      detail: {
        message:
          'Offline mode (default). Set PPT_EVAL_LIVE=1 to exercise live stub. Live eval would call presentation APIs (outline/generate); requires auth tokens.',
      },
    };
  }

  let deckGenLoaded = false;
  let deckGenError = null;
  try {
    require(path.join(ROOT, 'src/modules/presentation/deckGeneration.service.js'));
    deckGenLoaded = true;
  } catch (err) {
    deckGenError = String(err.message || err);
  }

  const baseUrl = process.env.PPT_EVAL_BASE_URL && String(process.env.PPT_EVAL_BASE_URL).trim();
  const token = process.env.PPT_EVAL_TOKEN && String(process.env.PPT_EVAL_TOKEN).trim();

  if (!baseUrl || !token) {
    console.error(
      '[presentation-eval] PPT_EVAL_LIVE=1: deckGeneration',
      deckGenLoaded ? 'loaded' : `failed (${deckGenError})`,
      '— live HTTP skipped (set PPT_EVAL_BASE_URL and PPT_EVAL_TOKEN). Offline checks remain primary.'
    );
    return {
      name: 'live_eval',
      ok: deckGenLoaded,
      skipped: true,
      detail: {
        message:
          'Live eval needs PPT_EVAL_BASE_URL + PPT_EVAL_TOKEN for HTTP; OpenAI not called from this script. Would hit create/outline/generate against a running API.',
        deckGenLoaded,
        deckGenError,
        baseUrlSet: Boolean(baseUrl),
        tokenSet: Boolean(token),
      },
    };
  }

  // Keep simple: do not actually POST unless both are set — still skip network body to avoid
  // accidental billable runs without an explicit future expansion.
  console.error(
    '[presentation-eval] PPT_EVAL_LIVE=1 with base URL + token set, but HTTP calls are stubbed (offline is main).',
    'Base:',
    baseUrl
  );
  return {
    name: 'live_eval',
    ok: deckGenLoaded,
    skipped: true,
    detail: {
      message:
        'Stub only: would call APIs with Bearer token; no live OpenAI/HTTP executed in this version.',
      deckGenLoaded,
      baseUrl,
    },
  };
}

async function main() {
  const promptsIndex = require(path.join(ROOT, 'src/modules/presentation/prompts/index.js'));
  const themes = loadJson(THEME_CATALOG_PATH);
  const coverageCheck = checkLayoutCoverage();

  const checks = [
    checkGoldenPrompts(),
    coverageCheck,
    checkThemeContrast(),
    checkPromptModules(),
    checkCreditPricing(),
    await runLiveStub(),
  ];

  const report = {
    ok: checks.every((c) => c.ok),
    coverage: coverageCheck.detail.contentTypes,
    themeCount: themes.length,
    promptBundleVersion: promptsIndex.PROMPT_BUNDLE_VERSION || null,
    checks,
  };

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
}

main().catch((err) => {
  console.error(JSON.stringify({ ok: false, error: String(err.message || err) }));
  process.exitCode = 1;
});
