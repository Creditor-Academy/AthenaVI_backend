const { chatJson, DEFAULT_OUTLINE_MODEL } = require('../../shared/services/ai');
const logger = require('../../shared/utils/logger');
const { buildSystem, buildUser, PLAN_SCHEMA } = require('./prompts/infographicPlan.prompt');

const REGION_TYPES = new Set(['header', 'flowRow', 'sidebar', 'footer', 'note']);

function pad2(n) {
  const num = Number(n);
  if (!Number.isFinite(num) || num < 0) return '01';
  return String(Math.floor(num)).padStart(2, '0');
}

function asString(value) {
  if (value == null) return '';
  return String(value).trim();
}

function normalizeStep(step, fallbackNumber) {
  const raw = step && typeof step === 'object' ? step : {};
  return {
    number: pad2(raw.number || fallbackNumber),
    heading: asString(raw.heading || raw.title),
    body: asString(raw.body || raw.content),
    icon: asString(raw.icon),
  };
}

function normalizeRegion(region) {
  const raw = region && typeof region === 'object' ? region : {};
  const type = REGION_TYPES.has(raw.type) ? raw.type : 'flowRow';
  const steps = Array.isArray(raw.steps) ? raw.steps.map((s, i) => normalizeStep(s, i + 1)) : [];
  return {
    type,
    title: asString(raw.title),
    steps,
  };
}

function flowSteps(plan) {
  const regions = Array.isArray(plan.regions) ? plan.regions : [];
  const steps = [];
  for (const region of regions) {
    if (region.type === 'sidebar' || region.type === 'footer' || region.type === 'note' || region.type === 'header') {
      continue;
    }
    for (const step of region.steps || []) {
      steps.push(step);
    }
  }
  return steps;
}

function allSteps(plan) {
  const regions = Array.isArray(plan.regions) ? plan.regions : [];
  return regions.flatMap((region) => region.steps || []);
}

function collectExactText(plan, infographic = {}) {
  const texts = [];
  const push = (value) => {
    const s = asString(value);
    if (s) texts.push(s);
  };
  push(plan.title);
  push(plan.subtitle);
  for (const region of plan.regions || []) {
    push(region.title);
    for (const step of region.steps || []) {
      push(step.heading);
      push(step.body);
      if (step.number) push(String(step.number).padStart(2, '0'));
    }
  }
  for (const section of infographic.sections || []) {
    push(section.title);
    push(section.content);
    for (const bullet of section.bullets || []) push(bullet);
  }
  if (Array.isArray(plan.exactText)) {
    for (const item of plan.exactText) push(item);
  }
  if (Array.isArray(plan.metrics)) {
    for (const metric of plan.metrics) push(String(metric));
  }
  const seen = new Set();
  const unique = [];
  for (const t of texts) {
    const key = t.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(t);
  }
  return unique;
}

function ensureClientSections(plan, infographic = {}) {
  const sections = Array.isArray(infographic.sections) ? infographic.sections : [];
  if (!sections.length) return plan;

  const headings = new Set(
    allSteps(plan)
      .map((s) => s.heading.toLowerCase())
      .filter(Boolean)
  );

  const missing = [];
  for (const section of sections) {
    const title = asString(section.title);
    if (!title) continue;
    if (!headings.has(title.toLowerCase())) {
      missing.push({
        number: '01',
        heading: title,
        body: Array.isArray(section.bullets)
          ? section.bullets.filter(Boolean).join('. ')
          : asString(section.content),
        icon: '',
      });
    }
  }
  if (!missing.length) return plan;

  const regions = [...(plan.regions || [])];
  let flow = regions.find((r) => r.type === 'flowRow');
  if (!flow) {
    flow = { type: 'flowRow', title: '', steps: [] };
    regions.push(flow);
  }
  flow.steps = [...(flow.steps || []), ...missing];
  return { ...plan, regions };
}

function renumberFlowSteps(plan) {
  let n = 1;
  const regions = (plan.regions || []).map((region) => {
    if (region.type !== 'flowRow') return region;
    return {
      ...region,
      steps: (region.steps || []).map((step) => ({
        ...step,
        number: pad2(n++),
      })),
    };
  });
  return { ...plan, regions, expectedStepCount: n - 1 };
}

function normalizeMetrics(plan, layout) {
  if (!Array.isArray(plan.metrics) || !plan.metrics.length) return plan;
  const nums = plan.metrics
    .map((m) => {
      if (typeof m === 'number' && Number.isFinite(m)) return m;
      const parsed = Number(String(m).replace(/[^0-9.-]/g, ''));
      return Number.isFinite(parsed) ? parsed : null;
    })
    .filter((n) => n != null);
  if (layout === 'funnel' && nums.length >= 2) {
    let decreasing = true;
    for (let i = 1; i < nums.length; i += 1) {
      if (nums[i] > nums[i - 1]) decreasing = false;
    }
    if (!decreasing) {
      nums.sort((a, b) => b - a);
    }
  }
  return { ...plan, metrics: nums };
}

function fourDigitYears(plan, userPrompt = '') {
  const promptYears = String(userPrompt).match(/\b(?:1[89]\d{2}|20\d{2})\b/g) || [];
  const exactText = (plan.exactText || []).map((item) => {
    const s = String(item);
    if (/^\d{1,3}$/.test(s) && promptYears.length) {
      const match = promptYears.find((y) => y.endsWith(s) || y.includes(s));
      return match || s;
    }
    return s;
  });
  return { ...plan, exactText };
}

/**
 * Repair numbering, completeness, funnel metrics, and exactText.
 */
function validateInfographicSpec(rawPlan, { infographic = {}, prompt = '' } = {}) {
  const layout = asString(rawPlan.layout) || infographic.layout || 'custom';
  let plan = {
    title: asString(rawPlan.title) || asString(infographic.title),
    subtitle: asString(rawPlan.subtitle),
    layout,
    regions: Array.isArray(rawPlan.regions) ? rawPlan.regions.map(normalizeRegion) : [],
    exactText: Array.isArray(rawPlan.exactText) ? rawPlan.exactText : [],
    expectedStepCount: Number(rawPlan.expectedStepCount) || 0,
    metrics: Array.isArray(rawPlan.metrics) ? rawPlan.metrics : [],
    palette: Array.isArray(rawPlan.palette) ? rawPlan.palette.map(asString).filter(Boolean) : [],
    characterNotes: asString(rawPlan.characterNotes),
  };

  if (!plan.regions.length && Array.isArray(infographic.sections) && infographic.sections.length) {
    plan.regions = [
      {
        type: 'header',
        title: plan.title,
        steps: [],
      },
      {
        type: 'flowRow',
        title: '',
        steps: infographic.sections.map((section, i) =>
          normalizeStep(
            {
              heading: section.title,
              body: Array.isArray(section.bullets)
                ? section.bullets.join('. ')
                : section.content,
            },
            i + 1
          )
        ),
      },
    ];
  }

  plan = ensureClientSections(plan, infographic);
  plan = renumberFlowSteps(plan);
  plan = normalizeMetrics(plan, layout);
  plan.exactText = collectExactText(plan, infographic);
  plan = fourDigitYears(plan, prompt);
  plan.expectedStepCount = flowSteps(plan).length;
  return plan;
}

function fallbackPlan({ prompt, infographic = {}, brandPalette } = {}) {
  return validateInfographicSpec(
    {
      title: infographic.title || '',
      subtitle: '',
      layout: infographic.layout || 'custom',
      regions: [],
      exactText: [],
      metrics: [],
      palette: Array.isArray(brandPalette) ? brandPalette : [],
      characterNotes: '',
    },
    { infographic, prompt }
  );
}

async function planInfographic({
  prompt = '',
  infographic = {},
  brandPalette,
  contextExcerpt = '',
} = {}) {
  const plannerModel = process.env.IMAGE_GEN_PLANNER_MODEL || DEFAULT_OUTLINE_MODEL;
  try {
    const result = await chatJson({
      system: buildSystem(),
      user: buildUser({ prompt, infographic, brandPalette, contextExcerpt }),
      model: plannerModel,
      schemaHint: PLAN_SCHEMA,
      temperature: 0.2,
    });
    return validateInfographicSpec(result.data || {}, { infographic, prompt });
  } catch (err) {
    logger.warn('Infographic planner failed; using section fallback', {
      message: err?.message,
    });
    return fallbackPlan({ prompt, infographic, brandPalette });
  }
}

module.exports = {
  planInfographic,
  validateInfographicSpec,
  fallbackPlan,
  flowSteps,
};
