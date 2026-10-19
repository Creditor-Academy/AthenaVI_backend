/**
 * Reusable narrative slide roles and reference story arcs by deck length.
 * Roles map to content contracts; blueprints are examples for the outline LLM—not hardcoded slide order.
 */

const { PPT_NARRATIVE_SLIDE_COUNTS } = require('./presentation.constants');
const { promptLooksQuantitative, promptLooksProductUi } = require('./layoutCatalogPolicy');
const { countProcessSteps } = require('./diagramPathPolicy.util');

const BOOKEND_ROLES = Object.freeze(['hero_title', 'agenda_overview', 'summary_cta']);

const INTRO_ROLE_POOL = Object.freeze([
  'introduction',
  'context_background',
  'problem_statement',
  'market_overview',
  'pain_points',
]);

const SYNTHESIS_ROLE_POOL = Object.freeze([
  'key_takeaways',
  'results_impact',
  'solution_overview',
  'strategy_framework',
  'key_insight',
]);

const NARRATIVE_ROLES = Object.freeze([
  'hero_title',
  'agenda_overview',
  'introduction',
  'context_background',
  'problem_statement',
  'market_overview',
  'research_data',
  'key_insight',
  'key_data',
  'audience_profile',
  'pain_points',
  'solution_overview',
  'strategy_framework',
  'process_workflow',
  'feature_breakdown',
  'comparison_options',
  'implementation_roadmap',
  'results_impact',
  'case_study',
  'key_takeaways',
  'summary_cta',
]);

const BLUEPRINT_20 = [
  'hero_title',
  'agenda_overview',
  'introduction',
  'context_background',
  'problem_statement',
  'market_overview',
  'research_data',
  'key_insight',
  'audience_profile',
  'pain_points',
  'solution_overview',
  'strategy_framework',
  'process_workflow',
  'feature_breakdown',
  'comparison_options',
  'implementation_roadmap',
  'results_impact',
  'case_study',
  'key_takeaways',
  'summary_cta',
];

const BLUEPRINT_BY_COUNT = Object.freeze({
  5: [
    'hero_title',
    'agenda_overview',
    'introduction',
    'key_insight',
    'summary_cta',
  ],
  8: [
    'hero_title',
    'agenda_overview',
    'problem_statement',
    'key_data',
    'solution_overview',
    'process_workflow',
    'results_impact',
    'summary_cta',
  ],
  10: [
    'hero_title',
    'agenda_overview',
    'problem_statement',
    'context_background',
    'key_data',
    'strategy_framework',
    'process_workflow',
    'comparison_options',
    'key_takeaways',
    'summary_cta',
  ],
  12: [
    'hero_title',
    'agenda_overview',
    'context_background',
    'problem_statement',
    'research_data',
    'key_insight',
    'strategy_framework',
    'process_workflow',
    'comparison_options',
    'results_impact',
    'key_takeaways',
    'summary_cta',
  ],
  20: BLUEPRINT_20,
});

const ROLE_LABELS = {
  hero_title: 'Hero / Title',
  agenda_overview: 'Agenda / Overview',
  introduction: 'Introduction',
  context_background: 'Context / Background',
  problem_statement: 'Problem / Context',
  market_overview: 'Market / Industry Overview',
  research_data: 'Research / Data',
  key_insight: 'Key Insight / Insights',
  key_data: 'Key Data / Statistics',
  audience_profile: 'User / Audience Profile',
  pain_points: 'Challenges / Pain Points',
  solution_overview: 'Solution / Main Content',
  strategy_framework: 'Solution / Strategy / Framework',
  process_workflow: 'Process / Workflow',
  feature_breakdown: 'Feature / Component Breakdown',
  comparison_options: 'Comparison / Alternatives',
  implementation_roadmap: 'Implementation / Roadmap',
  results_impact: 'Results / Impact / Metrics',
  case_study: 'Case Study / Example',
  key_takeaways: 'Key Takeaways',
  summary_cta: 'Summary / Conclusion / CTA',
};

/** Alternate content types when fixing adjacent duplicates (process_workflow). */
const PROCESS_ALTERNATES = ['timeline', 'bullet_list', 'image+text'];

/** General fallbacks when adjacent type must change (middle slides). */
const ADJACENCY_FALLBACK_TYPES = [
  'image+text',
  'grid',
  'bullet_list',
  'stat',
  'comparison',
  'section_divider',
  'quote',
  'timeline',
  'diagram',
  'chart',
  'agenda',
];

function normalizeRole(role) {
  const r = String(role || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_');
  return NARRATIVE_ROLES.includes(r) ? r : null;
}

function blueprintForSlideCount(slideCount) {
  const n = Number(slideCount) || 0;
  if (BLUEPRINT_BY_COUNT[n]) return BLUEPRINT_BY_COUNT[n].slice();
  if (n > 20) return BLUEPRINT_20.slice();
  if (n > 12) return BLUEPRINT_20.slice(0, Math.min(n, 20));
  if (n > 10) return BLUEPRINT_BY_COUNT[12].slice(0, n);
  if (n > 8) return BLUEPRINT_BY_COUNT[10].slice(0, n);
  if (n > 5) return BLUEPRINT_BY_COUNT[8].slice(0, n);
  return BLUEPRINT_BY_COUNT[5].slice(0, Math.max(1, n));
}

function isBookendRole(role) {
  const r = normalizeRole(role);
  return r != null && BOOKEND_ROLES.includes(r);
}

function isIntroBandOrder(order, slideCount) {
  const n = Number(slideCount) || 0;
  const o = Number(order) || 0;
  return n >= 4 && (o === 3 || o === 4);
}

function isMiddleOrder(order, slideCount) {
  const n = Number(slideCount) || 0;
  const o = Number(order) || 0;
  if (o <= 2 || o >= n) return false;
  if (n >= 6 && o === n - 1) return false;
  return true;
}

function defaultIntroRoleForOrder(order) {
  const idx = Math.max(0, Number(order) - 3);
  return INTRO_ROLE_POOL[idx % INTRO_ROLE_POOL.length];
}

function defaultSynthesisRole(slide = {}) {
  const existing = normalizeRole(slide.narrativeRole || slide.narrative_role);
  if (existing && SYNTHESIS_ROLE_POOL.includes(existing)) return existing;
  return 'key_takeaways';
}

function contentSlideOrdersForAgenda(slideCount) {
  const n = Number(slideCount) || 0;
  if (n <= 2) return [];
  if (n === 5) return [3, 4];
  if (n >= 6) {
    const last = n - 2;
    const orders = [];
    for (let o = 3; o <= last; o += 1) orders.push(o);
    return orders;
  }
  return [3];
}

/**
 * Slide 2 agenda beats mirror planned content slide titles (not a rigid middle template).
 */
function syncAgendaFromOutline(slides, slideCount) {
  const list = Array.isArray(slides) ? slides : [];
  const n = Number(slideCount) || list.length;
  if (!list.length || n < 2) return list;

  const byOrder = new Map(
    list.map((s, idx) => [Number(s.order) > 0 ? Number(s.order) : idx + 1, s])
  );
  const contentOrders = contentSlideOrdersForAgenda(n);
  const beats = contentOrders
    .map((o) => {
      const slide = byOrder.get(o);
      const title = String(slide?.title || '').trim();
      return title || null;
    })
    .filter(Boolean);

  return list.map((slide, idx) => {
    const order = Number(slide.order) > 0 ? Number(slide.order) : idx + 1;
    if (order !== 2) return slide;
    const prevBeats = Array.isArray(slide.beats) ? slide.beats.filter(Boolean) : [];
    const nextBeats = beats.length ? beats : prevBeats;
    return {
      ...slide,
      beats: nextBeats,
      narrativeRole: normalizeRole(slide.narrativeRole) || 'agenda_overview',
      suggestedContentType: slide.suggestedContentType || 'agenda',
    };
  });
}

/**
 * Protected bookends + soft intro band; middle narrative roles stay LLM-chosen when valid.
 */
function applyProtectedBookends(slides, slideCount, { sourceText = '', skipBookends = false } = {}) {
  const list = Array.isArray(slides) ? slides : [];
  const n = Number(slideCount) || list.length;
  if (!list.length || skipBookends) {
    return list.map((slide, idx) => ({
      ...slide,
      order: Number(slide.order) > 0 ? Number(slide.order) : idx + 1,
    }));
  }

  return list.map((slide, idx) => {
    const order = Number(slide.order) > 0 ? Number(slide.order) : idx + 1;
    let role = normalizeRole(slide.narrativeRole || slide.narrative_role);
    let suggested = String(slide.suggestedContentType || slide.content_type || '').toLowerCase();

    if (order === 1) {
      role = 'hero_title';
      if (!slide.layoutLocked) suggested = 'title';
    } else if (order === 2) {
      role = 'agenda_overview';
      if (!slide.layoutLocked) suggested = 'agenda';
    } else if (n >= 6 && order === n - 1) {
      role = defaultSynthesisRole({ ...slide, narrativeRole: role });
      if (!slide.layoutLocked && ['chart', 'diagram', 'timeline'].includes(suggested)) {
        suggested = roleToContentDefaults(role, { slide, sourceText }).suggestedContentType;
      }
    } else if (order === n) {
      role = 'summary_cta';
      if (!slide.layoutLocked) suggested = 'closing';
    } else if (isIntroBandOrder(order, n)) {
      if (!role || isBookendRole(role)) {
        role = defaultIntroRoleForOrder(order);
      }
    } else if (isMiddleOrder(order, n)) {
      if (isBookendRole(role)) role = null;
      if (role && !NARRATIVE_ROLES.includes(role)) role = null;
    }

    const defaults = role ? roleToContentDefaults(role, { slide, sourceText }) : null;
    if (!suggested && defaults) suggested = defaults.suggestedContentType;
    if (order === 1) suggested = 'title';
    if (order === 2 && !slide.layoutLocked) suggested = 'agenda';
    if (order === n && !slide.layoutLocked) suggested = 'closing';

    return {
      ...slide,
      order,
      narrativeRole: role || slide.narrativeRole || undefined,
      suggestedContentType: suggested || slide.suggestedContentType || 'image+text',
      purpose: slide.purpose || defaults?.purpose || slide.purpose,
      visual_need:
        slide.visual_need ||
        slide.visualNeed ||
        defaults?.visual_need ||
        undefined,
    };
  });
}

/**
 * Format structural narrative guidance for the outline LLM (not a mandatory per-index role list).
 */
function formatBlueprintExampleForPrompt(slideCount) {
  const n = Number(slideCount) || 10;
  const example = blueprintForSlideCount(Math.min(n, 10));
  const exampleLines = example
    .slice(0, Math.min(example.length, 6))
    .map((role, i) => `  ${i + 1}. ${ROLE_LABELS[role] || role} (narrativeRole: ${role})`)
    .join('\n');

  const synthesisLine =
    n >= 6
      ? `- Slide ${n - 1}: synthesis / key takeaways (narrativeRole from: ${SYNTHESIS_ROLE_POOL.slice(0, 4).join(', ')}) — prefer bullet_list, stat, quote, image+text; not chart/diagram as default`
      : '- No separate synthesis slide (deck too short)';

  return [
    `Structure for ${n} slides:`,
    '- Slide 1: title/cover (narrativeRole: hero_title, suggestedContentType: title)',
    '- Slide 2: agenda/overview (narrativeRole: agenda_overview, suggestedContentType: agenda) — beats[] should list the titles of your main content slides',
    n >= 4
      ? '- Slides 3–4: intro band — pick roles from introduction/context/problem framing (topic-dependent; not duplicate bookends)'
      : null,
    `- Slides between intro and closing: YOU choose narrativeRole and content mix (charts/diagrams/comparisons allowed when the source warrants)`,
    synthesisLine,
    `- Slide ${n}: conclusion / CTA (narrativeRole: summary_cta, suggestedContentType: closing)`,
    '',
    'Example opening arc (adapt topics to source — middle slides are NOT fixed to this list):',
    exampleLines,
    example.length > 6 ? '  … flexible middle …' : null,
  ]
    .filter(Boolean)
    .join('\n');
}

function beatCount(slide = {}) {
  return Array.isArray(slide.beats) ? slide.beats.filter(Boolean).length : 0;
}

/**
 * Default suggestedContentType + purpose for a narrative role.
 */
function roleToContentDefaults(role, { slide = {}, sourceText = '', promptQuant = null } = {}) {
  const r = normalizeRole(role);
  const quant =
    promptQuant != null ? Boolean(promptQuant) : promptLooksQuantitative(sourceText);
  const productUi = promptLooksProductUi(sourceText);
  const steps = beatCount(slide) || countProcessSteps({
    beats: slide.beats,
    bullets: slide.bullets,
    columns: slide.columns,
  });

  const base = { suggestedContentType: 'image+text', purpose: null, visual_need: null };

  if (!r) return base;

  switch (r) {
    case 'hero_title':
      return { suggestedContentType: 'title', purpose: 'cover', visual_need: 'photo' };
    case 'agenda_overview':
      return { suggestedContentType: 'agenda', purpose: null, visual_need: 'photo' };
    case 'summary_cta':
      return { suggestedContentType: 'closing', purpose: 'closing', visual_need: 'photo' };
    case 'introduction':
    case 'context_background':
    case 'solution_overview':
    case 'case_study':
      return { suggestedContentType: 'image+text', purpose: slide.purpose || null, visual_need: 'photo' };
    case 'problem_statement':
    case 'pain_points':
      return {
        suggestedContentType: 'bullet_list',
        purpose: 'problem',
        visual_need: 'photo',
      };
    case 'market_overview':
    case 'audience_profile':
    case 'strategy_framework':
    case 'feature_breakdown':
      return { suggestedContentType: 'grid', purpose: null, visual_need: 'photo' };
    case 'research_data':
      return {
        suggestedContentType: quant ? 'chart' : 'stat',
        purpose: null,
        visual_need: quant ? 'chart' : 'photo',
      };
    case 'key_insight':
      return { suggestedContentType: 'stat', purpose: null, visual_need: 'illustration' };
    case 'key_data':
    case 'results_impact':
      return {
        suggestedContentType: quant ? 'chart' : 'stat',
        purpose: null,
        visual_need: quant ? 'chart' : 'photo',
      };
    case 'process_workflow':
      if (steps >= 5) {
        return { suggestedContentType: 'timeline', purpose: null, visual_need: 'diagram_template' };
      }
      if (steps >= 2) {
        return { suggestedContentType: 'diagram', purpose: null, visual_need: 'diagram_template' };
      }
      return { suggestedContentType: 'bullet_list', purpose: null, visual_need: 'photo' };
    case 'comparison_options':
      return { suggestedContentType: 'comparison', purpose: null, visual_need: 'photo' };
    case 'implementation_roadmap':
      return { suggestedContentType: 'timeline', purpose: null, visual_need: 'photo' };
    case 'key_takeaways':
      return { suggestedContentType: 'bullet_list', purpose: null, visual_need: 'none' };
    default:
      if (productUi && r === 'feature_breakdown') {
        return { suggestedContentType: 'device_frames', purpose: null, visual_need: 'photo' };
      }
      return base;
  }
}

/**
 * Pick alternate content type when adjacent to same type as previous slide.
 */
function alternateContentTypeForAdjacency({
  previousType,
  slide = {},
  narrativeRole = null,
} = {}) {
  const prev = String(previousType || '').toLowerCase();
  const role = normalizeRole(narrativeRole || slide.narrativeRole);

  if (role === 'process_workflow') {
    for (const alt of PROCESS_ALTERNATES) {
      if (alt !== prev) return alt;
    }
  }

  if (role) {
    const primary = roleToContentDefaults(role, { slide }).suggestedContentType;
    if (primary && primary !== prev) return primary;
    const alts = roleToContentDefaults(role, { slide });
    if (alts.suggestedContentType !== prev) return alts.suggestedContentType;
  }

  for (const t of ADJACENCY_FALLBACK_TYPES) {
    if (t !== prev) return t;
  }
  return prev === 'image+text' ? 'grid' : 'image+text';
}

/**
 * Apply role defaults to slides missing suggestedContentType or narrativeRole hints.
 */
function applyRoleDefaultsToSlides(
  slides,
  { sourceText = '', slideCount = null, skipBookends = false } = {}
) {
  const total = slideCount || (Array.isArray(slides) ? slides.length : 0);
  let list = applyProtectedBookends(slides, total, { sourceText, skipBookends });
  list = syncAgendaFromOutline(list, total);
  return list;
}

module.exports = {
  NARRATIVE_ROLES,
  PPT_NARRATIVE_SLIDE_COUNTS,
  BOOKEND_ROLES,
  INTRO_ROLE_POOL,
  SYNTHESIS_ROLE_POOL,
  BLUEPRINT_BY_COUNT,
  BLUEPRINT_20,
  ROLE_LABELS,
  normalizeRole,
  blueprintForSlideCount,
  formatBlueprintExampleForPrompt,
  roleToContentDefaults,
  alternateContentTypeForAdjacency,
  applyRoleDefaultsToSlides,
  applyProtectedBookends,
  syncAgendaFromOutline,
  contentSlideOrdersForAgenda,
  isBookendRole,
  isIntroBandOrder,
  isMiddleOrder,
  ADJACENCY_FALLBACK_TYPES,
};
