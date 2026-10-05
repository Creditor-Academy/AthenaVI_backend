/**
 * Reusable narrative slide roles and reference story arcs by deck length.
 * Roles map to content contracts; blueprints are examples for the outline LLM—not hardcoded slide order.
 */

const { promptLooksQuantitative, promptLooksProductUi } = require('./layoutCatalogPolicy');
const { countProcessSteps } = require('./diagramPathPolicy.util');

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
    'problem_statement',
    'key_insight',
    'solution_overview',
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
  15: BLUEPRINT_20.slice(0, 15),
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
  if (n > 15) return BLUEPRINT_20.slice(0, n);
  if (n > 12) return BLUEPRINT_20.slice(0, Math.min(n, 15));
  if (n > 10) return BLUEPRINT_BY_COUNT[12].slice(0, n);
  if (n > 8) return BLUEPRINT_BY_COUNT[10].slice(0, n);
  if (n > 5) return BLUEPRINT_BY_COUNT[8].slice(0, n);
  return BLUEPRINT_BY_COUNT[5].slice(0, Math.max(1, n));
}

/**
 * Format blueprint as prompt lines for outline LLM.
 */
function formatBlueprintExampleForPrompt(slideCount) {
  const roles = blueprintForSlideCount(slideCount);
  return roles
    .map((role, i) => `${i + 1}. ${ROLE_LABELS[role] || role} (narrativeRole: ${role})`)
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
function applyRoleDefaultsToSlides(slides, { sourceText = '', slideCount = null } = {}) {
  const list = Array.isArray(slides) ? slides : [];
  const blueprint = blueprintForSlideCount(slideCount || list.length);

  return list.map((slide, idx) => {
    const order = Number(slide.order) > 0 ? Number(slide.order) : idx + 1;
    const role =
      normalizeRole(slide.narrativeRole || slide.narrative_role) ||
      blueprint[order - 1] ||
      null;
    const defaults = role ? roleToContentDefaults(role, { slide, sourceText }) : null;
    let suggested = String(slide.suggestedContentType || slide.content_type || '').toLowerCase();
    if (!suggested && defaults) suggested = defaults.suggestedContentType;
    if (order === 1) suggested = 'title';
    const total = slideCount || list.length;
    if (order === total && !slide.layoutLocked) suggested = 'closing';

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

module.exports = {
  NARRATIVE_ROLES,
  BLUEPRINT_BY_COUNT,
  BLUEPRINT_20,
  ROLE_LABELS,
  normalizeRole,
  blueprintForSlideCount,
  formatBlueprintExampleForPrompt,
  roleToContentDefaults,
  alternateContentTypeForAdjacency,
  applyRoleDefaultsToSlides,
  ADJACENCY_FALLBACK_TYPES,
};
