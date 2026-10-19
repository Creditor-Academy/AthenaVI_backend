'use strict';

/**
 * Canonical layout topics and slide-search aliases.
 * Layouts inherit all aliases for their topics; slide text is matched to topic ids.
 */
const LAYOUT_TOPIC_LEXICON = {
  roadmap: [
    'roadmap',
    'road map',
    'journey',
    'phases',
    'milestones',
    'milestone',
    'rollout',
    'timeline',
    'quarters',
    'horizon',
    'roadmap slide',
  ],
  comparison: [
    'compare',
    'comparison',
    'versus',
    'vs',
    'side by side',
    'pros',
    'cons',
    'tradeoff',
    'alternative',
    'before after',
    'competitor',
  ],
  metrics: [
    'kpi',
    'kpis',
    'metrics',
    'metric',
    'traction',
    'growth',
    'revenue',
    'percent',
    'analytics',
    'dashboard',
    'statistics',
    'numbers',
  ],
  pricing: ['pricing', 'tiers', 'plans', 'plan', 'subscription', 'freemium', 'package', 'tier'],
  team: ['team', 'founders', 'leadership', 'bios', 'roles', 'members', 'people'],
  quote: ['quote', 'testimonial', 'customer said', 'review', 'statement', 'said'],
  agenda: ['agenda', 'outline', 'today', 'session', 'topics', 'schedule'],
  process: ['process', 'workflow', 'steps', 'how it works', 'pipeline', 'linear'],
  funnel: ['funnel', 'conversion', 'stages', 'tier'],
  swot: ['swot', 'strengths', 'weaknesses', 'matrix', 'quadrant'],
  table: ['table', 'grid data', 'rows', 'columns', 'cells', 'spreadsheet'],
  gallery: ['gallery', 'showcase', 'highlights', 'portfolio', 'photos', 'bento', 'mosaic'],
  closing: ['closing', 'thank you', 'contact', 'next steps', 'cta', 'goodbye'],
  hero: ['cover', 'hero', 'intro', 'opening', 'title slide', 'full bleed'],
  section: ['section', 'divider', 'break', 'chapter', 'part', 'interlude', 'segment'],
  device: ['product', 'app', 'mockup', 'screenshot', 'mobile', 'device', 'saas', 'ui'],
  bullets: ['bullets', 'bullet', 'list', 'points', 'features list'],
  diagram: ['diagram', 'architecture', 'cycle', 'flow'],
};

const NOISE_TOKENS = new Set(['v1', 'v2', 'layout', 'para', 'text', 'image', 'card', 'cards']);

function normalizeBlob(text) {
  return String(text || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ');
}

function tokenizeWords(text) {
  return normalizeBlob(text)
    .split(/\s+/)
    .map((w) => w.trim())
    .filter((w) => w.length > 2 && !NOISE_TOKENS.has(w));
}

/**
 * Detect canonical topic ids present in free text (alias substring match).
 */
function topicsFromText(blob) {
  const normalized = normalizeBlob(blob);
  if (!normalized.trim()) return [];
  const found = new Set();
  for (const [topicId, aliases] of Object.entries(LAYOUT_TOPIC_LEXICON)) {
    for (const alias of aliases) {
      const a = alias.toLowerCase().trim();
      if (a.length <= 2) continue;
      if (normalized.includes(a)) {
        found.add(topicId);
        break;
      }
    }
  }
  return [...found].sort();
}

function aliasesForTopics(topicIds) {
  const set = new Set();
  for (const id of topicIds || []) {
    const aliases = LAYOUT_TOPIC_LEXICON[id];
    if (!Array.isArray(aliases)) continue;
    for (const a of aliases) {
      const t = String(a || '').trim().toLowerCase();
      if (t) set.add(t);
    }
    if (id) set.add(String(id).toLowerCase());
  }
  return [...set].sort();
}

function expandSlideTokens(rawText) {
  const topics = topicsFromText(rawText);
  const words = tokenizeWords(rawText);
  const aliasSet = new Set([...words, ...aliasesForTopics(topics)]);
  return {
    topics,
    tokens: [...aliasSet].sort(),
  };
}

function slideTopicsFromProfile(slide = {}, searchText = '') {
  const parts = [
    slide.title,
    slide.subtitle,
    slide.body,
    slide.summary,
    slide.suggestedContentType,
    slide.purpose,
    slide.narrativeRole,
    slide.contentStructure,
    Array.isArray(slide.contentTypes) ? slide.contentTypes.join(' ') : '',
    searchText,
  ];
  const blob = parts.filter(Boolean).join(' ');
  const { topics, tokens } = expandSlideTokens(blob);
  const extra = new Set(topics);
  if (slide.hasTimeline) extra.add('roadmap');
  if (slide.hasComparison) extra.add('comparison');
  if (slide.hasChart || slide.metricCount >= 2) extra.add('metrics');
  if (slide.hasPricing) extra.add('pricing');
  if (slide.hasTeam) extra.add('team');
  if (slide.hasQuote) extra.add('quote');
  if (slide.suggestedContentType) {
    const st = String(slide.suggestedContentType).toLowerCase();
    if (st === 'comparison') extra.add('comparison');
    if (st === 'timeline') extra.add('roadmap');
    if (st === 'stat' || st === 'chart') extra.add('metrics');
    if (st === 'quote') extra.add('quote');
    if (st === 'team') extra.add('team');
    if (st === 'pricing') extra.add('pricing');
    if (st === 'grid') extra.add('gallery');
    if (st === 'closing') extra.add('closing');
    if (st === 'title') extra.add('hero');
    if (st === 'bullet_list') extra.add('bullets');
    if (st === 'diagram') extra.add('diagram');
  }
  return {
    topics: [...extra].sort(),
    tokens: [...new Set([...tokens, ...aliasesForTopics([...extra])])].sort(),
  };
}

module.exports = {
  LAYOUT_TOPIC_LEXICON,
  topicsFromText,
  aliasesForTopics,
  expandSlideTokens,
  slideTopicsFromProfile,
  tokenizeWords,
};
