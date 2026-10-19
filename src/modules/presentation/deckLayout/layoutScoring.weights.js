const DEFAULT_LAYOUT_SCORING_WEIGHTS = {
  purposeMatch: 25,
  contentTypeMatch: 25,
  capacityMatch: 15,
  compositionMatch: 10,
  styleMatch: 10,
  industryMatch: 5,
};

/** Bidirectional related slide purposes. */
const RELATED_PURPOSES = {
  cover: ['introduction'],
  introduction: ['cover'],
  problem: ['solution'],
  solution: ['problem'],
  features: ['benefits', 'product'],
  benefits: ['features', 'product'],
  product: ['features', 'benefits'],
  statistics: ['traction'],
  traction: ['statistics'],
  process: ['roadmap'],
  roadmap: ['process'],
  competition: ['market'],
  market: ['competition'],
  pricing: ['business-model'],
  'business-model': ['pricing'],
};

const PURPOSE_CATEGORY_WEAK = {
  cover: ['hero', 'title'],
  introduction: ['hero', 'title', 'section', 'content'],
  conclusion: ['closing'],
  team: ['team'],
  pricing: ['pricing'],
  statistics: ['data', 'chart'],
  traction: ['data', 'chart'],
  process: ['process', 'timeline'],
  roadmap: ['process', 'timeline'],
  competition: ['comparison'],
  product: ['product', 'image'],
  features: ['content', 'image'],
  benefits: ['content', 'quote'],
  market: ['data', 'comparison'],
  'business-model': ['pricing', 'content'],
  problem: ['content'],
  solution: ['content', 'image'],
};

const RELATED_INDUSTRY_GROUPS = [
  ['technology', 'startup'],
  ['business', 'consulting', 'finance'],
  ['media', 'education'],
  ['healthcare', 'education'],
  ['retail', 'business'],
];

const CONTENT_TYPE_TO_SUPPORTED = {
  title: 'title',
  subtitle: 'subtitle',
  paragraph: 'body',
  bullets: 'bullets',
  image: 'image',
  icon: 'icons',
  statistic: 'metrics',
  metrics: 'metrics',
  cards: 'cards',
  chart: 'chart',
  table: 'table',
  quote: 'quote',
};

const REPETITION_PENALTIES = {
  1: -5,
  2: -12,
  3: -20,
};

/** Strong penalty when the candidate matches the immediately previous slide's layout. */
const ADJACENT_LAYOUT_PENALTY = -35;

module.exports = {
  DEFAULT_LAYOUT_SCORING_WEIGHTS,
  RELATED_PURPOSES,
  PURPOSE_CATEGORY_WEAK,
  RELATED_INDUSTRY_GROUPS,
  CONTENT_TYPE_TO_SUPPORTED,
  REPETITION_PENALTIES,
  ADJACENT_LAYOUT_PENALTY,
};
