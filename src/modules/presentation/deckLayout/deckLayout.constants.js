const { ELEMENT_TYPES } = require('../presentation.constants');

const DECK_LAYOUT_CATEGORIES = [
  'hero',
  'title',
  'section',
  'content',
  'image',
  'data',
  'comparison',
  'process',
  'timeline',
  'quote',
  'team',
  'product',
  'pricing',
  'closing',
  'chart',
  'table',
];

const DECK_LAYOUT_SLIDE_PURPOSES = [
  'cover',
  'introduction',
  'problem',
  'solution',
  'market',
  'product',
  'features',
  'benefits',
  'statistics',
  'traction',
  'business-model',
  'competition',
  'process',
  'roadmap',
  'team',
  'pricing',
  'conclusion',
];

const DECK_LAYOUT_CONTENT_CAPABILITIES = [
  'title',
  'subtitle',
  'paragraph',
  'bullets',
  'image',
  'icon',
  'statistic',
  'metrics',
  'cards',
  'chart',
  'table',
  'timeline',
  'quote',
  'comparison',
];

const DECK_LAYOUT_DENSITIES = ['low', 'medium', 'high'];

const DECK_LAYOUT_STRUCTURES = [
  'centered',
  'split',
  'two-column',
  'three-column',
  'grid',
  'full-image',
  'text-heavy',
  'image-heavy',
  'card-grid',
];

const DECK_LAYOUT_VISUAL_WEIGHTS = ['text-heavy', 'image-heavy', 'balanced', 'data-heavy'];

const DECK_LAYOUT_IMAGE_POSITIONS = ['none', 'left', 'right', 'top', 'bottom', 'center', 'full'];

const DECK_LAYOUT_TEXT_POSITIONS = ['left', 'right', 'top', 'bottom', 'center'];

const DECK_LAYOUT_ALIGNMENTS = ['left', 'center', 'right'];

const DECK_LAYOUT_DESIGN_STYLES = [
  'minimal',
  'modern',
  'editorial',
  'corporate',
  'luxury',
  'playful',
  'bold',
  'clean',
  'premium',
];

const DECK_LAYOUT_MOODS = [
  'professional',
  'premium',
  'energetic',
  'calm',
  'futuristic',
  'trustworthy',
  'creative',
  'confident',
];

const DECK_LAYOUT_INDUSTRIES = [
  'technology',
  'business',
  'startup',
  'finance',
  'healthcare',
  'education',
  'retail',
  'media',
  'consulting',
  'general',
];

const SUPPORTED_ELEMENT_KEYS = [
  'title',
  'subtitle',
  'body',
  'bullets',
  'image',
  'icons',
  'metrics',
  'chart',
  'table',
  'cards',
  'quote',
];

const DECK_LAYOUT_SLOT_ROLES = [
  'heading',
  'subheading',
  'body',
  'caption',
  'stat',
  'stat_label',
  'decoration',
  'background',
  'image',
  'chart',
  'table',
  'quote',
  'attribution',
  'cta',
  'contact',
  'eyebrow',
  'divider',
];

const CANVAS_ELEMENT_TYPES = ELEMENT_TYPES;

module.exports = {
  DECK_LAYOUT_CATEGORIES,
  DECK_LAYOUT_SLIDE_PURPOSES,
  DECK_LAYOUT_CONTENT_CAPABILITIES,
  DECK_LAYOUT_DENSITIES,
  DECK_LAYOUT_STRUCTURES,
  DECK_LAYOUT_VISUAL_WEIGHTS,
  DECK_LAYOUT_IMAGE_POSITIONS,
  DECK_LAYOUT_TEXT_POSITIONS,
  DECK_LAYOUT_ALIGNMENTS,
  DECK_LAYOUT_DESIGN_STYLES,
  DECK_LAYOUT_MOODS,
  DECK_LAYOUT_INDUSTRIES,
  SUPPORTED_ELEMENT_KEYS,
  DECK_LAYOUT_SLOT_ROLES,
  CANVAS_ELEMENT_TYPES,
};
