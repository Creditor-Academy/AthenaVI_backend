/**
 * FE layout gallery categories (picker tabs).
 * `contentTypes` maps to DECK_LAYOUT.contentType / schema.content_type (AI tags).
 * `all` has empty contentTypes → no filter.
 */
const LAYOUT_CATEGORIES = [
  {
    id: 'all',
    label: 'All',
    contentTypes: [],
  },
  {
    id: 'simple_slides',
    label: 'Simple slides',
    contentTypes: ['title', 'bullet_list', 'section_divider', 'image+text', 'comparison'],
  },
  {
    id: 'grid',
    label: 'Grid',
    contentTypes: ['grid'],
  },
  {
    id: 'charts_and_data',
    label: 'Charts and data',
    contentTypes: ['chart', 'stat'],
  },
  {
    id: 'timeline_and_plans',
    label: 'Timeline and project plans',
    contentTypes: ['timeline'],
  },
  {
    id: 'pricing',
    label: 'Pricing',
    contentTypes: ['pricing'],
  },
  {
    id: 'agenda',
    label: 'Agenda',
    contentTypes: ['agenda'],
  },
  {
    id: 'people_and_team',
    label: 'People and team',
    contentTypes: ['team'],
  },
  {
    id: 'quotes_and_testimonials',
    label: 'Quotes and testimonial',
    contentTypes: ['quote'],
  },
  {
    id: 'device_frames',
    label: 'Device frames',
    contentTypes: ['device_frames'],
  },
  {
    id: 'diagrams',
    label: 'Diagrams',
    contentTypes: ['diagram'],
  },
  {
    id: 'closing',
    label: 'Closing',
    contentTypes: ['closing'],
  },
];

const LAYOUT_CONTENT_TYPES = [
  'title',
  'agenda',
  'bullet_list',
  'comparison',
  'stat',
  'quote',
  'image+text',
  'timeline',
  'team',
  'chart',
  'closing',
  'section_divider',
  'grid',
  'pricing',
  'device_frames',
  'diagram',
];

function listLayoutCategories() {
  return LAYOUT_CATEGORIES.map((c) => ({ ...c }));
}

function resolveCategoryContentTypes(categoryId) {
  if (categoryId == null || categoryId === '') return null;
  const id = String(categoryId).trim().toLowerCase();
  const cat = LAYOUT_CATEGORIES.find((c) => c.id === id);
  if (!cat) return undefined; // unknown
  if (!cat.contentTypes.length) return null; // all
  return [...cat.contentTypes];
}

function categoryIdsForContentType(contentType) {
  const type = String(contentType || '');
  return LAYOUT_CATEGORIES.filter(
    (c) => c.contentTypes.length === 0 || c.contentTypes.includes(type)
  ).map((c) => c.id);
}

module.exports = {
  LAYOUT_CATEGORIES,
  LAYOUT_CONTENT_TYPES,
  listLayoutCategories,
  resolveCategoryContentTypes,
  categoryIdsForContentType,
};
