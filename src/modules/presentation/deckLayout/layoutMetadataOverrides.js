/**
 * Hand-tuned DeckLayout metadata keyed by existing layout_id.
 * Merged over heuristic output. Never replace schema.slots geometry.
 */

const TITLE_HERO_RIGHT_FADE_OVERRIDE = {
  id: 'title_hero_right_fade_v1',
  name: 'Split Hero',
  description:
    'Large headline and supporting text on the left with a dominant image on the right.',
  version: 1,
  category: 'hero',
  slidePurposes: ['cover', 'introduction', 'product'],
  contentTypes: ['title', 'subtitle', 'image'],
  tags: ['hero', 'premium', 'minimal', 'image-led'],
  contentCapacity: {
    maxTitleCharacters: 80,
    maxSubtitleCharacters: 140,
    maxBodyCharacters: 0,
    maxBullets: 0,
    maxCards: 0,
    maxImages: 1,
    maxMetrics: 0,
    maxColumns: 2,
    density: 'low',
  },
  composition: {
    structure: 'split',
    imagePosition: 'right',
    textPosition: 'left',
    alignment: 'left',
    visualWeight: 'image-heavy',
  },
  style: {
    designStyles: ['modern', 'minimal', 'premium'],
    moods: ['professional', 'premium', 'confident'],
    industries: ['technology', 'business', 'startup'],
  },
  supportedElements: {
    title: true,
    subtitle: true,
    body: false,
    bullets: false,
    image: true,
    icons: false,
    metrics: false,
    chart: false,
    table: false,
    cards: false,
    quote: false,
  },
};

const TIMELINE_PROCESS_OVERRIDE = {
  slidePurposes: ['process', 'roadmap'],
  contentTypes: ['title', 'timeline'],
  tags: ['timeline', 'process', 'steps'],
  composition: { structure: 'split', visualWeight: 'balanced' },
};

const PRICING_TABLE_OVERRIDE = {
  slidePurposes: ['pricing', 'benefits'],
  contentTypes: ['title', 'cards', 'metrics', 'comparison'],
  tags: ['pricing', 'comparison'],
  composition: { structure: 'three-column', visualWeight: 'data-heavy' },
};

const TEAM_LAYOUT_OVERRIDE = {
  slidePurposes: ['team', 'introduction'],
  contentTypes: ['title', 'cards', 'image'],
  tags: ['team', 'profiles'],
  contentCapacity: { maxCards: 6, density: 'medium' },
};

const LAYOUT_METADATA_OVERRIDES = {
  title_hero_right_fade_v1: TITLE_HERO_RIGHT_FADE_OVERRIDE,
  timeline_process_horizontal_v1: TIMELINE_PROCESS_OVERRIDE,
  timeline_vertical_steps_v1: TIMELINE_PROCESS_OVERRIDE,
  pricing_three_tiers_v1: PRICING_TABLE_OVERRIDE,
  pricing_table_compare_v1: PRICING_TABLE_OVERRIDE,
  team_six_v1: TEAM_LAYOUT_OVERRIDE,
  team_four_cards_v1: TEAM_LAYOUT_OVERRIDE,
};

function applyLayoutMetadataOverride(layout) {
  const id = String(layout?.id || '').trim();
  const overlay = LAYOUT_METADATA_OVERRIDES[id];
  if (!overlay) return layout;

  return {
    ...layout,
    ...overlay,
    id: layout.id,
    contentType: layout.contentType,
    schema: layout.schema,
    elements: layout.elements,
    contentCapacity: { ...layout.contentCapacity, ...overlay.contentCapacity },
    composition: { ...layout.composition, ...overlay.composition },
    style: {
      ...layout.style,
      ...overlay.style,
      designStyles: overlay.style?.designStyles || layout.style?.designStyles,
      moods: overlay.style?.moods || layout.style?.moods,
      industries: overlay.style?.industries || layout.style?.industries,
    },
    supportedElements: { ...layout.supportedElements, ...overlay.supportedElements },
    extensions: overlay.extensions || layout.extensions,
  };
}

module.exports = {
  LAYOUT_METADATA_OVERRIDES,
  TITLE_HERO_RIGHT_FADE_OVERRIDE,
  applyLayoutMetadataOverride,
};
