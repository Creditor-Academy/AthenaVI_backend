/**
 * Slide arrangement archetypes — common content-type sequences and preferred layouts.
 * Applied after outline generation and during deck-wide layout planning.
 */

const ARCHETYPES = {
  general: {
    id: 'general',
    label: 'General purpose',
    keywords: [],
    sequence(n) {
      return expandSequence(
        ['title', 'agenda', 'section_divider', 'image+text', 'grid', 'bullet_list', 'stat', 'chart', 'comparison', 'timeline', 'diagram', 'quote', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: [
        'title_hero_left_blob_v1',
        'title_hero_right_oval_v1',
        'title_hero_left_fade_v1',
        'title_hero_right_fade_v1',
        'title_fullbleed_v1',
        'title_image_logo_v1',
        'title_centered_v1',
        'title_minimal_v1',
        'headline_centered_v1',
        'title_statement_v1',
      ],
      agenda: ['agenda_three_columns_v1', 'agenda_numbered_v1', 'agenda_three_columns_hero_v1', 'agenda_minimal_v1'],
      'image+text': [
        'section_with_image_v1',
        'two_para_right_image_v1',
        'three_para_image_v1',
        'section_left_image_v1',
        'three_cards_image_text_v1',
        'para_split_50_50_v1',
        'wide_image_statement_top_v1',
      ],
      bullet_list: ['bullet_split_image_v1', 'four_para_image_v1', 'intro_four_para_v1', 'bullet_list_cards_v1', 'intro_three_para_icons_v1', 'bullet_list_dense_v1'],
      stat: ['metric_single_v1', 'metric_three_v1', 'metric_four_v1'],
      chart: ['chart_single_v1', 'chart_with_description_v1', 'chart_exponential_desc_v1', 'chart_donut_context_v1', 'chart_two_v1', 'grid_insights_chart_v1'],
      grid: ['grid_bento_three_v1', 'grid_text_image_cards_v1', 'grid_three_images_text_v1', 'grid_images_text_cards_v1'],
      device_frames: ['grid_device_mockups_v1'],
      quote: ['statement_left_v1', 'quote_portrait_v1', 'statement_large_v1', 'quote_testimonial_card_v1'],
      comparison: ['comparison_side_by_side_v1', 'comparison_pros_cons_v1', 'comparison_before_after_v1', 'comparison_table_v1'],
      timeline: ['timeline_milestones_v1', 'timeline_roadmap_v1', 'timeline_process_steps_v1', 'timeline_milestones_image_v1', 'timeline_horizontal_v1', 'timeline_vertical_v1'],
      diagram: ['diagram_process_steps_v1', 'diagram_swot_v1', 'diagram_matrix_v1', 'diagram_funnel_v1'],
      section_divider: ['section_divider_split_v1', 'section_divider_numbered_v1', 'section_divider_band_v1', 'section_divider_centered_v1'],
      closing: ['closing_thank_you_fullbleed_v1', 'closing_thank_you_v1', 'closing_contact_cta_v1', 'centered_text_cta_v1', 'para_image_cta_v1'],
    },
  },
  pitch: {
    id: 'pitch',
    label: 'Pitch / startup',
    keywords: ['pitch', 'startup', 'investor', 'funding', 'raise', 'vc', 'saas product'],
    sequence(n) {
      return expandSequence(
        ['title', 'agenda', 'section_divider', 'image+text', 'grid', 'stat', 'chart', 'comparison', 'device_frames', 'timeline', 'diagram', 'quote', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: [
        'title_hero_right_oval_v1',
        'title_hero_left_blob_v1',
        'title_fullbleed_v1',
        'title_hero_right_fade_v1',
        'title_image_logo_v1',
        'title_statement_v1',
      ],
      section_divider: ['section_divider_split_v1', 'section_divider_numbered_v1', 'section_divider_band_v1'],
      grid: ['grid_bento_three_v1', 'grid_text_image_cards_v1', 'grid_three_images_text_v1'],
      agenda: ['agenda_three_columns_hero_v1', 'agenda_numbered_v1'],
      comparison: ['comparison_side_by_side_v1', 'comparison_pros_cons_v1', 'comparison_table_v1'],
      timeline: ['timeline_roadmap_v1', 'timeline_process_steps_v1', 'timeline_milestones_v1', 'timeline_milestones_image_v1', 'timeline_vertical_v1'],
      diagram: ['diagram_process_steps_v1', 'diagram_funnel_v1', 'diagram_matrix_v1'],
      stat: ['metric_single_v1', 'metric_three_v1'],
      chart: ['chart_single_v1', 'chart_with_description_v1', 'chart_exponential_desc_v1', 'chart_donut_context_v1', 'chart_two_v1'],
      device_frames: ['grid_device_mockups_v1'],
      'image+text': ['three_cards_image_text_v1', 'two_para_right_image_v1', 'section_with_image_v1'],
      closing: ['closing_thank_you_fullbleed_v1', 'closing_contact_cta_v1', 'closing_thank_you_v1', 'centered_text_cta_v1'],
    },
  },
  educational: {
    id: 'educational',
    label: 'Educational / history',
    keywords: ['history', 'learn', 'course', 'lesson', 'tutorial', 'explain', 'education', 'chapter'],
    sequence(n) {
      return expandSequence(
        ['title', 'section_divider', 'image+text', 'timeline', 'bullet_list', 'diagram', 'grid', 'stat', 'section_divider', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: ['title_centered_v1', 'title_minimal_v1', 'title_statement_v1', 'title_image_logo_v1'],
      agenda: ['agenda_three_columns_v1', 'agenda_timeline_preview_v1'],
      timeline: ['timeline_milestones_image_v1', 'timeline_milestones_v1', 'timeline_process_steps_v1', 'timeline_vertical_v1', 'timeline_horizontal_v1'],
      'image+text': ['three_para_image_v1', 'two_para_right_image_v1', 'section_with_image_v1', 'three_cards_image_text_v1'],
      diagram: ['diagram_process_steps_v1', 'diagram_cycle_v1', 'diagram_swot_v1'],
      grid: ['grid_bento_three_v1', 'grid_three_images_text_v1'],
      section_divider: ['section_divider_numbered_v1', 'section_divider_split_v1'],
      bullet_list: ['bullet_split_image_v1', 'intro_four_para_v1', 'four_para_image_v1', 'bullet_list_numbered_v1'],
    },
  },
  product: {
    id: 'product',
    label: 'Product / launch',
    keywords: ['product', 'launch', 'feature', 'roadmap', 'release', 'website', 'app'],
    sequence(n) {
      return expandSequence(
        ['title', 'agenda', 'section_divider', 'image+text', 'grid', 'device_frames', 'comparison', 'stat', 'timeline', 'diagram', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: [
        'title_hero_right_oval_v1',
        'title_hero_left_blob_v1',
        'title_fullbleed_v1',
        'title_hero_right_fade_v1',
        'title_image_logo_v1',
        'title_statement_v1',
      ],
      section_divider: ['section_divider_split_v1', 'section_divider_numbered_v1'],
      agenda: ['agenda_three_columns_hero_v1', 'agenda_two_column_v1'],
      comparison: ['comparison_pros_cons_v1', 'comparison_side_by_side_v1', 'comparison_table_v1'],
      'image+text': ['three_cards_image_text_v1', 'three_para_image_v1', 'grid_bento_three_v1'],
      device_frames: ['grid_device_mockups_v1'],
      grid: ['grid_bento_three_v1', 'grid_text_image_cards_v1'],
      timeline: ['timeline_milestones_image_v1', 'timeline_roadmap_v1', 'timeline_milestones_v1'],
      diagram: ['diagram_funnel_v1', 'diagram_process_steps_v1', 'diagram_pyramid_v1'],
    },
  },
  corporate: {
    id: 'corporate',
    label: 'Corporate / report',
    keywords: ['quarterly', 'report', 'strategy', 'corporate', 'business review', 'kpi', 'metrics'],
    sequence(n) {
      return expandSequence(
        ['title', 'agenda', 'stat', 'chart', 'comparison', 'diagram', 'grid', 'section_divider', 'closing'],
        n
      );
    },
    preferredLayouts: {
      stat: ['metric_three_v1', 'metric_four_v1', 'metric_six_para_v1'],
      chart: ['chart_single_v1', 'chart_with_description_v1', 'chart_exponential_desc_v1', 'chart_donut_context_v1', 'chart_two_v1', 'grid_insights_chart_v1'],
      comparison: ['comparison_table_v1', 'comparison_side_by_side_v1'],
      diagram: ['diagram_swot_v1', 'diagram_matrix_v1', 'diagram_process_steps_v1'],
      grid: ['grid_metrics_masonry_v1', 'grid_insights_chart_v1'],
      section_divider: ['section_divider_band_v1', 'section_divider_numbered_v1'],
    },
  },
};

const BODY_ROTATION = [
  'image+text',
  'grid',
  'bullet_list',
  'stat',
  'chart',
  'comparison',
  'timeline',
  'diagram',
  'device_frames',
  'quote',
  'section_divider',
  'image+text',
];

/**
 * Every deck with 5+ slides gets at least one section_divider and one grid slide.
 */
function ensureMandatorySlideTypes(sequence, slideCount) {
  const n = Math.max(1, Number(slideCount) || sequence.length);
  const out = sequence.slice(0, n);
  if (n < 5) return out;

  const replaceableIndices = out
    .map((t, i) => ({ t, i }))
    .filter(
      ({ t, i }) =>
        i > 0 &&
        i < out.length - 1 &&
        !['title', 'agenda', 'closing', 'section_divider', 'grid'].includes(t)
    )
    .map(({ i }) => i);

  if (!out.includes('section_divider') && replaceableIndices.length) {
    out[replaceableIndices[0]] = 'section_divider';
  }
  if (!out.includes('grid')) {
    const idx =
      replaceableIndices.find((i) => out[i] !== 'section_divider') ??
      replaceableIndices[replaceableIndices.length - 1];
    if (idx != null) out[idx] = 'grid';
  }
  return out;
}

function expandSequence(core, slideCount) {
  const n = Math.max(1, Number(slideCount) || core.length);
  let out = n <= core.length ? core.slice(0, n) : core.slice();
  let rot = 0;
  while (out.length < n) {
    const type = BODY_ROTATION[rot % BODY_ROTATION.length];
    if (out[out.length - 1] === 'closing') {
      out.splice(out.length - 1, 0, type);
    } else {
      out.push(type);
    }
    rot += 1;
  }
  if (n >= 2 && out[out.length - 1] !== 'closing') {
    out[out.length - 1] = 'closing';
  }
  return ensureMandatorySlideTypes(out.slice(0, n), n);
}

function detectArchetype(sourceText = '', userPrompt = '') {
  const hay = `${sourceText} ${userPrompt}`.toLowerCase();
  let best = ARCHETYPES.general;
  let bestScore = 0;
  for (const arch of Object.values(ARCHETYPES)) {
    if (arch.id === 'general') continue;
    const score = (arch.keywords || []).reduce((acc, kw) => (hay.includes(kw) ? acc + 1 : acc), 0);
    if (score > bestScore) {
      bestScore = score;
      best = arch;
    }
  }
  return best;
}

function enrichOutlineWithArrangement(outline, { sourceText = '', userPrompt = '' } = {}) {
  if (!outline || !Array.isArray(outline.slides) || outline.slides.length === 0) {
    return outline;
  }
  const archetype = detectArchetype(sourceText || outline.sourcePrompt || '', userPrompt);
  const sequence = archetype.sequence(outline.slides.length);
  const slides = outline.slides.map((slide, idx) => {
    const order = Number(slide.order) > 0 ? Number(slide.order) : idx + 1;
    const seqIndex = order - 1;
    const hint = sequence[seqIndex] || 'image+text';
    return {
      ...slide,
      order,
      suggestedContentType: slide.suggestedContentType || slide.content_type || hint,
      arrangementHint: hint,
    };
  });
  return {
    ...outline,
    slides,
    arrangementArchetype: archetype.id,
    arrangementLabel: archetype.label,
  };
}

function simpleDeckHash(ctx = {}) {
  const raw = [
    ctx.deckId || '',
    ctx.outline?.title || '',
    ctx.userPrompt || '',
    ctx.outline?.arrangementArchetype || '',
  ].join('|');
  let hash = 0;
  for (let i = 0; i < raw.length; i += 1) {
    hash = (hash * 31 + raw.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

/**
 * Pick a preferred layout_id — rotate among prefs using slide order + deck hash to reduce repetition.
 */
function preferredLayoutForSlide(ctx, contentType, usedLayoutIds = new Set(), slideOrder = 0) {
  const archetypeId = ctx.outline?.arrangementArchetype || 'general';
  const archetype = ARCHETYPES[archetypeId] || ARCHETYPES.general;
  const prefs = archetype.preferredLayouts?.[String(contentType || '').toLowerCase()] || [];
  const unused = prefs.filter((layoutId) => !usedLayoutIds.has(String(layoutId)));
  const pool = unused.length ? unused : prefs;
  if (!pool.length) return null;
  const order = Math.max(0, Number(slideOrder) - 1);
  const seed = simpleDeckHash(ctx);
  const idx = (order + seed) % pool.length;
  return pool[idx];
}

function getArchetype(id) {
  return ARCHETYPES[id] || ARCHETYPES.general;
}

module.exports = {
  ARCHETYPES,
  detectArchetype,
  enrichOutlineWithArrangement,
  preferredLayoutForSlide,
  expandSequence,
  ensureMandatorySlideTypes,
  getArchetype,
  simpleDeckHash,
};
