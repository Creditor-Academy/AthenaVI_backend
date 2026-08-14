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
        ['title', 'agenda', 'image+text', 'bullet_list', 'stat', 'comparison', 'timeline', 'quote', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: ['title_image_logo_v1', 'title_minimal_v1', 'title_centered_v1', 'headline_centered_v1'],
      agenda: ['agenda_three_columns_v1', 'agenda_numbered_v1', 'agenda_three_columns_hero_v1', 'agenda_minimal_v1'],
      'image+text': ['section_with_image_v1', 'section_left_image_v1', 'three_cards_image_text_v1', 'para_split_50_50_v1'],
      bullet_list: ['bullet_list_cards_v1', 'bullet_list_dense_v1', 'intro_four_para_v1', 'text_only_centered_v1'],
      stat: ['metric_single_v1', 'metric_three_v1', 'metric_four_v1'],
      quote: ['statement_left_v1', 'quote_portrait_v1', 'statement_large_v1', 'quote_testimonial_card_v1'],
      comparison: ['comparison_side_by_side_v1', 'comparison_pros_cons_v1', 'comparison_before_after_v1', 'comparison_table_v1'],
      timeline: ['timeline_horizontal_v1', 'timeline_milestones_v1', 'timeline_roadmap_v1', 'timeline_vertical_v1'],
      diagram: ['diagram_swot_v1', 'diagram_matrix_v1', 'diagram_process_steps_v1', 'diagram_funnel_v1'],
      section_divider: ['section_divider_numbered_v1', 'section_divider_band_v1', 'section_divider_centered_v1'],
      closing: ['centered_text_cta_v1', 'closing_thank_you_v1', 'para_image_cta_v1', 'closing_contact_cta_v1'],
    },
  },
  pitch: {
    id: 'pitch',
    label: 'Pitch / startup',
    keywords: ['pitch', 'startup', 'investor', 'funding', 'raise', 'vc', 'saas product'],
    sequence(n) {
      return expandSequence(
        ['title', 'agenda', 'image+text', 'stat', 'comparison', 'timeline', 'diagram', 'quote', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: ['title_image_logo_v1', 'title_statement_v1'],
      agenda: ['agenda_three_columns_hero_v1', 'agenda_numbered_v1'],
      comparison: ['comparison_side_by_side_v1', 'comparison_pros_cons_v1', 'comparison_table_v1'],
      timeline: ['timeline_milestones_v1', 'timeline_roadmap_v1'],
      diagram: ['diagram_funnel_v1', 'diagram_matrix_v1'],
      stat: ['metric_single_v1', 'metric_three_v1'],
      closing: ['centered_text_cta_v1', 'closing_contact_cta_v1'],
    },
  },
  educational: {
    id: 'educational',
    label: 'Educational / history',
    keywords: ['history', 'learn', 'course', 'lesson', 'tutorial', 'explain', 'education', 'chapter'],
    sequence(n) {
      return expandSequence(
        ['title', 'section_divider', 'image+text', 'timeline', 'bullet_list', 'diagram', 'stat', 'section_divider', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: ['title_centered_v1', 'title_minimal_v1'],
      agenda: ['agenda_three_columns_v1', 'agenda_timeline_preview_v1'],
      timeline: ['timeline_horizontal_v1', 'timeline_milestones_v1', 'timeline_vertical_v1', 'timeline_process_steps_v1'],
      'image+text': ['section_with_image_v1', 'wide_image_statement_top_v1'],
      diagram: ['diagram_process_steps_v1', 'diagram_cycle_v1', 'diagram_swot_v1'],
      section_divider: ['section_divider_numbered_v1', 'section_divider_split_v1'],
      bullet_list: ['bullet_list_numbered_v1', 'intro_four_para_v1'],
    },
  },
  product: {
    id: 'product',
    label: 'Product / launch',
    keywords: ['product', 'launch', 'feature', 'roadmap', 'release', 'website', 'app'],
    sequence(n) {
      return expandSequence(
        ['title', 'agenda', 'image+text', 'comparison', 'stat', 'timeline', 'diagram', 'closing'],
        n
      );
    },
    preferredLayouts: {
      title: ['title_image_logo_v1', 'title_statement_v1'],
      agenda: ['agenda_three_columns_hero_v1', 'agenda_two_column_v1'],
      comparison: ['comparison_pros_cons_v1', 'comparison_side_by_side_v1', 'comparison_table_v1'],
      'image+text': ['three_cards_image_text_v1', 'grid_bento_three_v1'],
      timeline: ['timeline_roadmap_v1', 'timeline_milestones_v1'],
      diagram: ['diagram_funnel_v1', 'diagram_pyramid_v1'],
    },
  },
  corporate: {
    id: 'corporate',
    label: 'Corporate / report',
    keywords: ['quarterly', 'report', 'strategy', 'corporate', 'business review', 'kpi', 'metrics'],
    sequence(n) {
      return expandSequence(
        ['title', 'agenda', 'stat', 'chart', 'comparison', 'diagram', 'section_divider', 'closing'],
        n
      );
    },
    preferredLayouts: {
      stat: ['metric_three_v1', 'metric_four_v1', 'metric_six_para_v1'],
      chart: ['chart_with_description_v1', 'chart_two_v1'],
      comparison: ['comparison_table_v1', 'comparison_side_by_side_v1'],
      diagram: ['diagram_swot_v1', 'diagram_matrix_v1'],
      section_divider: ['section_divider_band_v1', 'section_divider_numbered_v1'],
    },
  },
};

const BODY_ROTATION = [
  'image+text',
  'bullet_list',
  'stat',
  'comparison',
  'timeline',
  'diagram',
  'quote',
  'section_divider',
  'image+text',
];

function expandSequence(core, slideCount) {
  const n = Math.max(1, Number(slideCount) || core.length);
  if (n <= core.length) return core.slice(0, n);
  const out = core.slice();
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
  return out.slice(0, n);
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

/**
 * Pick a preferred layout_id — rotate among prefs using slide order to reduce repetition.
 */
function preferredLayoutForSlide(ctx, contentType, usedLayoutIds = new Set(), slideOrder = 0) {
  const archetypeId = ctx.outline?.arrangementArchetype || 'general';
  const archetype = ARCHETYPES[archetypeId] || ARCHETYPES.general;
  const prefs = archetype.preferredLayouts?.[String(contentType || '').toLowerCase()] || [];
  const unused = prefs.filter((layoutId) => !usedLayoutIds.has(String(layoutId)));
  const pool = unused.length ? unused : prefs;
  if (!pool.length) return null;
  const idx = Math.max(0, Number(slideOrder) - 1) % pool.length;
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
  getArchetype,
};
