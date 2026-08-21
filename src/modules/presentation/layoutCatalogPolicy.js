/**
 * Blueprint layout catalog: derive tags from schemas, map wizard image styles
 * to layout families, and filter the pool before the outline LLM.
 */

const PARA_DENSE_RE = /two_para|three_para|four_para|intro_four_para|bullet_list_dense/;
const GALLERY_RE =
  /four_images|para_two_images|para_three_images|grid_three_images|grid_images_text|grid_bento|two_large_image|grid_text_image_cards/;
const INFOGRAPHIC_RE =
  /diagram_|intro_three_para_icons|timeline_process|grid_insights|metric_|funnel|swot|matrix|cycle|pyramid/;
const DEVICE_RE = /device_|grid_device/;
const HERO_RE =
  /fullbleed|full_bg|overlay|title_hero|title_fullbleed|wide_image|large_image|closing_thank_you_fullbleed|statement_top|statement_bottom/;
const SPLIT_RE =
  /section_with_image|section_left_image|section_right_image|para_split|bullet_split|two_para_right|three_para_image|para_title_.*_image/;
const TEXT_RE = /title_minimal|title_centered|text_only|headline_centered|title_statement|bullet_list_cards|intro_four_para|agenda_minimal|section_divider_centered/;
const DARK_RE = /full_bg|overlay|fullbleed|neon|statement_top|statement_bottom/;
const QUANT_RE =
  /\b(chart|graph|kpi|metric|revenue|growth|%|percent|quarterly|forecast|analytics|data|statistics|numbers)\b/;
const PRODUCT_UI_RE =
  /\b(app|apps|saas|website|ui|ux|mockup|dashboard|product launch|mobile|iphone|android|screenshot)\b/;

const IMAGE_STYLE_TO_FAMILIES = {
  scene: ['hero', 'split'],
  photo: ['hero', 'split'],
  cinematic: ['hero', 'split'],
  'still-life': ['split', 'hero'],
  gouache: ['gallery', 'split'],
  watercolor: ['gallery', 'split'],
  'modern-art': ['gallery', 'split'],
  illustration: ['infographic', 'split'],
  'flat-line': ['infographic'],
  infographic: ['infographic'],
  isometric: ['infographic', 'device'],
  '3d': ['infographic', 'device'],
  'bold-poster': ['hero'],
  'neon-glow': ['hero'],
  'spot-color': ['hero'],
  mesh: ['hero', 'text'],
  bauhaus: ['infographic', 'gallery'],
};

const FILTER_PILL_FAMILIES = {
  photo: ['hero', 'split'],
  illustration: ['infographic', 'split', 'gallery'],
  abstract: ['gallery', 'hero'],
};

const STRUCTURAL_TYPES = new Set(['title', 'closing', 'agenda', 'section_divider']);

function layoutIdOf(template) {
  return String(template?.schema?.layout_id || template?.variant || template?.id || '').trim();
}

function contentTypeOf(template) {
  return String(template?.contentType || template?.schema?.content_type || '').toLowerCase();
}

function isMediaImageSlot(slot) {
  const id = String(slot?.id || '').toLowerCase();
  const role = String(slot?.role || '').toLowerCase();
  if (role === 'image' || role === 'background') return true;
  if (id.includes('image') || id === 'hero' || id.includes('device')) return true;
  return false;
}

function isTextSlot(slot) {
  const role = String(slot?.role || '').toLowerCase();
  return ['heading', 'subheading', 'body', 'caption', 'bullet', 'stat', 'cta', 'quote', 'title'].includes(
    role
  );
}

function isHeadingSlot(slot) {
  const role = String(slot?.role || '').toLowerCase();
  const id = String(slot?.id || '').toUpperCase();
  return (
    role === 'heading' ||
    role === 'title' ||
    ['MAIN_TITLE', 'HEADING', 'HEADLINE', 'TITLE', 'STATEMENT'].includes(id)
  );
}

function isCaptionOnlyLayout(slots, imageSlotCount) {
  const list = Array.isArray(slots) ? slots : [];
  if (imageSlotCount < 1) return false;
  if (list.some(isHeadingSlot)) return false;
  const bodyish = list.filter((s) =>
    ['body', 'subheading', 'bullet', 'quote', 'cta'].includes(String(s?.role || '').toLowerCase())
  );
  return bodyish.length === 0;
}

function deriveImageStyleFamilies(layoutId, contentType, imageSlotCount, hasChart, hasDevice) {
  const id = String(layoutId || '').toLowerCase();
  const families = new Set();
  if (GALLERY_RE.test(id) || imageSlotCount >= 3) families.add('gallery');
  if (INFOGRAPHIC_RE.test(id) || contentType === 'diagram' || contentType === 'stat') {
    families.add('infographic');
  }
  if (hasChart) families.add('infographic');
  if (DEVICE_RE.test(id) || contentType === 'device_frames' || hasDevice) families.add('device');
  if (HERO_RE.test(id)) families.add('hero');
  if (SPLIT_RE.test(id)) families.add('split');
  if (TEXT_RE.test(id) || imageSlotCount === 0) families.add('text');
  if (!families.size) {
    if (imageSlotCount >= 1) families.add('split');
    else families.add('text');
  }
  return [...families];
}

function deriveDensityFit(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  if (PARA_DENSE_RE.test(id) || /grid_metrics|metric_six|bullet_list_dense/.test(id)) {
    return ['balanced', 'detailed'];
  }
  if (/title_minimal|text_only|headline_centered|statement_large|agenda_minimal/.test(id)) {
    return ['concise', 'balanced'];
  }
  return ['concise', 'balanced', 'detailed'];
}

function deriveAppearance(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  if (DARK_RE.test(id)) return 'dark';
  return 'either';
}

function deriveLayoutMeta(template) {
  const schema = template?.schema || {};
  const layoutId = layoutIdOf(template);
  const contentType = contentTypeOf(template);
  const slots = Array.isArray(schema.slots) ? schema.slots : [];
  const imageSlotCount = slots.filter((s) => isMediaImageSlot(s)).length;
  const textSlotCount = slots.filter((s) => isTextSlot(s)).length;
  const hasChart =
    contentType === 'chart' ||
    slots.some((s) => String(s.role || '').toLowerCase() === 'chart') ||
    /chart|table_/.test(layoutId);
  const hasDevice =
    contentType === 'device_frames' || DEVICE_RE.test(layoutId) || slots.some((s) => /device/i.test(s.id || ''));
  const hasHeadingSlot = slots.some(isHeadingSlot);
  const captionOnly = isCaptionOnlyLayout(slots, imageSlotCount);

  return {
    layoutId,
    contentType,
    name: template?.name || layoutId,
    textSlotCount,
    imageSlotCount,
    hasHeadingSlot,
    captionOnly,
    hasChart,
    hasDevice,
    appearance: deriveAppearance(layoutId),
    densityFit: deriveDensityFit(layoutId),
    imageStyleFamilies: deriveImageStyleFamilies(
      layoutId,
      contentType,
      imageSlotCount,
      hasChart,
      hasDevice
    ),
    template,
  };
}

function familiesForImageStyle(imageStyle, imageStyleFilter) {
  const style = String(imageStyle || '')
    .trim()
    .toLowerCase();
  const filter = String(imageStyleFilter || '')
    .trim()
    .toLowerCase();
  const fromStyle = IMAGE_STYLE_TO_FAMILIES[style] || null;
  const fromFilter = FILTER_PILL_FAMILIES[filter] || null;
  if (fromStyle && fromFilter) {
    const overlap = fromStyle.filter((f) => fromFilter.includes(f));
    return overlap.length ? overlap : fromStyle;
  }
  return fromStyle || fromFilter || null;
}

function hexLuminance(hex) {
  const raw = String(hex || '')
    .replace('#', '')
    .trim();
  if (raw.length !== 6 && raw.length !== 3) return 0.5;
  const full =
    raw.length === 3
      ? raw
          .split('')
          .map((c) => c + c)
          .join('')
      : raw;
  const n = parseInt(full, 16);
  if (Number.isNaN(n)) return 0.5;
  const r = ((n >> 16) & 255) / 255;
  const g = ((n >> 8) & 255) / 255;
  const b = (n & 255) / 255;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function appearanceFromPalette(paletteOrHex) {
  const hex =
    typeof paletteOrHex === 'string'
      ? paletteOrHex
      : paletteOrHex?.bg || paletteOrHex?.background || '';
  const lum = hexLuminance(hex);
  return lum < 0.35 ? 'dark' : 'light';
}

function namedPromptPalette(sourceText) {
  const t = String(sourceText || '').toLowerCase();
  const keys = ['cream', 'sand', 'espresso', 'forest', 'mist'];
  const hits = keys.filter((k) => t.includes(k));
  if (t.includes('warm sand') && !hits.includes('sand')) hits.push('sand');
  if (hits.length < 2) return null;
  return {
    bg: '#F5EDE3',
    surface: '#E8DCC8',
    cardBg: '#EDE4D4',
    text: '#2C1810',
    muted: '#5C4A3E',
    primary: '#3D5C4A',
    secondary: '#8A9AA4',
    accent: '#6B4F3A',
    border: '#D4C4B0',
    overlayScrim: 'rgba(44,24,16,0.45)',
    textOnImage: '#F5EDE3',
    textOnImageMuted: 'rgba(245,237,227,0.88)',
  };
}

function biasPaletteFromSourceText(themeTokens, sourceText) {
  if (!themeTokens || typeof themeTokens !== 'object' || !themeTokens.palette) return themeTokens;
  const named = namedPromptPalette(sourceText);
  if (!named) return themeTokens;
  return {
    ...themeTokens,
    palette: { ...themeTokens.palette, ...named },
  };
}

function promptLooksQuantitative(text) {
  return QUANT_RE.test(String(text || '').toLowerCase());
}

function promptLooksProductUi(text) {
  return PRODUCT_UI_RE.test(String(text || '').toLowerCase());
}

function mapDensity(value) {
  const t = String(value || '')
    .trim()
    .toLowerCase();
  if (t === 'minimal' || t === 'concise') return 'concise';
  if (t === 'detailed' || t === 'extensive') return 'detailed';
  if (t === 'balanced') return 'balanced';
  return 'balanced';
}

function filterLayoutTemplates(templates, policy = {}) {
  const list = Array.isArray(templates) ? templates : [];
  const density = mapDensity(policy.density);
  const imageType = String(policy.imageType || 'ai')
    .trim()
    .toLowerCase();
  const noImages = imageType === 'none';
  const themeAppearance = policy.themeAppearance || null;
  const wantedFamilies = noImages
    ? ['text']
    : familiesForImageStyle(policy.imageStyle, policy.imageStyleFilter);
  const allowCharts = policy.allowCharts !== false;
  const allowDevices = policy.allowDevices !== false;
  const tone = String(policy.tone || '').toLowerCase();

  const metas = list.map(deriveLayoutMeta);
  const kept = metas.filter((meta) => {
    if (!meta.layoutId) return false;
    if (density === 'concise' && PARA_DENSE_RE.test(meta.layoutId)) return false;
    if (Array.isArray(meta.densityFit) && !meta.densityFit.includes(density)) return false;
    if (noImages && meta.imageSlotCount > 0) return false;
    if (!allowCharts && meta.hasChart) return false;
    if (!allowDevices && meta.hasDevice) return false;
    if (themeAppearance === 'dark' && meta.appearance === 'light') return false;
    if (themeAppearance === 'light' && meta.appearance === 'dark' && !STRUCTURAL_TYPES.has(meta.contentType)) {
      if (wantedFamilies && wantedFamilies.includes('hero')) return true;
      return false;
    }
    if (wantedFamilies && !STRUCTURAL_TYPES.has(meta.contentType)) {
      const hit = meta.imageStyleFamilies.some((f) => wantedFamilies.includes(f));
      if (!hit && meta.contentType !== 'chart' && meta.contentType !== 'comparison') return false;
    }
    if (/professional|corporate/.test(tone) && /neon-glow|playful/.test(meta.layoutId)) return false;
    return true;
  });

  return kept.length ? kept : metas.filter((m) => m.layoutId);
}

function buildLayoutDigest(metas, { maxPerType = 6, maxTotal = 48 } = {}) {
  const byType = new Map();
  for (const meta of metas) {
    const type = meta.contentType || 'other';
    if (!byType.has(type)) byType.set(type, []);
    const bucket = byType.get(type);
    if (bucket.length < maxPerType) bucket.push(meta);
  }
  const rows = [];
  for (const [contentType, bucket] of byType) {
    for (const meta of bucket) {
      rows.push({
        layoutId: meta.layoutId,
        name: meta.name,
        contentType,
        imageSlotCount: meta.imageSlotCount,
        textSlotCount: meta.textSlotCount,
        hasHeadingSlot: Boolean(meta.hasHeadingSlot),
        captionOnly: Boolean(meta.captionOnly),
        families: meta.imageStyleFamilies,
        appearance: meta.appearance,
      });
      if (rows.length >= maxTotal) return rows;
    }
  }
  return rows;
}

function allowedIdSet(digestOrMetas) {
  return new Set(
    (digestOrMetas || [])
      .map((row) => String(row.layoutId || row.layout_id || '').trim())
      .filter(Boolean)
  );
}

function pickFromPool(metas, predicate, used) {
  const pool = metas.filter(predicate);
  const unused = pool.filter((m) => !used.has(m.layoutId));
  const list = unused.length ? unused : pool;
  return list[0] || null;
}

function pickPreferredTitleLayout(metas, { visualsOn = true, used } = {}) {
  const usedSet = used instanceof Set ? used : new Set();
  const titles = (metas || []).filter(
    (m) => m.contentType === 'title' && m.hasHeadingSlot && !m.captionOnly
  );
  const unused = titles.filter((m) => !usedSet.has(m.layoutId));
  const pool = unused.length ? unused : titles;

  if (visualsOn) {
    return (
      pool.find((m) => m.layoutId === 'title_fullbleed_v1') ||
      pool.find((m) => /title_hero/.test(m.layoutId)) ||
      pool.find((m) => m.imageSlotCount > 0) ||
      pool[0] ||
      null
    );
  }
  return (
    pool.find((m) => m.layoutId === 'title_centered_v1') ||
    pool.find((m) => m.imageSlotCount === 0) ||
    pool[0] ||
    null
  );
}

function pickFallbackLayout(metas, { order, total, contentType, used, visualsOn = true }) {
  const usedSet = used instanceof Set ? used : new Set();
  const type = String(contentType || '').toLowerCase();
  const n = Number(order) || 1;
  const last = Number(total) || n;

  if (n === 1) {
    return (
      pickPreferredTitleLayout(metas, { visualsOn, used: usedSet }) ||
      pickFromPool(metas, (m) => m.contentType === 'title' && m.hasHeadingSlot, usedSet) ||
      pickFromPool(metas, (m) => m.layoutId, usedSet)
    );
  }
  if (n === last) {
    return (
      pickFromPool(metas, (m) => m.contentType === 'closing', usedSet) ||
      pickFromPool(metas, (m) => m.contentType === type, usedSet)
    );
  }
  if (type) {
    const typed = pickFromPool(metas, (m) => m.contentType === type, usedSet);
    if (typed) return typed;
  }
  return pickFromPool(
    metas,
    (m) => !['title', 'closing'].includes(m.contentType),
    usedSet
  );
}

function coerceOutlineLayouts(slides, metas, { slideCount, imageType } = {}) {
  const list = Array.isArray(slides) ? slides.slice() : [];
  const allowed = allowedIdSet(metas);
  const used = new Set();
  const total = slideCount || list.length;
  const visualsOn = String(imageType || 'ai').toLowerCase() !== 'none';

  const next = list.map((slide, idx) => {
    const order = Number(slide.order) > 0 ? Number(slide.order) : idx + 1;
    const layoutLocked = Boolean(slide.layoutLocked || slide.layout_locked);
    let layoutId = String(slide.layoutId || slide.layout_id || '').trim();
    if (layoutLocked && (!layoutId || !allowed.has(layoutId))) {
      const picked = pickFallbackLayout(metas, {
        order,
        total,
        contentType: slide.suggestedContentType || slide.content_type,
        used,
        visualsOn,
      });
      layoutId = picked?.layoutId || null;
    }
    if (!layoutLocked) layoutId = null;
    if (layoutLocked && layoutId) used.add(layoutId);
    const meta = metas.find((m) => m.layoutId === layoutId);
    return {
      ...slide,
      order,
      layoutLocked,
      layoutId: layoutId || null,
      suggestedContentType: slide.suggestedContentType || meta?.contentType || null,
      visual_need:
        slide.visual_need ||
        slide.visualNeed ||
        (meta?.imageSlotCount > 0 ? 'photo' : meta?.hasChart ? 'chart' : 'none'),
      layoutWhy: slide.layoutWhy || slide.layout_why || null,
    };
  });

  const firstIdx = next.findIndex((s) => Number(s.order) === 1);
  const idx = firstIdx >= 0 ? firstIdx : 0;
  if (next[idx]) {
    const meta = metas.find((m) => m.layoutId === next[idx].layoutId);
    const needsTitle =
      !meta ||
      meta.contentType !== 'title' ||
      !meta.hasHeadingSlot ||
      meta.captionOnly ||
      /large_image/.test(String(next[idx].layoutId || ''));
    if (next[idx].layoutLocked && needsTitle) {
      const picked = pickPreferredTitleLayout(metas, { visualsOn, used: new Set() });
      if (picked) {
        next[idx] = {
          ...next[idx],
          layoutId: picked.layoutId,
          suggestedContentType: 'title',
          visual_need: picked.imageSlotCount > 0 ? 'photo' : 'none',
          layoutWhy: next[idx].layoutWhy || 'Opening title with headline and subtitle slots',
        };
      }
    } else if (next[idx].layoutLocked) {
      next[idx] = { ...next[idx], suggestedContentType: 'title' };
    } else {
      next[idx] = { ...next[idx], suggestedContentType: 'title', layoutId: null };
    }
  }

  return next;
}

function enforceSlideCount(slides, slideCount) {
  const n = Math.max(1, Number(slideCount) || slides.length);
  let list = Array.isArray(slides) ? slides.slice() : [];
  if (list.length > n) list = list.slice(0, n);
  while (list.length < n) {
    const order = list.length + 1;
    const isLast = order === n;
    list.push({
      order,
      title: isLast ? 'Thank you' : `Topic ${order}`,
      subtitle: '',
      summary: isLast ? 'Close with a next step.' : 'Key point for this slide.',
      beats: [],
      visual: '',
      suggestedContentType: isLast ? 'closing' : order === 1 ? 'title' : 'bullet_list',
      layoutId: null,
    });
  }
  return list.map((s, idx) => ({ ...s, order: idx + 1 }));
}

function ensureDeckMix(slides, metas, policy = {}) {
  const list = Array.isArray(slides) ? slides.slice() : [];
  const style = String(policy.imageStyle || '').toLowerCase();
  const families = familiesForImageStyle(style, policy.imageStyleFilter) || [];
  const used = new Set(list.map((s) => s.layoutId).filter(Boolean));

  function swapMiddle(predicate) {
    const target = pickFromPool(metas, predicate, used);
    if (!target) return;
    const idx = list.findIndex(
      (s, i) => i > 0 && i < list.length - 1 && !predicate({ layoutId: s.layoutId, contentType: s.suggestedContentType })
    );
    if (idx < 0) return;
    list[idx] = {
      ...list[idx],
      layoutId: target.layoutId,
      suggestedContentType: target.contentType,
      layoutWhy: list[idx].layoutWhy || `Matched image style ${style}`,
    };
    used.add(target.layoutId);
  }

  const hasFamily = (fam) =>
    list.some((s) => {
      const meta = metas.find((m) => m.layoutId === s.layoutId);
      return meta?.imageStyleFamilies?.includes(fam);
    });

  if (families.includes('gallery') && list.length >= 5 && !hasFamily('gallery')) {
    swapMiddle((m) => (m.imageStyleFamilies || []).includes('gallery') || GALLERY_RE.test(m.layoutId || ''));
  }
  if (families.includes('infographic') && list.length >= 5 && !hasFamily('infographic')) {
    swapMiddle(
      (m) =>
        (m.imageStyleFamilies || []).includes('infographic') ||
        INFOGRAPHIC_RE.test(m.layoutId || '') ||
        m.contentType === 'diagram'
    );
  }

  const galleryCount = list.filter((s) => {
    const meta = metas.find((m) => m.layoutId === s.layoutId);
    return meta?.imageStyleFamilies?.includes('gallery');
  }).length;
  if ((style === 'photo' || style === 'cinematic' || style === 'scene') && galleryCount > 1) {
    const extra = list
      .map((s, i) => ({ s, i, meta: metas.find((m) => m.layoutId === s.layoutId) }))
      .filter((row) => row.meta?.imageStyleFamilies?.includes('gallery') && row.i > 0 && row.i < list.length - 1);
    extra.slice(1).forEach((row) => {
      const split = pickFromPool(metas, (m) => m.imageStyleFamilies.includes('split'), used);
      if (!split) return;
      list[row.i] = {
        ...list[row.i],
        layoutId: split.layoutId,
        suggestedContentType: split.contentType,
      };
      used.add(split.layoutId);
    });
  }

  return list;
}

const CHART_QUANT_RE =
  /\b(market|share|growth|revenue|sales|quarter|yoy|y\/y|percent|%|kpi|metric|funnel|conversion|pipeline|roi|arr|mrr|cac|ltv|trend|forecast|volume|units|stats?|data|analytics)\b/i;

function maxChartSlidesForDeck(slideCount) {
  const n = Number(slideCount) || 0;
  if (n <= 10) return 2;
  if (n <= 16) return 3;
  return 4;
}

function scoreChartSlideCandidate(slide) {
  const hay = [
    slide?.title,
    slide?.subtitle,
    slide?.summary,
    slide?.intent,
    slide?.contentIntent,
    Array.isArray(slide?.beats) ? slide.beats.join(' ') : '',
    Array.isArray(slide?.contentType) ? slide.contentType.join(' ') : '',
  ]
    .filter(Boolean)
    .join(' ');
  const matches = hay.match(new RegExp(CHART_QUANT_RE.source, 'gi'));
  return matches ? matches.length : 0;
}

/**
 * Cap chart slides by deck length. Demotes surplus middle-slide charts to image+text.
 * Skips layoutLocked slides (pack-bound). Never demotes title/closing ends.
 */
function enforceChartDensityCap(slides) {
  const list = Array.isArray(slides) ? slides.map((s) => ({ ...s })) : [];
  if (list.length < 2) return list;

  const maxCharts = maxChartSlidesForDeck(list.length);
  const candidates = list
    .map((s, i) => ({ s, i }))
    .filter(({ s, i }) => {
      if (i === 0 || i === list.length - 1) return false;
      if (s.layoutLocked || s.layout_locked) return false;
      return String(s.suggestedContentType || '').toLowerCase() === 'chart';
    });

  if (candidates.length <= maxCharts) return list;

  const ranked = candidates
    .map((row) => ({ ...row, score: scoreChartSlideCandidate(row.s) }))
    .sort((a, b) => b.score - a.score || a.i - b.i);

  const demote = ranked.slice(maxCharts);
  for (const row of demote) {
    const next = { ...list[row.i] };
    next.suggestedContentType = 'image+text';
    next.layoutWhy = next.layoutWhy
      ? `${next.layoutWhy}; Demoted chart — deck chart budget`
      : 'Demoted chart — deck chart budget';
    if (String(next.visual_need || '').toLowerCase() === 'chart') {
      next.visual_need = 'photo';
    }
    // Clear advisory chart layout so downstream can re-pick for image+text.
    if (!next.layoutLocked && !next.layout_locked) {
      next.layoutId = null;
    }
    list[row.i] = next;
  }

  return list;
}

function buildPolicyFromWizard({
  density,
  imageType,
  imageStyle,
  imageStyleFilter,
  sourceText,
  tone,
  purpose,
  themeTokens,
  packBound,
} = {}) {
  const text = String(sourceText || '');
  return {
    density: mapDensity(density),
    imageType: imageType || 'ai',
    imageStyle: imageStyle || '',
    imageStyleFilter: imageStyleFilter || '',
    themeAppearance: themeTokens?.palette ? appearanceFromPalette(themeTokens.palette) : null,
    allowCharts: packBound ? promptLooksQuantitative(text) : true,
    allowDevices: packBound ? promptLooksProductUi(text) : true,
    tone: tone || '',
    purpose: purpose || '',
  };
}

function layoutChoicesForUi(metas) {
  return (metas || []).map((m) => ({
    layoutId: m.layoutId,
    name: m.name,
    contentType: m.contentType,
    families: m.imageStyleFamilies,
  }));
}

module.exports = {
  IMAGE_STYLE_TO_FAMILIES,
  PARA_DENSE_RE,
  GALLERY_RE,
  layoutIdOf,
  deriveLayoutMeta,
  familiesForImageStyle,
  appearanceFromPalette,
  hexLuminance,
  promptLooksQuantitative,
  promptLooksProductUi,
  mapDensity,
  filterLayoutTemplates,
  buildLayoutDigest,
  coerceOutlineLayouts,
  enforceSlideCount,
  ensureDeckMix,
  maxChartSlidesForDeck,
  enforceChartDensityCap,
  buildPolicyFromWizard,
  layoutChoicesForUi,
  pickFallbackLayout,
  pickPreferredTitleLayout,
  isHeadingSlot,
  isCaptionOnlyLayout,
  biasPaletteFromSourceText,
  namedPromptPalette,
};
