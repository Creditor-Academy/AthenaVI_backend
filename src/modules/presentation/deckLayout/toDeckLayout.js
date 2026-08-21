const {
  DECK_LAYOUT_CATEGORIES,
} = require('./deckLayout.constants');
const { applyLayoutMetadataOverride } = require('./layoutMetadataOverrides');

const CHARS_PER_WORD = 6;
const WORDS_PER_LINE = 12;
const DEFAULT_TITLE_CHARS = 80;
const DEFAULT_SUBTITLE_CHARS = 140;
const DEFAULT_BODY_LINE_CHARS = 72;

function parseRegion(region) {
  const str = String(region || '');
  const cols = str.match(/cols\s+(\d+)\s*-\s*(\d+)/i);
  const rows = str.match(/rows\s+(\d+)\s*-\s*(\d+)/i);
  if (!cols || !rows) return null;
  return {
    c1: Math.max(1, Number(cols[1])),
    c2: Math.max(Number(cols[1]), Number(cols[2])),
    r1: Math.max(1, Number(rows[1])),
    r2: Math.max(Number(rows[1]), Number(rows[2])),
  };
}

function regionArea(reg) {
  if (!reg) return 0;
  return (reg.c2 - reg.c1 + 1) * (reg.r2 - reg.r1 + 1);
}

function humanizeLayoutId(id) {
  return String(id || '')
    .replace(/_v\d+$/i, '')
    .split('_')
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function layoutIdOf(input) {
  if (!input) return '';
  if (input.schema) {
    return String(input.schema.layout_id || input.variant || input.id || '').trim();
  }
  return String(input.layout_id || input.id || '').trim();
}

function contentTypeOf(input) {
  if (!input) return '';
  return String(input.contentType || input.content_type || input.schema?.content_type || '')
    .trim()
    .toLowerCase();
}

function schemaOf(input) {
  if (!input) return { layout_id: '', content_type: '', slots: [] };
  if (input.schema && typeof input.schema === 'object') return input.schema;
  if (Array.isArray(input.slots)) return input;
  return { layout_id: layoutIdOf(input), content_type: contentTypeOf(input), slots: [] };
}

function slotsOf(schema) {
  return Array.isArray(schema?.slots) ? schema.slots.filter(Boolean) : [];
}

function roleOf(slot) {
  return String(slot?.role || '').trim().toLowerCase();
}

function idOf(slot) {
  return String(slot?.id || '');
}

function idLower(slot) {
  return idOf(slot).toLowerCase();
}

function isLogoSlot(slot) {
  const id = idLower(slot);
  const role = roleOf(slot);
  return id === 'logo' || role === 'logo' || (role === 'decoration' && id.includes('logo'));
}

function isImageSlot(slot) {
  if (isLogoSlot(slot)) return false;
  const id = idLower(slot);
  const role = roleOf(slot);
  if (/^text_half_bg$/i.test(id)) return false;
  if (role === 'image' || role === 'background') return true;
  if (id.includes('image') || id.includes('hero') || id.includes('background')) return true;
  if (slot?.fit === 'cover') return true;
  return false;
}

function isHeadingSlot(slot) {
  const role = roleOf(slot);
  const id = idOf(slot).toUpperCase();
  return role === 'heading' || ['MAIN_TITLE', 'HEADING', 'HEADLINE', 'TITLE', 'STATEMENT'].includes(id);
}

function isSubheadingSlot(slot) {
  const role = roleOf(slot);
  const id = idOf(slot).toUpperCase();
  return role === 'subheading' || id === 'SUBTITLE' || id === 'SUBHEADLINE';
}

function isBodySlot(slot) {
  const role = roleOf(slot);
  const id = idLower(slot);
  if (role === 'body') return true;
  if (/^body_\d+$/i.test(id) || /^bullet_\d+$/i.test(id)) return true;
  return false;
}

function isBulletSlot(slot) {
  return /bullet/i.test(idOf(slot)) || /bullet/i.test(roleOf(slot));
}

function isStatSlot(slot) {
  const role = roleOf(slot);
  const id = idOf(slot);
  return role === 'stat' || /^STAT_\d+/i.test(id) || /^METRIC_/i.test(id);
}

function isIconSlot(slot) {
  const id = idLower(slot);
  const role = roleOf(slot);
  return id.includes('icon') || (role === 'decoration' && id.includes('icon'));
}

function countIndexed(slots, re) {
  const nums = new Set();
  for (const slot of slots) {
    const m = idOf(slot).match(re);
    if (m) nums.add(Number(m[1]));
  }
  return nums.size;
}

function charsFromLimits(slot, fallbackChars) {
  const maxWords = slot?.max_words != null ? Number(slot.max_words) : null;
  const maxLines = slot?.max_lines != null ? Number(slot.max_lines) : null;
  if (maxWords != null && maxWords > 0) return Math.round(maxWords * CHARS_PER_WORD);
  if (maxLines != null && maxLines > 0) return Math.round(maxLines * WORDS_PER_LINE * CHARS_PER_WORD);
  return fallbackChars;
}

function uniqueSorted(list) {
  return [...new Set(list.filter(Boolean))];
}

function deriveCategory(layoutId, contentType, slots) {
  const id = String(layoutId || '').toLowerCase();
  const ct = String(contentType || '').toLowerCase();
  const hasHeroImage = slots.some((s) => /hero|fullbleed|full_bg|background_image/i.test(idOf(s)));
  if (ct === 'title' && (/hero|fullbleed|full_bg|overlay/.test(id) || hasHeroImage)) return 'hero';
  if (ct === 'title') return 'title';
  if (ct === 'section_divider') return 'section';
  if (ct === 'closing') return 'closing';
  if (ct === 'quote') return 'quote';
  if (ct === 'team') return 'team';
  if (ct === 'pricing') return 'pricing';
  if (ct === 'comparison') return 'comparison';
  if (ct === 'timeline') return 'timeline';
  if (ct === 'diagram') return 'process';
  if (ct === 'chart') {
    if (/table/i.test(id) || slots.some((s) => roleOf(s) === 'table')) return 'table';
    return 'chart';
  }
  if (ct === 'stat') return 'data';
  if (ct === 'device_frames') return 'product';
  if (ct === 'image+text') return 'image';
  if (ct === 'grid') return 'content';
  if (ct === 'agenda') return 'content';
  if (ct === 'bullet_list') return 'content';
  if (DECK_LAYOUT_CATEGORIES.includes(ct)) return ct;
  return 'content';
}

function deriveSlidePurposes(layoutId, contentType, category) {
  const id = String(layoutId || '').toLowerCase();
  const ct = String(contentType || '').toLowerCase();
  const purposes = [];

  if (ct === 'title' || category === 'hero') {
    purposes.push('cover', 'introduction');
  }
  if (ct === 'section_divider') purposes.push('introduction');
  if (ct === 'closing') purposes.push('conclusion');
  if (ct === 'team') purposes.push('team');
  if (ct === 'pricing') purposes.push('pricing');
  if (ct === 'comparison') purposes.push('competition');
  if (ct === 'timeline' || /roadmap/.test(id)) purposes.push('roadmap');
  if (ct === 'diagram' || /process|funnel|cycle/.test(id)) purposes.push('process');
  if (ct === 'stat' || ct === 'chart' || /metric|kpi/.test(id)) purposes.push('statistics', 'traction');
  if (ct === 'quote') purposes.push('benefits');
  if (ct === 'device_frames' || /product/.test(id)) purposes.push('product');
  if (ct === 'image+text' || ct === 'bullet_list' || ct === 'grid') {
    purposes.push('features', 'solution');
  }
  if (ct === 'agenda') purposes.push('introduction');
  if (/problem/.test(id)) purposes.push('problem');
  if (/market/.test(id)) purposes.push('market');
  if (/pricing|plan_/.test(id)) purposes.push('pricing');
  if (category === 'hero') purposes.push('product');

  const unique = uniqueSorted(purposes);
  return unique.length ? unique : ['introduction'];
}

function deriveSupportedElements(slots, contentType) {
  const ct = String(contentType || '').toLowerCase();
  const hasTitle = slots.some(isHeadingSlot);
  const hasSubtitle = slots.some(isSubheadingSlot);
  const hasBody = slots.some((s) => isBodySlot(s) && !isBulletSlot(s));
  const hasBullets =
    ct === 'bullet_list' || slots.some(isBulletSlot) || slots.some((s) => /^body_\d+$/i.test(idOf(s)));
  const hasImage = slots.some(isImageSlot);
  const hasIcons = slots.some(isIconSlot);
  const hasMetrics = ct === 'stat' || slots.some(isStatSlot);
  const hasChart = ct === 'chart' || slots.some((s) => roleOf(s) === 'chart');
  const hasTable = slots.some((s) => roleOf(s) === 'table') || /table/i.test(ct);
  const hasCards =
    countIndexed(slots, /^card_(\d+)/i) > 0 ||
    countIndexed(slots, /^col_(\d+)/i) > 0 ||
    countIndexed(slots, /^MEMBER_(\d+)/i) > 0 ||
    countIndexed(slots, /^PLAN_(\d+)/i) > 0 ||
    countIndexed(slots, /^agenda_col_(\d+)/i) > 0;
  const hasQuote = ct === 'quote' || slots.some((s) => roleOf(s) === 'quote');

  return {
    title: hasTitle,
    subtitle: hasSubtitle,
    body: hasBody || hasBullets,
    bullets: hasBullets,
    image: hasImage,
    icons: hasIcons,
    metrics: hasMetrics,
    chart: hasChart,
    table: hasTable,
    cards: hasCards,
    quote: hasQuote,
  };
}

function deriveContentTypes(slots, contentType, supported) {
  const ct = String(contentType || '').toLowerCase();
  const types = [];
  if (supported.title) types.push('title');
  if (supported.subtitle) types.push('subtitle');
  if (supported.body && !supported.bullets) types.push('paragraph');
  if (supported.body && supported.bullets && slots.some((s) => roleOf(s) === 'body' && !isBulletSlot(s))) {
    types.push('paragraph');
  }
  if (supported.bullets) types.push('bullets');
  if (supported.image) types.push('image');
  if (supported.icons) types.push('icon');
  if (supported.metrics) {
    types.push('statistic');
    types.push('metrics');
  }
  if (supported.cards) types.push('cards');
  if (supported.chart) types.push('chart');
  if (supported.table) types.push('table');
  if (ct === 'timeline' || slots.some((s) => /timeline|step_/i.test(idOf(s)))) types.push('timeline');
  if (supported.quote) types.push('quote');
  if (ct === 'comparison' || /compare|vs_|versus/i.test(String(contentType))) types.push('comparison');
  return uniqueSorted(types);
}

function deriveContentCapacity(slots, layoutId, supported) {
  const heading = slots.find(isHeadingSlot);
  const subtitle = slots.find(isSubheadingSlot);
  const bodySlots = slots.filter((s) => isBodySlot(s) && !isBulletSlot(s));
  const bulletSlots = slots.filter(isBulletSlot);
  const imageCount = slots.filter(isImageSlot).length;
  const metricCount = slots.filter((s) => roleOf(s) === 'stat' || /^STAT_\d+(_VALUE)?$/i.test(idOf(s))).length;
  const cardCount = Math.max(
    countIndexed(slots, /^card_(\d+)/i),
    countIndexed(slots, /^col_(\d+)/i),
    countIndexed(slots, /^MEMBER_(\d+)/i),
    countIndexed(slots, /^PLAN_(\d+)/i),
    countIndexed(slots, /^agenda_col_(\d+)/i),
    countIndexed(slots, /^q(\d+)_/i),
    countIndexed(slots, /^step_(\d+)/i),
    countIndexed(slots, /^funnel_(\d+)/i)
  );
  const bodyIndexCount = countIndexed(slots, /^body_(\d+)$/i);
  const bulletIndexCount = countIndexed(slots, /^bullet_(\d+)$/i);

  let maxBullets = 0;
  if (supported.bullets) {
    maxBullets = Math.max(bulletIndexCount, bodyIndexCount, bulletSlots.length);
    for (const slot of slots) {
      if (slot.max_items != null) maxBullets = Math.max(maxBullets, Number(slot.max_items) || 0);
    }
    if (!maxBullets && supported.body) maxBullets = 6;
  }

  const maxBodyCharacters = bodySlots.reduce((sum, slot) => {
    return sum + charsFromLimits(slot, (slot.max_lines || 4) * DEFAULT_BODY_LINE_CHARS);
  }, 0);
  const maxBulletBodyFromSlots = bulletSlots.reduce((sum, slot) => {
    const fallback = Math.max(1, Number(slot.max_items) || 0) * 48;
    return sum + charsFromLimits(slot, fallback);
  }, 0);
  const textCapacity = maxBodyCharacters + maxBulletBodyFromSlots;

  const columnCount = Math.max(cardCount, bodyIndexCount > 1 ? bodyIndexCount : 0, 1);
  const visibleSlots = slots.filter((s) => roleOf(s) !== 'decoration' && roleOf(s) !== 'background');
  let density = 'medium';
  if (visibleSlots.length <= 3 && imageCount <= 1 && maxBullets <= 3) density = 'low';
  if (
    visibleSlots.length >= 8 ||
    maxBullets >= 8 ||
    cardCount >= 4 ||
    textCapacity >= 420 ||
    /dense|compact|three_para|four_para/.test(layoutId)
  ) {
    density = 'high';
  }

  return {
    maxTitleCharacters: supported.title
      ? charsFromLimits(heading || {}, DEFAULT_TITLE_CHARS)
      : 0,
    maxSubtitleCharacters: supported.subtitle
      ? charsFromLimits(subtitle || {}, DEFAULT_SUBTITLE_CHARS)
      : 0,
    maxBodyCharacters: supported.body ? textCapacity : 0,
    maxBullets,
    maxCards: supported.cards ? cardCount : 0,
    maxImages: supported.image ? imageCount : 0,
    maxMetrics: supported.metrics ? Math.max(metricCount, 0) : 0,
    maxColumns: Math.max(columnCount, imageCount && bodySlots.length ? 2 : 1, cardCount >= 3 ? 3 : 1),
    density,
  };
}

function deriveComposition(slots, layoutId, contentType, supported) {
  const id = String(layoutId || '').toLowerCase();
  const ct = String(contentType || '').toLowerCase();
  const imageSlots = slots.filter(isImageSlot);
  const textSlots = slots.filter((s) =>
    ['heading', 'subheading', 'body', 'caption', 'quote', 'stat', 'eyebrow', 'cta'].includes(roleOf(s))
  );
  const heading = slots.find(isHeadingSlot);
  const alignRaw = String(heading?.typography?.align || '').toLowerCase();
  const alignment = ['left', 'center', 'right'].includes(alignRaw) ? alignRaw : (ct === 'title' && !imageSlots.length ? 'center' : 'left');

  let imageArea = 0;
  let textArea = 0;
  let imgCenterC = 0;
  let imgCenterR = 0;
  for (const slot of imageSlots) {
    const reg = parseRegion(slot.region);
    const area = regionArea(reg);
    imageArea += area;
    if (reg) {
      imgCenterC += ((reg.c1 + reg.c2) / 2) * area;
      imgCenterR += ((reg.r1 + reg.r2) / 2) * area;
    }
  }
  if (imageArea > 0) {
    imgCenterC /= imageArea;
    imgCenterR /= imageArea;
  }

  let textCenterC = 6.5;
  let textAreaSum = 0;
  for (const slot of textSlots) {
    const reg = parseRegion(slot.region);
    const area = regionArea(reg);
    textArea += area;
    if (reg) {
      textCenterC = textAreaSum === 0 ? (reg.c1 + reg.c2) / 2 : textCenterC;
      textAreaSum += area;
    }
  }

  let imagePosition = 'none';
  if (imageSlots.length) {
    const fullBleed = imageSlots.some((s) => {
      const reg = parseRegion(s.region);
      return reg && reg.c1 <= 1 && reg.c2 >= 12 && (reg.r2 - reg.r1 + 1) >= 8;
    });
    if (fullBleed && textArea < imageArea * 0.35) imagePosition = 'full';
    else if (imgCenterR <= 4 && imgCenterC > 4 && imgCenterC < 9) imagePosition = 'top';
    else if (imgCenterR >= 7) imagePosition = 'bottom';
    else if (imgCenterC >= 7) imagePosition = 'right';
    else if (imgCenterC <= 6) imagePosition = 'left';
    else imagePosition = 'center';
  }

  let textPosition = 'center';
  if (textSlots.length) {
    const avg = textSlots.reduce((sum, s) => {
      const reg = parseRegion(s.region);
      return sum + (reg ? (reg.c1 + reg.c2) / 2 : 6.5);
    }, 0) / textSlots.length;
    if (avg <= 5.5) textPosition = 'left';
    else if (avg >= 7.5) textPosition = 'right';
    else textPosition = 'center';
  }

  const cardCount = Math.max(
    countIndexed(slots, /^card_(\d+)/i),
    countIndexed(slots, /^col_(\d+)/i),
    countIndexed(slots, /^MEMBER_(\d+)/i),
    countIndexed(slots, /^PLAN_(\d+)/i)
  );

  let structure = 'centered';
  if (ct === 'grid' || cardCount >= 4) structure = 'card-grid';
  else if (cardCount === 3 || /three_col|three_column/.test(id)) structure = 'three-column';
  else if (cardCount === 2 || /two_col|two_column/.test(id)) structure = 'two-column';
  else if (imagePosition === 'full') structure = 'full-image';
  else if (imagePosition === 'left' || imagePosition === 'right' || /split|50_50|left_image|right_image/.test(id)) {
    structure = 'split';
  } else if (!imageSlots.length && textSlots.length >= 4) structure = 'text-heavy';
  else if (imageSlots.length >= 2) structure = 'image-heavy';
  else if (alignment === 'center' && imageSlots.length <= 1) structure = 'centered';
  else if (ct === 'timeline') structure = 'split';

  let visualWeight = 'balanced';
  if (supported.chart || supported.metrics || supported.table) visualWeight = 'data-heavy';
  else if (imageArea > textArea * 1.2 && imageSlots.length) visualWeight = 'image-heavy';
  else if (textArea > imageArea * 1.4 || !imageSlots.length) visualWeight = 'text-heavy';

  if (structure === 'full-image') visualWeight = 'image-heavy';

  return {
    structure,
    imagePosition,
    textPosition,
    alignment,
    visualWeight,
  };
}

function deriveStyle(contentType, category) {
  const ct = String(contentType || '').toLowerCase();
  if (ct === 'pricing' || ct === 'team' || ct === 'closing') {
    return {
      designStyles: ['corporate', 'clean', 'minimal'],
      moods: ['professional', 'trustworthy'],
      industries: ['business', 'technology', 'consulting'],
    };
  }
  if (ct === 'chart' || ct === 'stat') {
    return {
      designStyles: ['corporate', 'clean', 'modern'],
      moods: ['professional', 'trustworthy'],
      industries: ['business', 'finance', 'technology'],
    };
  }
  if (ct === 'quote') {
    return {
      designStyles: ['editorial', 'minimal', 'premium'],
      moods: ['calm', 'premium', 'confident'],
      industries: ['business', 'media', 'general'],
    };
  }
  if (ct === 'device_frames' || category === 'product') {
    return {
      designStyles: ['modern', 'bold', 'clean'],
      moods: ['futuristic', 'energetic', 'creative'],
      industries: ['technology', 'startup'],
    };
  }
  if (category === 'hero' || ct === 'title') {
    return {
      designStyles: ['modern', 'minimal', 'premium'],
      moods: ['professional', 'premium', 'confident'],
      industries: ['technology', 'business', 'startup'],
    };
  }
  return {
    designStyles: ['modern', 'clean', 'minimal'],
    moods: ['professional', 'trustworthy'],
    industries: ['business', 'technology', 'general'],
  };
}

function deriveTags(layoutId, contentType, category, composition, supported) {
  const tags = [category, contentType, composition.structure, composition.visualWeight];
  if (supported.image) tags.push('image-led');
  if (composition.structure === 'split') tags.push('split');
  if (composition.structure === 'centered') tags.push('centered');
  if (/hero|fullbleed/.test(String(layoutId))) tags.push('hero');
  if (supported.chart) tags.push('data');
  return uniqueSorted(tags.map((t) => String(t || '').toLowerCase()).filter((t) => t && t !== 'undefined'));
}

function defaultDescription(name, category, composition, supported) {
  const bits = [];
  if (supported.title) bits.push('headline');
  if (supported.subtitle) bits.push('supporting text');
  if (supported.body) bits.push('body copy');
  if (supported.bullets) bits.push('bullets');
  if (supported.image) bits.push('image');
  if (supported.metrics) bits.push('metrics');
  if (supported.chart) bits.push('chart');
  if (supported.cards) bits.push('cards');
  const what = bits.length ? bits.join(', ') : 'slide content';
  return `${name} is a ${composition.structure} ${category} layout (${composition.visualWeight}) for ${what}.`;
}

function compileElements(schema) {
  try {
    const { layoutSlotsToElements } = require('../layoutToElements');
    const doc = layoutSlotsToElements(schema, {}, null, {});
    return Array.isArray(doc?.elements) ? doc.elements : [];
  } catch {
    return [];
  }
}

/**
 * Map an existing catalog template or DECK_LAYOUT schema into DeckLayout metadata.
 * @param {object} input Template row `{ name, contentType, variant, schema }` or a raw schema.
 * @param {{ includeElements?: boolean }} [options]
 */
function toDeckLayout(input, options = {}) {
  const schema = schemaOf(input);
  const id = layoutIdOf(input) || String(schema.layout_id || '').trim();
  const contentType = contentTypeOf(input) || String(schema.content_type || '').trim();
  const slots = slotsOf(schema);
  const name =
    (input && input.name) ||
    humanizeLayoutId(id) ||
    id;
  const version = Number(schema.schemaVersion || input?.version || 1) || 1;

  const supportedElements = deriveSupportedElements(slots, contentType);
  const category = deriveCategory(id, contentType, slots);
  const composition = deriveComposition(slots, id, contentType, supportedElements);
  const contentTypes = deriveContentTypes(slots, contentType, supportedElements);
  const contentCapacity = deriveContentCapacity(slots, id, supportedElements);
  const style = deriveStyle(contentType, category);
  const slidePurposes = deriveSlidePurposes(id, contentType, category);
  const tags = deriveTags(id, contentType, category, composition, supportedElements);

  const layout = {
    id,
    name,
    description: defaultDescription(name, category, composition, supportedElements),
    version,
    category,
    slidePurposes,
    contentTypes,
    tags,
    contentType,
    contentCapacity,
    composition,
    style,
    supportedElements,
    schema,
    elements: options.includeElements ? compileElements(schema) : [],
  };

  return applyLayoutMetadataOverride(layout);
}

module.exports = {
  toDeckLayout,
  layoutIdOf,
  contentTypeOf,
  parseRegion,
  deriveCategory,
  deriveSupportedElements,
};
