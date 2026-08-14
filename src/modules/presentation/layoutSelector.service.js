function countWords(text) {
  if (text == null) return 0;
  const s = String(text).trim();
  if (!s) return 0;
  return s.split(/\s+/).filter(Boolean).length;
}

function contentDensity(content) {
  if (!content || typeof content !== 'object') {
    return { bulletCount: 0, wordCount: 0 };
  }

  const bullets = Array.isArray(content.bullets) ? content.bullets : [];
  const bulletCount = bullets.length;

  let wordCount = 0;
  wordCount += countWords(content.title);
  wordCount += countWords(content.subtitle);
  wordCount += countWords(content.body);
  wordCount += countWords(content.quote);
  for (const b of bullets) {
    wordCount += countWords(typeof b === 'string' ? b : b?.text);
  }

  if (Array.isArray(content.stats)) {
    for (const stat of content.stats) {
      wordCount += countWords(stat?.label);
      wordCount += countWords(stat?.value);
    }
  }

  const statCount = Array.isArray(content.stats) ? content.stats.length : 0;
  const memberCount = Array.isArray(content.members) ? content.members.length : 0;
  const planCount = Array.isArray(content.plans) ? content.plans.length : 0;
  const hasChart = Boolean(content.chart && (content.chart.labels?.length || content.chart.series?.length));
  const hasTable = Boolean(content.table && (content.table.headers?.length || content.table.rows?.length));
  const hasAgenda = Boolean(content.agenda?.columns?.length);
  const hasContact = Boolean(content.contact && (content.contact.address || content.contact.phone || content.contact.email));

  return { bulletCount, wordCount, statCount, memberCount, planCount, hasChart, hasTable, hasAgenda, hasContact };
}

function layoutCapacity(template) {
  const schema = template?.schema || {};
  const slots = Array.isArray(schema.slots) ? schema.slots : [];
  let maxItems = 0;
  let maxWordsHint = 0;
  let hasDenseVariant = false;

  const variant = String(template.variant || schema.layout_id || '').toLowerCase();
  if (variant.includes('dense') || variant.includes('compact')) {
    hasDenseVariant = true;
  }

  for (const slot of slots) {
    if (slot.max_items != null) {
      maxItems = Math.max(maxItems, Number(slot.max_items) || 0);
    }
    if (slot.max_words != null) {
      maxWordsHint = Math.max(maxWordsHint, Number(slot.max_words) || 0);
    }
  }

  return { maxItems, maxWordsHint, hasDenseVariant, slotCount: slots.length };
}

function templateHasImageSlot(template) {
  const slots = Array.isArray(template?.schema?.slots) ? template.schema.slots : [];
  return slots.some((slot) => {
    const id = String(slot?.id || '').toLowerCase();
    return id.includes('image') || id === 'hero' || slot?.fit === 'cover';
  });
}

function countImageSlots(template) {
  const slots = Array.isArray(template?.schema?.slots) ? template.schema.slots : [];
  return slots.filter((slot) => {
    const id = String(slot?.id || '').toLowerCase();
    return slot?.role === 'image' || id.includes('image') || id.includes('device');
  }).length;
}

function countStatSlots(template) {
  const slots = Array.isArray(template?.schema?.slots) ? template.schema.slots : [];
  return slots.filter((slot) => slot?.role === 'stat' || /^stat_\d+_value$/i.test(String(slot?.id || ''))).length;
}

function countMemberSlots(template) {
  const slots = Array.isArray(template?.schema?.slots) ? template.schema.slots : [];
  return slots.filter((slot) => /^MEMBER_\d+_NAME$/i.test(String(slot?.id || ''))).length;
}

function countPlanSlots(template) {
  const slots = Array.isArray(template?.schema?.slots) ? template.schema.slots : [];
  return slots.filter((slot) => /^PLAN_\d+_LABEL$/i.test(String(slot?.id || ''))).length;
}

function scoreTemplate(
  template,
  { bulletCount, wordCount, statCount, memberCount, planCount, hasChart, hasTable, hasAgenda, hasContact },
  previousLayoutId,
  preferImageSlot,
  usedLayoutIds = null,
  preferredLayoutId = null
) {
  const layoutId =
    template?.schema?.layout_id || template?.id || `${template?.contentType}_${template?.variant}`;
  const capacity = layoutCapacity(template);
  let score = 0;

  if (preferredLayoutId && String(layoutId) === String(preferredLayoutId)) {
    score += 40;
  }

  if (previousLayoutId && String(layoutId) === String(previousLayoutId)) {
    score -= 100;
  }

  if (usedLayoutIds && typeof usedLayoutIds.has === 'function' && usedLayoutIds.has(String(layoutId))) {
    score -= 60;
  }

  if (preferImageSlot) {
    if (templateHasImageSlot(template)) score += 50;
    else score -= 40;
  }

  const ct = String(template.contentType || template?.schema?.content_type || '');
  const imageSlotCount = countImageSlots(template);
  const statSlotCount = countStatSlots(template);

  if (hasChart && ct === 'chart') score += 40;
  if (hasTable && ct === 'chart') score += 35;
  if (hasTable && ct === 'pricing') score += 30;
  if (planCount > 0 && ct === 'pricing') {
    score += 30;
    const planSlots = countPlanSlots(template);
    if (planSlots === planCount) score += 25;
    else if (planSlots >= planCount) score += 15;
  }
  if (memberCount > 0 && ct === 'team') {
    score += 30;
    const memberSlots = countMemberSlots(template);
    if (memberSlots === memberCount) score += 25;
    else if (memberSlots >= memberCount) score += 15;
  }
  if (hasAgenda && ct === 'agenda') score += 40;
  if (hasContact && ct === 'team') score += 20;
  if (ct === 'device_frames') score += 35;
  if (statCount > 0 && ct === 'stat') {
    score += 30;
    if (statSlotCount >= statCount) score += 20;
    else if (statSlotCount > 0) score += 10;
  }
  if (imageSlotCount >= 3 && ct === 'grid') score += 25;
  if (bulletCount >= 4 && ct === 'grid') score += 15;

  const variant = String(template.variant || template?.schema?.layout_id || '').toLowerCase();
  if (/two_para|three_para|four_para|intro_four_para|intro_three_para/.test(variant)) {
    if (wordCount >= 30) score += 25;
    if (bulletCount >= 2) score += 15;
  }
  if (/three_cards|cards_image/.test(variant) && bulletCount >= 2) score += 20;
  if (/section_with_image|two_para_right|three_para_image|section_left_image|para_split/.test(variant)) {
    score += 22;
  }

  if (bulletCount >= 7) {
    if (capacity.maxItems >= bulletCount || capacity.hasDenseVariant) score += 30;
    else if (capacity.maxItems >= 6) score += 15;
    else score -= 10;
  } else if (bulletCount <= 3 && bulletCount > 0) {
    if (capacity.maxItems > 0 && capacity.maxItems <= 6) score += 20;
    if (capacity.hasDenseVariant) score -= 5;
  } else if (bulletCount > 3) {
    if (capacity.maxItems >= bulletCount) score += 20;
  }

  if (wordCount >= 80) {
    if (capacity.hasDenseVariant || capacity.maxWordsHint >= 14) score += 15;
  } else if (wordCount > 0 && wordCount < 30) {
    if (!capacity.hasDenseVariant) score += 10;
  }

  // Prefer primary variants when density is moderate
  if (String(template.variant || '').toLowerCase() === 'v1') {
    score += 2;
  }

  return { layoutId, score, template };
}

/**
 * Exclude title/closing layouts when slide order forbids them.
 */
function filterTemplatesForSlideOrder(templates, slideOrder, totalSlides) {
  const list = Array.isArray(templates) ? templates : [];
  const order = Number(slideOrder) > 0 ? Number(slideOrder) : 1;
  const total = Number(totalSlides) > 0 ? Number(totalSlides) : order;
  return list.filter((t) => {
    const ct = String(t.contentType || t.schema?.content_type || '').toLowerCase();
    if (ct === 'title' && order !== 1) return false;
    if (ct === 'closing' && order !== total) return false;
    return true;
  });
}

/**
 * Rule-based layout pick: match contentType, prefer by density, avoid previousLayoutId.
 * @returns {{ layoutId: string, template: object|null }}
 */
function selectLayout({
  contentType,
  content,
  previousLayoutId,
  templates,
  preferImageSlot = false,
  usedLayoutIds = null,
  preferredLayoutId = null,
  slideOrder = null,
  totalSlides = null,
}) {
  let list = Array.isArray(templates) ? templates : [];
  if (slideOrder != null) {
    list = filterTemplatesForSlideOrder(list, slideOrder, totalSlides ?? slideOrder);
  }
  const type = contentType != null ? String(contentType) : null;

  const matched = type
    ? list.filter((t) => String(t.contentType || t.schema?.content_type || '') === type)
    : list.slice();

  let pool = matched.length > 0 ? matched : list;

  // If we need an image slot and this content type has none, fall back to image+text templates
  if (preferImageSlot && pool.length > 0 && !pool.some(templateHasImageSlot)) {
    const imageText = list.filter(
      (t) => String(t.contentType || t.schema?.content_type || '') === 'image+text'
    );
    if (imageText.length) pool = imageText;
  }

  if (pool.length === 0) {
    return { layoutId: null, template: null };
  }

  const density = contentDensity(content);
  const scored = pool
    .map((template) =>
      scoreTemplate(
        template,
        density,
        previousLayoutId,
        preferImageSlot,
        usedLayoutIds,
        preferredLayoutId
      )
    )
    .sort((a, b) => b.score - a.score || String(a.layoutId).localeCompare(String(b.layoutId)));

  // Prefer unused layouts when any remain; never repeat if pool has alternatives
  const unused = scored.filter(
    (s) =>
      (!usedLayoutIds?.has?.(String(s.layoutId))) &&
      (!previousLayoutId || String(s.layoutId) !== String(previousLayoutId))
  );
  const preferred =
    unused[0] ||
    scored.find((s) => previousLayoutId && String(s.layoutId) !== String(previousLayoutId)) ||
    scored[0];

  return {
    layoutId: preferred.layoutId,
    template: preferred.template,
  };
}

module.exports = {
  selectLayout,
  filterTemplatesForSlideOrder,
  contentDensity,
  countWords,
  templateHasImageSlot,
};
