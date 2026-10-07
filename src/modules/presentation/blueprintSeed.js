const { isCatalogPlaceholderText } = require('./catalogPlaceholder');

function isWeakText(text) {
  const t = String(text || '').trim();
  if (!t) return true;
  if (isCatalogPlaceholderText(t)) return true;
  const lower = t.toLowerCase();
  return (
    /^your (title|subtitle|heading|headline|name|company|tagline|text|quote)/.test(lower) ||
    lower === 'insert text' ||
    lower.startsWith('lorem ipsum') ||
    lower === 'double-click to edit' ||
    lower === 'double click to edit' ||
    lower === 'presentation title' ||
    lower === 'tagline or company name' ||
    lower === 'add your presentation title'
  );
}

function beatItems(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((beat) => {
      if (typeof beat === 'string') {
        const text = beat.trim();
        return text ? { title: text, body: text } : null;
      }
      if (!beat || typeof beat !== 'object') return null;
      const title = String(beat.label || beat.title || beat.heading || beat.name || '').trim();
      const body = String(beat.text || beat.body || beat.detail || beat.summary || '').trim();
      if (!title && !body) return null;
      return { title: title || body, body: body || title };
    })
    .filter(Boolean);
}

function seedFromOutlineSlide(outlineSlide = {}) {
  const beats = beatItems(outlineSlide.beats);
  const title = String(outlineSlide.title || '').trim();
  const subtitle = String(outlineSlide.subtitle || '').trim();
  const summary = String(outlineSlide.summary || outlineSlide.description || '').trim();
  const suggested = String(outlineSlide.suggestedContentType || outlineSlide.contentType || '').toLowerCase();
  const seed = {
    title,
    subtitle,
    body: summary,
    summary,
    visual: String(outlineSlide.visual || '').trim(),
    beats,
    bullets: beats.map((b) => (b.title === b.body ? b.title : `**${b.title}:** ${b.body}`)),
    columns: beats.map((b) => ({ title: b.title, body: b.body })),
    outlineSlide,
  };
  if (suggested === 'pricing' || suggested.includes('pricing')) {
    seed.plans = seedPlansFromOutline(outlineSlide);
  }
  return seed;
}

function countHeadingSlots(slots) {
  return (slots || []).filter((s) => {
    const role = String(s.role || '').toLowerCase();
    const id = String(s.id || '').toUpperCase();
    return (
      role === 'heading' ||
      role === 'title' ||
      ['MAIN_TITLE', 'HEADING', 'HEADLINE', 'TITLE', 'STATEMENT', 'QUOTE'].includes(id)
    );
  }).length;
}

function countBodyishSlots(slots) {
  return (slots || []).filter((s) => {
    const role = String(s.role || '').toLowerCase();
    const id = String(s.id || '').toLowerCase();
    if (['subheading', 'body', 'bullet', 'caption', 'stat', 'cta', 'quote'].includes(role)) return true;
    return /subtitle|body|bullet|card_|col_|item_/.test(id);
  }).length;
}

function hasPricingPlanSlots(slots) {
  return (slots || []).some((s) => /^plan_\d+_/i.test(String(s.id || '')));
}

function countPlanLabelSlots(slots) {
  return (slots || []).filter((s) => /^plan_\d+_(label|name)$/i.test(String(s.id || ''))).length;
}

function isPricingLayoutSchema(layoutSchema) {
  const ct = String(layoutSchema?.content_type || '').toLowerCase();
  const layoutId = String(layoutSchema?.layout_id || layoutSchema?.layoutId || '');
  return ct === 'pricing' || /^pricing_/.test(layoutId) || hasPricingPlanSlots(layoutSchema?.slots);
}

function planEntryIsWeak(plan) {
  if (!plan || typeof plan !== 'object') return true;
  if (isWeakText(plan.label) && isWeakText(plan.name)) return true;
  if (isWeakText(plan.price)) return true;
  const items = Array.isArray(plan.items) ? plan.items : [];
  if (!items.some((item) => !isWeakText(typeof item === 'string' ? item : item?.text))) return true;
  return false;
}

function seedPlansFromOutline(outlineSlide = {}) {
  const beats = beatItems(outlineSlide.beats);
  if (beats.length >= 2) {
    return beats.slice(0, 4).map((b, i) => {
      const body = String(b.body || '').trim();
      const priceMatch = body.match(/\$[\d,.]+(?:\s*\/\s*(?:mo|yr|month|year))?/i);
      return {
        label: b.title || `Tier ${i + 1}`,
        price: priceMatch ? priceMatch[0] : '',
        period: body.includes('/mo') ? '/mo' : body.includes('/yr') ? '/yr' : '',
        items: body && !priceMatch ? [body] : [`Includes ${b.title || `tier ${i + 1}`} benefits`],
        highlighted: i === 1,
      };
    });
  }
  return [
    { label: 'Starter', price: '$29', period: '/mo', items: ['Core access', 'Community support'] },
    {
      label: 'Pro',
      price: '$59',
      period: '/mo',
      items: ['Everything in Starter', 'Priority support'],
      highlighted: true,
    },
    { label: 'Enterprise', price: 'Custom', items: ['Dedicated success', 'Custom SLA'] },
  ];
}

function contentMissingPricingPlans(content, layoutSchema = null) {
  if (!isPricingLayoutSchema(layoutSchema)) return false;
  const minPlans = Math.max(2, countPlanLabelSlots(layoutSchema?.slots) || 3);
  const plans = Array.isArray(content?.plans)
    ? content.plans
    : Array.isArray(content?.pricing?.tiers)
      ? content.pricing.tiers
      : [];
  const valid = plans.filter((p) => !planEntryIsWeak(p));
  return valid.length < Math.min(minPlans, 3);
}

function compiledHasWeakPricingElements(elementsDoc, layoutSchema = null) {
  if (!isPricingLayoutSchema(layoutSchema)) return false;
  const elements = Array.isArray(elementsDoc?.elements) ? elementsDoc.elements : [];
  const bySlot = new Map();
  for (const el of elements) {
    if (el.type !== 'text' && el.type !== 'textbox') continue;
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (!/^PLAN_\d+_/.test(sid)) continue;
    bySlot.set(sid, el);
  }
  if (!bySlot.size) return false;

  for (let n = 1; n <= 6; n += 1) {
    const labelKey = bySlot.has(`PLAN_${n}_LABEL`)
      ? `PLAN_${n}_LABEL`
      : bySlot.has(`PLAN_${n}_NAME`)
        ? `PLAN_${n}_NAME`
        : null;
    const priceKey = bySlot.has(`PLAN_${n}_PRICE`) ? `PLAN_${n}_PRICE` : null;
    if (!labelKey && !priceKey) {
      if (![...bySlot.keys()].some((k) => k.startsWith(`PLAN_${n}_`))) continue;
    }
    if (labelKey && isWeakText(bySlot.get(labelKey)?.content?.text)) return true;
    if (priceKey && isWeakText(bySlot.get(priceKey)?.content?.text)) return true;
    const itemKeys = [...bySlot.keys()]
      .filter((k) => k.startsWith(`PLAN_${n}_ITEM_`))
      .sort();
    if (itemKeys.length) {
      const anyItem = itemKeys.some((k) => !isWeakText(bySlot.get(k)?.content?.text));
      if (!anyItem) return true;
    }
  }
  return false;
}

function mergeSeedIntoContent(content, seed, layoutSchema = null) {
  const next = content && typeof content === 'object' ? { ...content } : {};
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const seedObj = seed && typeof seed === 'object' ? seed : {};

  if (isWeakText(next.title) && seedObj.title) next.title = seedObj.title;
  if (isWeakText(next.subtitle) && seedObj.subtitle) next.subtitle = seedObj.subtitle;
  if (isWeakText(next.body) && seedObj.body) next.body = seedObj.body;

  const colSlots = slots.filter((s) => /^(card|col)_\d+_(title|body)$/i.test(String(s.id || '')));
  const minCols =
    slots.filter((s) => /^card_\d+_title$/i.test(String(s.id || ''))).length ||
    slots.filter((s) => /^col_\d+_title$/i.test(String(s.id || ''))).length;
  if (minCols > 0) {
    const cols = Array.isArray(next.columns) ? next.columns.slice() : [];
    const valid = cols.filter((col) => !isWeakText(col?.body ?? col?.text ?? col?.title));
    if (valid.length < minCols && Array.isArray(seedObj.columns) && seedObj.columns.length) {
      next.columns = seedObj.columns.slice(0, Math.max(minCols, seedObj.columns.length));
    }
  } else if (colSlots.length && (!Array.isArray(next.columns) || next.columns.length === 0) && seedObj.columns?.length) {
    next.columns = seedObj.columns;
  }

  const bulletSlots = slots.filter(
    (s) => /^bullet_\d+$/i.test(String(s.id || '')) || /^body_\d+$/i.test(String(s.id || ''))
  );
  if (bulletSlots.length) {
    const bullets = Array.isArray(next.bullets) ? next.bullets : [];
    const valid = bullets.filter((b) => {
      const t = typeof b === 'string' ? b : b?.text || '';
      return !isWeakText(t);
    });
    if (valid.length < Math.min(bulletSlots.length, 2) && seedObj.bullets?.length) {
      next.bullets = seedObj.bullets.slice(0, bulletSlots.length);
    }
  } else if ((!Array.isArray(next.bullets) || next.bullets.length === 0) && seedObj.bullets?.length) {
    next.bullets = seedObj.bullets;
  }

  const isTitle =
    String(layoutSchema?.content_type || '').toLowerCase() === 'title' ||
    /^title_/.test(String(layoutSchema?.layout_id || ''));
  const runs = Array.isArray(next.titleRuns) ? next.titleRuns.filter((r) => !isWeakText(r?.text)) : [];
  if (isTitle && runs.length < 2 && seedObj.title) {
    const lead = seedObj.title.endsWith('\n') ? seedObj.title : `${seedObj.title}\n`;
    next.titleRuns = seedObj.subtitle
      ? [
          { text: lead, colorRole: 'textOnImage' },
          { text: seedObj.subtitle, colorRole: 'accent', fontWeight: 700 },
        ]
      : [
          { text: seedObj.title, colorRole: 'textOnImage' },
        ];
    if (!next.title) next.title = seedObj.title;
    if (!next.subtitle && seedObj.subtitle) next.subtitle = seedObj.subtitle;
  }

  if (seedObj.visual && !next.imagePrompt && !next.visual) {
    next.visual = seedObj.visual;
  }

  if (isPricingLayoutSchema(layoutSchema)) {
    const plans = Array.isArray(next.plans) ? next.plans.slice() : [];
    const validPlans = plans.filter((p) => !planEntryIsWeak(p));
    const minPlans = Math.max(2, countPlanLabelSlots(slots) || 3);
    if (validPlans.length < minPlans) {
      const seeded =
        Array.isArray(seedObj.plans) && seedObj.plans.length
          ? seedObj.plans
          : seedPlansFromOutline(seedObj.outlineSlide || seedObj);
      next.plans = seeded.slice(0, Math.max(minPlans, seeded.length));
    } else if (validPlans.length) {
      next.plans = validPlans;
    }
  }

  return next;
}

function contentMissingRequiredCopy(content, layoutSchema = null) {
  if (contentMissingPricingPlans(content, layoutSchema)) return true;
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  if (!slots.length) return isWeakText(content?.title);
  const headings = countHeadingSlots(slots);
  const bodyish = countBodyishSlots(slots);
  if (headings && isWeakText(content?.title)) return true;
  if (slots.some((s) => String(s.role || '').toLowerCase() === 'subheading') && isWeakText(content?.subtitle) && isWeakText(content?.body)) {
    return true;
  }
  if (headings + bodyish >= 2) {
    const hasSecond =
      !isWeakText(content?.subtitle) ||
      !isWeakText(content?.body) ||
      (Array.isArray(content?.bullets) && content.bullets.some((b) => !isWeakText(typeof b === 'string' ? b : b?.text))) ||
      (Array.isArray(content?.columns) &&
        content.columns.filter((c) => !isWeakText(c?.body ?? c?.text ?? c?.title)).length >= 2);
    if (!hasSecond) return true;
  }
  return false;
}

module.exports = {
  isWeakText,
  beatItems,
  seedFromOutlineSlide,
  seedPlansFromOutline,
  mergeSeedIntoContent,
  contentMissingRequiredCopy,
  contentMissingPricingPlans,
  compiledHasWeakPricingElements,
  isPricingLayoutSchema,
  countHeadingSlots,
  countBodyishSlots,
  hasPricingPlanSlots,
};
