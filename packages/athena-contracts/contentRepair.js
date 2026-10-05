'use strict';

const deriveContentContract = require('./contentContract.js').deriveContentContract;
const normalizeContentForLayout = require('./contentContract.js').normalizeContentForLayout;
const { clampSlotText } = require('./textNormalize.js');
const { textForSlot, coerceSlotText } = require('./slotText.js');

const REPAIR_PREVIEW_MAX = 120;

function previewValue(v) {
  if (v == null) return v;
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  if (s.length <= REPAIR_PREVIEW_MAX) return s;
  return `${s.slice(0, REPAIR_PREVIEW_MAX)}…`;
}

function pushRepair(repairs, path, action, before, after) {
  repairs.push({
    path,
    action,
    before: previewValue(before),
    after: previewValue(after),
  });
}

function contextPhrase(content) {
  const t = String(content?.title || content?.subtitle || 'Topic').trim();
  return t || 'Topic';
}

function coercePlanItem(item, index, ctx, itemCount = 0) {
  if (item == null || typeof item !== 'object') {
    const label = `Plan ${index + 1}`;
    const items =
      itemCount > 0
        ? Array.from({ length: itemCount }, (_, i) => `Included benefit ${i + 1}`)
        : [`Core value for ${ctx}.`];
    return { label, price: '—', items, cta: 'Get started' };
  }
  const items = Array.isArray(item.items)
    ? [...item.items]
    : Array.isArray(item.bullets)
      ? [...item.bullets]
      : Array.isArray(item.features)
        ? [...item.features]
        : item.body
          ? [String(item.body)]
          : [];
  if (itemCount > 0) {
    while (items.length < itemCount) {
      items.push(`Included benefit ${items.length + 1}`);
    }
    items.splice(itemCount);
  }
  return {
    label: String(item.label ?? item.name ?? item.title ?? `Plan ${index + 1}`).trim(),
    price: String(item.price ?? item.amount ?? '—').trim(),
    period: item.period != null ? String(item.period).trim() : undefined,
    cta: String(item.cta ?? item.button ?? item.callToAction ?? 'Get started').trim(),
    items,
    body: item.body != null ? String(item.body).trim() : undefined,
    storage: item.storage != null ? String(item.storage).trim() : undefined,
  };
}

function coerceColumnItem(item, index, ctx) {
  if (item == null) {
    return {
      title: `Focus area ${index + 1}`,
      body: `Supporting detail for ${ctx}.`,
    };
  }
  if (typeof item === 'string') {
    const text = item.trim();
    const split = text.split(/[:\-—–]\s*/);
    return {
      title: split[0]?.trim() || `Focus area ${index + 1}`,
      body: split.slice(1).join(' ').trim() || text || `Detail for ${ctx}.`,
    };
  }
  if (typeof item === 'object') {
    return {
      title: String(item.title ?? item.heading ?? item.label ?? `Focus area ${index + 1}`).trim(),
      body: String(item.body ?? item.text ?? item.description ?? '').trim(),
    };
  }
  return { title: `Focus area ${index + 1}`, body: String(item) };
}

function padArray(arr, target, factory) {
  const out = Array.isArray(arr) ? [...arr] : [];
  while (out.length < target) {
    out.push(factory(out.length));
  }
  return out.slice(0, target);
}

/**
 * Canonicalize aliases and pad/slice repeating groups to exact contract counts.
 */
function clampRepeatingGroups(content, contract, repairs = []) {
  if (!content || typeof content !== 'object') return {};
  const next = { ...content };
  const ctx = contextPhrase(next);

  if (contract.groups.columns > 0) {
    let source =
      Array.isArray(next.columns) ? next.columns
        : Array.isArray(next.cards) ? next.cards
          : Array.isArray(next.features) ? next.features
            : [];
    const beforeLen = source.length;
    source = source.map((item, i) => coerceColumnItem(item, i, ctx));
    source = padArray(source, contract.groups.columns, (i) => ({
      title: `Focus area ${i + 1}`,
      body: `Key point about ${ctx}.`,
    }));
    if (beforeLen !== source.length || !Array.isArray(next.columns)) {
      pushRepair(repairs, 'columns', 'pad_clamp', beforeLen, source.length);
    }
    next.columns = source;
  }

  if (contract.groups.stats > 0) {
    let stats = Array.isArray(next.stats) ? [...next.stats] : [];
    const beforeLen = stats.length;
    stats = padArray(stats, contract.groups.stats, (i) => ({
      value: '—',
      label: `Metric ${i + 1}`,
    })).map((stat, i) => {
      if (typeof stat === 'string') {
        return { value: stat.trim(), label: `Metric ${i + 1}` };
      }
      if (typeof stat !== 'object' || !stat) {
        return { value: '—', label: `Metric ${i + 1}` };
      }
      return {
        value: stat.value != null ? String(stat.value) : '—',
        label: String(stat.label ?? stat.name ?? `Metric ${i + 1}`).trim(),
      };
    });
    if (beforeLen !== stats.length) {
      pushRepair(repairs, 'stats', 'pad_clamp', beforeLen, stats.length);
    }
    next.stats = stats;
  }

  if (contract.groups.members > 0) {
    let members =
      Array.isArray(next.members) ? next.members
        : Array.isArray(next.team) ? next.team
          : Array.isArray(next.people) ? next.people
            : [];
    const beforeLen = members.length;
    members = padArray(members, contract.groups.members, (i) => ({
      name: `Team member ${i + 1}`,
      role: 'Role',
      bio: `Contributor on ${ctx}.`,
    })).map((m, i) => {
      if (typeof m === 'string') {
        return { name: m.trim() || `Team member ${i + 1}`, role: 'Role', bio: '' };
      }
      if (typeof m !== 'object' || !m) {
        return { name: `Team member ${i + 1}`, role: 'Role', bio: '' };
      }
      return {
        name: String(m.name ?? m.title ?? `Team member ${i + 1}`).trim(),
        role: String(m.role ?? m.title ?? 'Role').trim(),
        bio: String(m.bio ?? m.body ?? m.description ?? '').trim(),
      };
    });
    if (beforeLen !== members.length) {
      pushRepair(repairs, 'members', 'pad_clamp', beforeLen, members.length);
    }
    next.members = members;
  }

  if (contract.groups.timeline > 0) {
    let timeline =
      Array.isArray(next.timeline) ? next.timeline
        : Array.isArray(next.milestones) ? next.milestones
          : Array.isArray(next.events) ? next.events
            : [];
    const beforeLen = timeline.length;
    timeline = padArray(timeline, contract.groups.timeline, (i) => ({
      label: String(2020 + i * 2),
      detail: `Milestone for ${ctx}.`,
    })).map((item, i) => {
      if (typeof item === 'string') {
        return { label: item.trim() || `Phase ${i + 1}`, detail: `Detail for ${ctx}.` };
      }
      if (typeof item !== 'object' || !item) {
        return { label: `Phase ${i + 1}`, detail: `Detail for ${ctx}.` };
      }
      return {
        label: String(item.label ?? item.date ?? item.year ?? item.title ?? `Phase ${i + 1}`).trim(),
        detail: String(item.detail ?? item.body ?? item.text ?? '').trim(),
      };
    });
    if (beforeLen !== timeline.length) {
      pushRepair(repairs, 'timeline', 'pad_clamp', beforeLen, timeline.length);
    }
    next.timeline = timeline;
  }

  const diagramLimit = Math.max(contract.groups.steps, contract.groups.quadrants, contract.groups.funnel);
  if (diagramLimit > 0) {
    let cells =
      next.diagram?.cells || next.cells || next.steps || next.quadrants || next.funnel;
    if (!Array.isArray(cells)) cells = [];
    const beforeLen = cells.length;
    cells = padArray(cells, diagramLimit, (i) => ({
      title: `Step ${i + 1}`,
      body: `Stage of ${ctx}.`,
    })).map((cell, i) => {
      if (typeof cell === 'string') {
        return { title: `Step ${i + 1}`, body: cell.trim() };
      }
      if (typeof cell !== 'object' || !cell) {
        return { title: `Step ${i + 1}`, body: '' };
      }
      return {
        title: String(cell.title ?? cell.label ?? cell.heading ?? `Step ${i + 1}`).trim(),
        body: String(cell.body ?? cell.text ?? cell.detail ?? '').trim(),
      };
    });
    if (beforeLen !== cells.length) {
      pushRepair(repairs, 'diagram.cells', 'pad_clamp', beforeLen, cells.length);
    }
    if (contract.groups.steps > 0) next.steps = cells;
    if (contract.groups.quadrants > 0) next.quadrants = cells;
    if (contract.groups.funnel > 0) next.funnel = cells;
    next.diagram = { ...(next.diagram || {}), cells };
  }

  if (contract.groups.bullets > 0) {
    let bullets = Array.isArray(next.bullets) ? [...next.bullets] : [];
    const beforeLen = bullets.length;
    bullets = padArray(bullets, contract.groups.bullets, (i) => `Point ${i + 1} about ${ctx}`);
    if (beforeLen !== bullets.length) {
      pushRepair(repairs, 'bullets', 'pad_clamp', beforeLen, bullets.length);
    }
    next.bullets = bullets;
  }

  if (contract.groups.items > 0) {
    let items = Array.isArray(next.items) ? [...next.items] : [];
    const beforeLen = items.length;
    items = padArray(items, contract.groups.items, (i) => `Item ${i + 1}`);
    if (beforeLen !== items.length) {
      pushRepair(repairs, 'items', 'pad_clamp', beforeLen, items.length);
    }
    next.items = items;
  }

  if (contract.groups.quotes > 0) {
    let quotes =
      Array.isArray(next.quotes) ? next.quotes
        : Array.isArray(next.testimonials) ? next.testimonials
          : [];
    const beforeLen = quotes.length;
    quotes = padArray(quotes, contract.groups.quotes, () => ({
      text: `Insight about ${ctx}.`,
      attribution: '',
    }));
    if (beforeLen !== quotes.length) {
      pushRepair(repairs, 'quotes', 'pad_clamp', beforeLen, quotes.length);
    }
    next.quotes = quotes;
  }

  if (contract.groups.plans > 0) {
    let plans = Array.isArray(next.plans) ? [...next.plans] : [];
    if (!plans.length && next.pricing != null) {
      const pricing = next.pricing;
      if (Array.isArray(pricing)) plans = [...pricing];
      else if (typeof pricing === 'object' && Array.isArray(pricing.tiers)) plans = [...pricing.tiers];
      else if (typeof pricing === 'object' && Array.isArray(pricing.plans)) plans = [...pricing.plans];
    }
    const beforeLen = plans.length;
    const itemCount = contract.groups.planItems || 0;
    plans = padArray(plans, contract.groups.plans, (i) =>
      coercePlanItem(null, i, ctx, itemCount)
    ).map((plan, i) => coercePlanItem(plan, i, ctx, itemCount));
    if (beforeLen !== plans.length || !Array.isArray(next.plans)) {
      pushRepair(repairs, 'plans', 'pad_clamp', beforeLen, plans.length);
    }
    next.plans = plans;
  }

  if (contract.groups.pricingFeatures > 0) {
    let features = Array.isArray(next.features)
      ? [...next.features]
      : Array.isArray(next.planFeatures)
        ? [...next.planFeatures]
        : Array.isArray(next.comparison?.features)
          ? [...next.comparison.features]
          : [];
    const beforeLen = features.length;
    features = padArray(features, contract.groups.pricingFeatures, (i) => `Feature row ${i + 1}`);
    if (beforeLen !== features.length) {
      pushRepair(repairs, 'features', 'pad_clamp', beforeLen, features.length);
    }
    next.features = features;
  }

  return next;
}

function clampAllSlotText(content, schema, contract, repairs) {
  const next = { ...content };
  const slots = Array.isArray(schema?.slots) ? schema.slots : [];
  for (const slot of slots) {
    if (!slot?.id) continue;
    const limits = contract.slots[slot.id];
    if (!limits) continue;
    const raw = coerceSlotText(textForSlot(slot.id, next, schema)).trim();
    if (!raw) continue;
    const clamped = clampSlotText(raw, limits);
    if (clamped !== raw) {
      pushRepair(repairs, `slot:${slot.id}`, 'clamp_text', raw, clamped);
    }
  }
  return next;
}

function ensureTitle(content, schema, repairs) {
  const slots = Array.isArray(schema?.slots) ? schema.slots : [];
  const requiresTitle = slots.some(
    (s) =>
      String(s.role || '').toLowerCase() === 'heading' ||
      /^(MAIN_TITLE|HEADING|HEADLINE|TITLE)$/i.test(String(s.id || ''))
  );
  if (!requiresTitle) return content;
  const title = String(content?.title || '').trim();
  if (title) return content;
  const fallback = String(content?.subtitle || content?.summary || 'Slide title').trim().slice(0, 80);
  pushRepair(repairs, 'title', 'fill_missing', '', fallback);
  return { ...content, title: fallback };
}

/**
 * @returns {{ content: object, warnings: string[], repairs: object[] }}
 */
function repairContentForLayoutDetailed(content, schema, options = {}) {
  const repairs = [];
  const warnings = [];
  if (!schema || !Array.isArray(schema.slots)) {
    warnings.push('INVALID_SCHEMA');
    return { content: content && typeof content === 'object' ? content : {}, warnings, repairs };
  }

  const contract = deriveContentContract(schema);
  let next = normalizeContentForLayout(content, schema);
  next = clampRepeatingGroups(next, contract, repairs);
  next = ensureTitle(next, schema, repairs);
  next = normalizeContentForLayout(next, schema);
  next = clampAllSlotText(next, schema, contract, repairs);

  if (repairs.length) {
    warnings.push(`REPAIRED_${repairs.length}_FIELDS`);
  }

  return { content: next, warnings, repairs };
}

function repairContentForLayout(content, schema, options = {}) {
  return repairContentForLayoutDetailed(content, schema, options).content;
}

module.exports = {
  clampRepeatingGroups,
  repairContentForLayout,
  repairContentForLayoutDetailed,
};
