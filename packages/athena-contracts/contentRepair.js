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

function sliceToMax(arr, target, repairs, path) {
  const out = Array.isArray(arr) ? [...arr] : [];
  const beforeLen = out.length;
  if (beforeLen > target) {
    const sliced = out.slice(0, target);
    pushRepair(repairs, path, 'slice_clamp', beforeLen, sliced.length);
    return sliced;
  }
  return out;
}

function coercePlanItem(item, index, itemCount = 0) {
  if (item == null || typeof item !== 'object') {
    const items =
      itemCount > 0 ? Array.from({ length: itemCount }, () => '') : [];
    return { label: '', price: '—', items, cta: '' };
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
  if (itemCount > 0 && items.length > itemCount) {
    items.splice(itemCount);
  }
  return {
    label: String(item.label ?? item.name ?? item.title ?? '').trim(),
    price: String(item.price ?? item.amount ?? '—').trim(),
    period: item.period != null ? String(item.period).trim() : undefined,
    cta: String(item.cta ?? item.button ?? item.callToAction ?? '').trim(),
    items,
    body: item.body != null ? String(item.body).trim() : undefined,
    storage: item.storage != null ? String(item.storage).trim() : undefined,
  };
}

function coerceColumnItem(item) {
  if (item == null) {
    return { title: '', body: '' };
  }
  if (typeof item === 'string') {
    const text = item.trim();
    const split = text.split(/[:\-—–]\s*/);
    return {
      title: split[0]?.trim() || '',
      body: split.slice(1).join(' ').trim() || text,
    };
  }
  if (typeof item === 'object') {
    return {
      title: String(item.title ?? item.heading ?? item.label ?? '').trim(),
      body: String(item.body ?? item.text ?? item.description ?? '').trim(),
    };
  }
  return { title: '', body: String(item) };
}

/**
 * Canonicalize aliases and slice overflowing groups (no synthetic underfill padding).
 */
function clampRepeatingGroups(content, contract, repairs = []) {
  if (!content || typeof content !== 'object') return {};
  const next = { ...content };

  if (contract.groups.columns > 0) {
    let source =
      Array.isArray(next.columns) ? next.columns
        : Array.isArray(next.cards) ? next.cards
          : Array.isArray(next.features) ? next.features
            : [];
    const beforeLen = source.length;
    source = source.map((item) => coerceColumnItem(item));
    source = sliceToMax(source, contract.groups.columns, repairs, 'columns');
    if (beforeLen !== source.length || !Array.isArray(next.columns)) {
      if (beforeLen === source.length && !Array.isArray(next.columns)) {
        pushRepair(repairs, 'columns', 'coerce_empty', beforeLen, source.length);
      }
    }
    next.columns = source;
  }

  if (contract.groups.stats > 0) {
    let stats = Array.isArray(next.stats) ? [...next.stats] : [];
    const beforeLen = stats.length;
    stats = stats.map((stat) => {
      if (typeof stat === 'string') {
        return { value: stat.trim(), label: '' };
      }
      if (typeof stat !== 'object' || !stat) {
        return { value: '—', label: '' };
      }
      return {
        value: stat.value != null ? String(stat.value) : '—',
        label: String(stat.label ?? stat.name ?? '').trim(),
      };
    });
    stats = sliceToMax(stats, contract.groups.stats, repairs, 'stats');
    if (beforeLen !== stats.length) {
      /* slice_clamp repair already recorded */
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
    members = members.map((m) => {
      if (typeof m === 'string') {
        return { name: m.trim(), role: '', bio: '' };
      }
      if (typeof m !== 'object' || !m) {
        return { name: '', role: '', bio: '' };
      }
      return {
        name: String(m.name ?? m.title ?? '').trim(),
        role: String(m.role ?? m.title ?? '').trim(),
        bio: String(m.bio ?? m.body ?? m.description ?? '').trim(),
      };
    });
    members = sliceToMax(members, contract.groups.members, repairs, 'members');
    if (beforeLen !== members.length) {
      /* slice_clamp */
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
    timeline = timeline.map((item) => {
      if (typeof item === 'string') {
        return { label: item.trim(), detail: '' };
      }
      if (typeof item !== 'object' || !item) {
        return { label: '', detail: '' };
      }
      return {
        label: String(item.label ?? item.date ?? item.year ?? item.title ?? '').trim(),
        detail: String(item.detail ?? item.body ?? item.text ?? '').trim(),
      };
    });
    timeline = sliceToMax(timeline, contract.groups.timeline, repairs, 'timeline');
    if (beforeLen !== timeline.length) {
      /* slice_clamp */
    }
    next.timeline = timeline;
  }

  const diagramLimit = Math.max(contract.groups.steps, contract.groups.quadrants, contract.groups.funnel);
  if (diagramLimit > 0) {
    let cells =
      next.diagram?.cells || next.cells || next.steps || next.quadrants || next.funnel;
    if (!Array.isArray(cells)) cells = [];
    const beforeLen = cells.length;
    cells = cells.map((cell) => {
      if (typeof cell === 'string') {
        return { title: '', body: cell.trim() };
      }
      if (typeof cell !== 'object' || !cell) {
        return { title: '', body: '' };
      }
      return {
        title: String(cell.title ?? cell.label ?? cell.heading ?? '').trim(),
        body: String(cell.body ?? cell.text ?? cell.detail ?? '').trim(),
      };
    });
    cells = sliceToMax(cells, diagramLimit, repairs, 'diagram.cells');
    if (beforeLen !== cells.length) {
      /* slice_clamp */
    }
    if (contract.groups.steps > 0) next.steps = cells;
    if (contract.groups.quadrants > 0) next.quadrants = cells;
    if (contract.groups.funnel > 0) next.funnel = cells;
    next.diagram = { ...(next.diagram || {}), cells };
  }

  if (contract.groups.bullets > 0) {
    let bullets = Array.isArray(next.bullets) ? [...next.bullets] : [];
    const beforeLen = bullets.length;
    bullets = sliceToMax(bullets, contract.groups.bullets, repairs, 'bullets');
    if (beforeLen !== bullets.length) {
      /* slice_clamp */
    }
    next.bullets = bullets;
  }

  if (contract.groups.items > 0) {
    let items = Array.isArray(next.items) ? [...next.items] : [];
    const beforeLen = items.length;
    items = sliceToMax(items, contract.groups.items, repairs, 'items');
    if (beforeLen !== items.length) {
      /* slice_clamp */
    }
    next.items = items;
  }

  if (contract.groups.quotes > 0) {
    let quotes =
      Array.isArray(next.quotes) ? next.quotes
        : Array.isArray(next.testimonials) ? next.testimonials
          : [];
    const beforeLen = quotes.length;
    quotes = sliceToMax(quotes, contract.groups.quotes, repairs, 'quotes');
    if (beforeLen !== quotes.length) {
      /* slice_clamp */
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
    plans = plans.map((plan, i) => coercePlanItem(plan, i, itemCount));
    plans = sliceToMax(plans, contract.groups.plans, repairs, 'plans');
    if (beforeLen !== plans.length || !Array.isArray(next.plans)) {
      if (beforeLen === plans.length && !Array.isArray(next.plans)) {
        pushRepair(repairs, 'plans', 'coerce_empty', beforeLen, plans.length);
      }
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
    features = sliceToMax(features, contract.groups.pricingFeatures, repairs, 'features');
    if (beforeLen !== features.length) {
      /* slice_clamp */
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
  if (!options.skipClampRepeatingGroups) {
    next = clampRepeatingGroups(next, contract, repairs);
  }
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
