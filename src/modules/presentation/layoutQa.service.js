function countWords(text) {
  if (text == null) return 0;
  const s = String(text).trim();
  if (!s) return 0;
  return s.split(/\s+/).filter(Boolean).length;
}

function truncateToWords(text, maxWords) {
  const raw = String(text ?? '');
  const words = raw.trim().split(/\s+/).filter(Boolean);
  if (words.length <= maxWords) return raw;
  return words.slice(0, maxWords).join(' ');
}

function truncateToLines(text, maxLines) {
  const raw = String(text ?? '');
  if (maxLines <= 0) return '';
  const lines = raw.split(/\r?\n/);
  if (lines.length <= maxLines) {
    // Approximate line length (~12 words/line) when single-line overflow
    const approxWords = maxLines * 12;
    if (countWords(raw) > approxWords) {
      return truncateToWords(raw, approxWords);
    }
    return raw;
  }
  return lines.slice(0, maxLines).join('\n');
}

function cloneContent(content) {
  if (!content || typeof content !== 'object') return {};
  return JSON.parse(JSON.stringify(content));
}

function layoutNeedsAgendaColumns(slots) {
  return slots.some((slot) => /^agenda_col_\d+_heading$/i.test(String(slot.id || '')));
}

function layoutNeedsStructuredColumns(slots) {
  return slots.some((slot) => /^(card|col)_\d+_(title|body)$/i.test(String(slot.id || '')));
}

function layoutNeedsIndexedColumns(slots) {
  return slots.some((slot) => /^body_\d+$/i.test(String(slot.id || '')) || /^bullet_\d+$/i.test(String(slot.id || '')));
}

function layoutNeedsChart(layoutSchema, slots) {
  const ct = String(layoutSchema?.content_type || '').toLowerCase();
  return ct === 'chart' || slots.some((slot) => String(slot.role || '').toLowerCase() === 'chart');
}

function countStructuredColumnSlots(slots) {
  const cardTitles = slots.filter((s) => /^card_\d+_title$/i.test(String(s.id || ''))).length;
  const bodySlots = slots.filter((s) => /^body_\d+$/i.test(String(s.id || ''))).length;
  const bulletSlots = slots.filter((s) => /^bullet_\d+$/i.test(String(s.id || ''))).length;
  return Math.max(cardTitles, bodySlots, bulletSlots, 0);
}

function normalizeChartSeries(chart) {
  if (!chart || typeof chart !== 'object') return { labels: [], values: [] };
  const labels = Array.isArray(chart.labels) ? chart.labels.filter(Boolean) : [];
  let values = [];
  if (Array.isArray(chart.series) && chart.series.length) {
    const first = chart.series[0];
    if (Array.isArray(first?.values)) values = first.values;
    else if (Array.isArray(first?.data)) values = first.data;
  } else if (Array.isArray(chart.data)) {
    values = chart.data;
  }
  return { labels, values };
}

const PLACEHOLDER_CTA_RE = /\b(book a demo|schedule a demo|get started today)\b/i;

function layoutNeedsComparison(slots) {
  return slots.some(
    (s) => /^(left|right)_/i.test(String(s.id || '')) || /^(pros|cons)$/i.test(String(s.id || ''))
  );
}

function validateStructuredFields(content, layoutSchema, issues) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  if (!slots.length) return;

  if (layoutNeedsAgendaColumns(slots)) {
    const cols = content?.agenda?.columns;
    const valid =
      Array.isArray(cols) &&
      cols.length >= 2 &&
      cols.some((col) => String(col?.heading ?? col?.title ?? '').trim()) &&
      cols.some((col) => Array.isArray(col?.items) && col.items.some((item) => String(item ?? '').trim()));
    if (!valid) {
      issues.push({ path: 'agenda.columns', rule: 'required_structured', repairable: true });
    }
  }

  if (layoutNeedsStructuredColumns(slots) || layoutNeedsIndexedColumns(slots)) {
    const cols = content?.columns || content?.cards || content?.features;
    const minCols = Math.max(2, countStructuredColumnSlots(slots) || 2);
    const valid =
      Array.isArray(cols) &&
      cols.length >= minCols &&
      cols.filter((col) => String(col?.title ?? col?.heading ?? col?.body ?? col?.text ?? '').trim())
        .length >= minCols;
    if (!valid) {
      issues.push({ path: 'columns', rule: 'required_structured', repairable: true });
    } else {
      const titles = cols
        .map((col) => String(col?.title ?? col?.heading ?? col?.label ?? '').trim().toLowerCase())
        .filter(Boolean);
      const uniqueTitles = new Set(titles);
      if (titles.length >= 2 && uniqueTitles.size < Math.min(titles.length, minCols)) {
        issues.push({ path: 'columns', rule: 'distinct_titles', repairable: true });
      }
    }
  }

  if (layoutNeedsChart(layoutSchema, slots)) {
    const { labels, values } = normalizeChartSeries(content?.chart);
    const numericValues = values.filter((v) => v != null && v !== '' && !Number.isNaN(Number(v)));
    const valid =
      labels.length >= 3 &&
      numericValues.length >= 3 &&
      numericValues.length === labels.length;
    if (!valid) {
      issues.push({ path: 'chart', rule: 'required_chart_data', repairable: true });
    }
  }

  const ct = String(layoutSchema?.content_type || '').toLowerCase();
  if (ct === 'closing' || slots.some((s) => String(s.role || '').toLowerCase() === 'cta')) {
    const ctaText = String(content?.cta ?? content?.callToAction ?? content?.buttonText ?? '').trim();
    if (ctaText && PLACEHOLDER_CTA_RE.test(ctaText)) {
      issues.push({ path: 'cta', rule: 'placeholder_cta', repairable: true });
    }
  }

  if (layoutNeedsComparison(slots)) {
    const hasSideBySide =
      (content?.left?.title || content?.comparison?.left?.title) &&
      (content?.right?.title || content?.comparison?.right?.title);
    const hasProsCons =
      (Array.isArray(content?.pros) && content.pros.length) ||
      (Array.isArray(content?.cons) && content.cons.length);
    if (!hasSideBySide && !hasProsCons) {
      issues.push({ path: 'comparison', rule: 'required_structured', repairable: true });
    }
  }

  const layoutId = String(layoutSchema?.layout_id || '');
  if (/timeline/i.test(layoutId) || slots.some((s) => /^milestone_/i.test(String(s.id || '')))) {
    const milestones = content?.timeline || content?.milestones || content?.events;
    const valid = Array.isArray(milestones) && milestones.filter(Boolean).length >= 2;
    if (!valid) {
      issues.push({ path: 'timeline', rule: 'required_structured', repairable: true });
    }
  }
}

function slotFieldMap(slotId) {
  const id = String(slotId || '').toLowerCase();
  if (id === 'title' || id.endsWith('_title') || id === 'left_title' || id === 'right_title') {
    return { kind: 'string', key: id === 'title' ? 'title' : id };
  }
  if (id === 'subtitle') return { kind: 'string', key: 'subtitle' };
  if (id === 'body' || id === 'left_body' || id === 'right_body') {
    return { kind: id.includes('body') && id !== 'body' ? 'arrayOrString' : 'string', key: id === 'body' ? 'body' : id };
  }
  if (id === 'bullets' || id === 'bullets_left' || id === 'bullets_right') {
    return { kind: 'bullets', key: id === 'bullets' ? 'bullets' : id };
  }
  if (id === 'quote') return { kind: 'string', key: 'quote' };
  if (id === 'pros' || id === 'cons') return { kind: 'bullets', key: id };
  if (id.startsWith('card_') || id.startsWith('stat_')) {
    return { kind: 'string', key: id };
  }
  return { kind: 'string', key: id };
}

function applyStringLimits(value, slot, issues, path) {
  let next = value == null ? value : String(value);
  if (next == null) return next;

  if (slot.max_lines != null) {
    const maxLines = Math.max(0, Number(slot.max_lines) || 0);
    const before = next;
    next = truncateToLines(next, maxLines);
    if (next !== before) {
      issues.push({ path, rule: 'max_lines', max: maxLines, truncated: true });
    }
  }

  if (slot.max_words != null) {
    const maxWords = Math.max(0, Number(slot.max_words) || 0);
    const before = next;
    next = truncateToWords(next, maxWords);
    if (next !== before) {
      issues.push({ path, rule: 'max_words', max: maxWords, truncated: true });
    }
  }

  return next;
}

function applyBulletLimits(items, slot, issues, path) {
  let list = Array.isArray(items) ? items.slice() : [];
  const maxItems = slot.max_items != null ? Math.max(0, Number(slot.max_items) || 0) : null;
  const maxWords = slot.max_words != null ? Math.max(0, Number(slot.max_words) || 0) : null;

  if (maxItems != null && list.length > maxItems) {
    list = list.slice(0, maxItems);
    issues.push({ path, rule: 'max_items', max: maxItems, truncated: true });
  }

  if (maxWords != null) {
    list = list.map((item, idx) => {
      if (typeof item === 'string') {
        const next = truncateToWords(item, maxWords);
        if (next !== item) {
          issues.push({ path: `${path}[${idx}]`, rule: 'max_words', max: maxWords, truncated: true });
        }
        return next;
      }
      if (item && typeof item === 'object' && item.text != null) {
        const nextText = truncateToWords(item.text, maxWords);
        if (nextText !== item.text) {
          issues.push({
            path: `${path}[${idx}].text`,
            rule: 'max_words',
            max: maxWords,
            truncated: true,
          });
        }
        return { ...item, text: nextText };
      }
      return item;
    });
  }

  return list;
}

/**
 * Validate / truncate slide content against layout schema slot caps.
 * @returns {{ content: object, issues: Array<object> }}
 */
function validateSlide({ content, layoutSchema }) {
  const issues = [];
  const next = cloneContent(content);
  const schema = layoutSchema && typeof layoutSchema === 'object' ? layoutSchema : {};
  const slots = Array.isArray(schema.slots) ? schema.slots : [];

  // Default soft caps when schema has no slots
  if (slots.length === 0) {
    if (next.title != null) {
      next.title = applyStringLimits(next.title, { max_lines: 3, max_words: 16 }, issues, 'title');
    }
    if (Array.isArray(next.bullets) && next.bullets.length > 8) {
      next.bullets = next.bullets.slice(0, 8);
      issues.push({ path: 'bullets', rule: 'max_items', max: 8, truncated: true });
    }
    return { content: next, issues };
  }

  for (const slot of slots) {
    const mapping = slotFieldMap(slot.id);
    const key = mapping.key;

    if (mapping.kind === 'bullets') {
      const source =
        key === 'bullets'
          ? next.bullets
          : next[key] != null
            ? next[key]
            : key === 'bullets_left' || key === 'bullets_right'
              ? next.bullets
              : next[key];

      if (source == null && key !== 'bullets') continue;

      if (key === 'bullets' || next[key] != null) {
        next[key === 'bullets' ? 'bullets' : key] = applyBulletLimits(
          key === 'bullets' ? next.bullets : next[key],
          slot,
          issues,
          key === 'bullets' ? 'bullets' : key
        );
      } else if ((key === 'bullets_left' || key === 'bullets_right') && Array.isArray(next.bullets)) {
        // Leave shared bullets; layout render can split. Still enforce soft word caps on all.
        next.bullets = applyBulletLimits(next.bullets, slot, issues, 'bullets');
      }
      continue;
    }

    if (mapping.kind === 'arrayOrString') {
      if (Array.isArray(next[key])) {
        next[key] = applyBulletLimits(next[key], slot, issues, key);
      } else if (next[key] != null) {
        next[key] = applyStringLimits(next[key], slot, issues, key);
      } else if (key === 'body' || key === 'left_body' || key === 'right_body') {
        // Map common content.body through body slot
        if (key === 'body' && next.body != null) {
          next.body = applyStringLimits(next.body, slot, issues, 'body');
        }
      }
      continue;
    }

    // Prefer well-known content keys for standard slots
    let targetKey = key;
    if (slot.id === 'title' && next.title != null) targetKey = 'title';
    if (slot.id === 'subtitle' && next.subtitle != null) targetKey = 'subtitle';
    if (slot.id === 'body' && next.body != null) targetKey = 'body';
    if (slot.id === 'quote' && next.quote != null) targetKey = 'quote';

    if (next[targetKey] != null && (typeof next[targetKey] === 'string' || typeof next[targetKey] === 'number')) {
      next[targetKey] = applyStringLimits(next[targetKey], slot, issues, targetKey);
    }
  }

  validateStructuredFields(next, schema, issues);

  return { content: next, issues };
}

module.exports = {
  validateSlide,
  truncateToWords,
  truncateToLines,
  countWords,
};
