function countWords(text) {
  if (text == null) return 0;
  const s = String(text).trim();
  if (!s) return 0;
  return s.split(/\s+/).filter(Boolean).length;
}

const { isCatalogPlaceholderText } = require('./catalogPlaceholder');
const { isWeakText } = require('./blueprintSeed');

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
  return slots.some((slot) => {
    const id = String(slot.id || '');
    return /^body_\d+$/i.test(id) || /^bullet_\d+$/i.test(id);
  });
}

function layoutNeedsGalleryLabels(slots) {
  return slots.some((slot) => /^IMAGE_\d+_LABEL$/i.test(String(slot.id || '')));
}

function layoutNeedsDiagramCells(slots) {
  return slots.some((slot) => {
    const id = String(slot.id || '').toLowerCase();
    return /^q\d+_body$/i.test(id) || /^funnel_\d+_body$/i.test(id) || /^step_\d+_body$/i.test(id);
  });
}

function countDiagramCellSlots(slots) {
  const quadrantBodies = slots.filter((s) => /^q\d+_body$/i.test(String(s.id || ''))).length;
  const funnelBodies = slots.filter((s) => /^funnel_\d+_body$/i.test(String(s.id || ''))).length;
  const stepBodies = slots.filter((s) => /^step_\d+_body$/i.test(String(s.id || ''))).length;
  return Math.max(quadrantBodies, funnelBodies, stepBodies, 0);
}

function diagramCellsFromContent(content) {
  const cells =
    content?.diagram?.cells ||
    content?.cells ||
    content?.quadrants ||
    content?.steps ||
    content?.funnel ||
    [];
  return Array.isArray(cells) ? cells : [];
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
const PLACEHOLDER_BODY_RE =
  /supporting paragraph with three to four lines|scannable copy that explains the key idea/i;
const GENERIC_CHART_LABEL_RE = /^(q[1-4]|quarter\s*[1-4]|series\s*1|period\s*[1-4])$/i;
const PLACEHOLDER_CHART_SUBTITLE_RE = /this chart has a subtitle|chart subtitle|sample data/i;

function layoutImageSlotIds(slots) {
  return slots
    .filter((slot) => {
      const id = String(slot.id || '').toLowerCase();
      const role = String(slot.role || '').toLowerCase();
      return role === 'image' || id.includes('image');
    })
    .map((slot) => String(slot.id || ''));
}

function slideCopyCorpus(content = {}) {
  const parts = [];
  const push = (v) => {
    const s = String(v || '').trim();
    if (s) parts.push(s);
  };
  push(content.body);
  push(content.summary);
  push(content.subtitle);
  push(content.left_body);
  push(content.right_body);
  for (const col of content.columns || content.cards || content.features || content.items || []) {
    if (typeof col === 'string') push(col);
    else if (col && typeof col === 'object') {
      push(col.body);
      push(col.text);
      push(col.description);
    }
  }
  for (const b of content.bullets || []) {
    if (typeof b === 'string') push(b);
    else if (b && typeof b === 'object') push(b.text || b.body || b.description);
  }
  return parts;
}

function imagePromptEchoesCopy(prompt, content = {}) {
  const p = String(prompt || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
  if (p.length < 36) return false;
  for (const body of slideCopyCorpus(content)) {
    const normalized = String(body).toLowerCase().replace(/\s+/g, ' ').trim();
    if (normalized.length < 28) continue;
    const words = normalized.split(/\s+/).filter(Boolean);
    if (words.length < 6) continue;
    for (let i = 0; i <= words.length - 6; i += 1) {
      const ngram = words.slice(i, i + 6).join(' ');
      if (p.includes(ngram)) return true;
    }
  }
  return false;
}

function shortVisualPhrase(text, maxWords = 8) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  const beforeBreak = raw.split(/[:—–|]/)[0].trim();
  const source = beforeBreak && beforeBreak.split(/\s+/).filter(Boolean).length >= 2 ? beforeBreak : raw;
  return source.split(/\s+/).filter(Boolean).slice(0, Math.max(2, maxWords)).join(' ');
}

function visualSubjectForSlot(slotId, content = {}) {
  const id = String(slotId || '');
  const cols = content.columns || content.cards || content.features || content.items || [];
  let idx = null;
  let m = id.match(/^COL_(\d+)_IMAGE$/i);
  if (m) idx = Number(m[1]) - 1;
  m = id.match(/^(?:GRID_)?IMAGE_(\d+)$/i);
  if (m) idx = Number(m[1]) - 1;
  m = id.match(/^METRIC_IMAGE_(\d+)$/i);
  if (m) idx = Number(m[1]) - 1;
  if (idx != null && cols[idx] && typeof cols[idx] === 'object') {
    const title = String(cols[idx].title ?? cols[idx].heading ?? cols[idx].label ?? '').trim();
    if (title) return shortVisualPhrase(title, 8);
  }
  return (
    shortVisualPhrase(content.visual || content.title || content.summary || 'presentation topic', 10) ||
    'presentation topic'
  );
}

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
      const slideTitle = String(content?.title || '').trim().toLowerCase();
      if (slideTitle && titles.some((t) => t === slideTitle)) {
        issues.push({ path: 'columns', rule: 'column_title_matches_slide_title', repairable: true });
      }
    }
  }

  if (layoutNeedsGalleryLabels(slots)) {
    const cols = content?.columns || content?.cards || content?.features || content?.items;
    const labelSlots = slots.filter((s) => /^IMAGE_\d+_LABEL$/i.test(String(s.id || '')));
    const minLabels = Math.max(2, labelSlots.length);
    if (Array.isArray(cols) && cols.length >= 2) {
      const titles = cols
        .slice(0, minLabels)
        .map((col) => {
          if (typeof col === 'string') return col.trim().toLowerCase();
          return String(col?.title ?? col?.heading ?? col?.label ?? '').trim().toLowerCase();
        })
        .filter(Boolean);
      const uniqueTitles = new Set(titles);
      if (titles.length >= 2 && uniqueTitles.size < Math.min(titles.length, minLabels)) {
        issues.push({ path: 'columns', rule: 'distinct_gallery_labels', repairable: true });
      }
      const slideTitle = String(content?.title || '').trim().toLowerCase();
      if (slideTitle && titles.some((t) => t === slideTitle)) {
        issues.push({ path: 'columns', rule: 'gallery_label_matches_slide_title', repairable: true });
      }
    } else {
      issues.push({ path: 'columns', rule: 'distinct_gallery_labels', repairable: true });
    }
  }

  const imageSlotIds = layoutImageSlotIds(slots);
  if (imageSlotIds.length > 1) {
    const prompts = content?.imagePrompts && typeof content.imagePrompts === 'object' ? content.imagePrompts : {};
    const normalized = imageSlotIds
      .map((slotId) =>
        String(
          prompts[slotId] || prompts[slotId.toUpperCase()] || prompts[slotId.toLowerCase()] || ''
        ).trim()
      )
      .filter(Boolean);
    const uniquePrompts = new Set(normalized.map((p) => p.toLowerCase()));
    if (normalized.length >= 2 && uniquePrompts.size < normalized.length) {
      issues.push({ path: 'imagePrompts', rule: 'duplicate_image_prompts', repairable: true });
    }

    if (content?.slotImageUrls && typeof content.slotImageUrls === 'object') {
      const seen = new Map();
      for (const slotId of imageSlotIds) {
        const url = content.slotImageUrls[slotId];
        if (!url) continue;
        if (seen.has(url)) {
          issues.push({ path: 'slotImageUrls', rule: 'duplicate_slot_image_urls', repairable: true });
          break;
        }
        seen.set(url, slotId);
      }
    }
  }

  if (imageSlotIds.length >= 1) {
    const prompts =
      content?.imagePrompts && typeof content.imagePrompts === 'object' ? { ...content.imagePrompts } : {};
    let rewritten = false;
    for (const slotId of imageSlotIds) {
      const key =
        (prompts[slotId] != null && slotId) ||
        (prompts[slotId.toUpperCase()] != null && slotId.toUpperCase()) ||
        (prompts[String(slotId).toLowerCase()] != null && String(slotId).toLowerCase()) ||
        null;
      if (!key) continue;
      const prompt = String(prompts[key] || '').trim();
      if (!prompt || !imagePromptEchoesCopy(prompt, content)) continue;
      issues.push({ path: `imagePrompts.${key}`, rule: 'image_prompt_echoes_copy', repairable: true });
      prompts[key] = visualSubjectForSlot(slotId, content);
      rewritten = true;
    }
    if (rewritten && content && typeof content === 'object') {
      content.imagePrompts = prompts;
    }

    const single = String(content?.imagePrompt || '').trim();
    if (single && imagePromptEchoesCopy(single, content)) {
      issues.push({ path: 'imagePrompt', rule: 'image_prompt_echoes_copy', repairable: true });
      content.imagePrompt = visualSubjectForSlot(imageSlotIds[0], content);
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
    } else {
      const genericLabels = labels.filter((label) => GENERIC_CHART_LABEL_RE.test(String(label || '').trim()));
      if (genericLabels.length >= Math.min(3, labels.length)) {
        issues.push({ path: 'chart.labels', rule: 'generic_chart_labels', repairable: true });
      }
    }
    const subtitle = String(content?.subtitle || content?.chart?.subtitle || '').trim();
    if (subtitle && PLACEHOLDER_CHART_SUBTITLE_RE.test(subtitle)) {
      issues.push({ path: 'subtitle', rule: 'placeholder_chart_subtitle', repairable: true });
    }
  }

  const ct = String(layoutSchema?.content_type || '').toLowerCase();
  if (ct === 'closing' || slots.some((s) => String(s.role || '').toLowerCase() === 'cta')) {
    const ctaText = String(content?.cta ?? content?.callToAction ?? content?.buttonText ?? '').trim();
    if (ctaText && PLACEHOLDER_CTA_RE.test(ctaText)) {
      issues.push({ path: 'cta', rule: 'placeholder_cta', repairable: true });
    }
  }

  for (const bodyKey of ['body', 'left_body', 'right_body']) {
    const bodyText = String(content?.[bodyKey] ?? '').trim();
    if (bodyText && (PLACEHOLDER_BODY_RE.test(bodyText) || isCatalogPlaceholderText(bodyText))) {
      issues.push({ path: bodyKey, rule: 'placeholder_body', repairable: true });
    }
  }

  if (layoutNeedsDiagramCells(slots)) {
    const minCells = Math.max(2, countDiagramCellSlots(slots) || 4);
    const cells = diagramCellsFromContent(content);
    const validCells = cells.filter((cell) => {
      const body = String(cell?.body ?? cell?.text ?? cell?.detail ?? '').trim();
      return body && !isCatalogPlaceholderText(body);
    });
    if (validCells.length < minCells) {
      issues.push({ path: 'diagram.cells', rule: 'required_structured', repairable: true });
    } else if (cells.some((cell) => isCatalogPlaceholderText(cell?.body ?? cell?.text ?? cell?.detail ?? ''))) {
      issues.push({ path: 'diagram.cells', rule: 'placeholder_diagram_body', repairable: true });
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
    } else {
      const withDetail = milestones.filter((item) => {
        if (typeof item === 'string') return false;
        return String(item.detail ?? item.body ?? item.text ?? item.description ?? '').trim().length > 0;
      });
      if (withDetail.length < 2) {
        issues.push({ path: 'timeline', rule: 'timeline_missing_details', repairable: true });
      }
    }
  }

  const headingSlots = slots.filter((s) => {
    const role = String(s.role || '').toLowerCase();
    const id = String(s.id || '').toUpperCase();
    return (
      role === 'heading' ||
      role === 'title' ||
      ['MAIN_TITLE', 'HEADING', 'HEADLINE', 'TITLE', 'STATEMENT'].includes(id)
    );
  });
  if (headingSlots.length && isWeakText(content?.title)) {
    issues.push({ path: 'title', rule: 'placeholder_heading', repairable: true });
  }
  const subSlots = slots.filter(
    (s) =>
      String(s.role || '').toLowerCase() === 'subheading' ||
      /subtitle/i.test(String(s.id || ''))
  );
  if (subSlots.length && isWeakText(content?.subtitle) && isWeakText(content?.body)) {
    issues.push({ path: 'subtitle', rule: 'empty_required_slot', repairable: true });
  }
  const copySlots = slots.filter((s) =>
    ['heading', 'subheading', 'body', 'bullet'].includes(String(s.role || '').toLowerCase())
  );
  if (copySlots.length >= 2) {
    const hasSecond =
      !isWeakText(content?.subtitle) ||
      !isWeakText(content?.body) ||
      (Array.isArray(content?.bullets) && content.bullets.some((b) => !isWeakText(typeof b === 'string' ? b : b?.text))) ||
      (Array.isArray(content?.columns) &&
        content.columns.some((c) => !isWeakText(c?.body ?? c?.text ?? c?.title)));
    if (!hasSecond) {
      issues.push({ path: 'body', rule: 'empty_required_slot', repairable: true });
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
  layoutNeedsGalleryLabels,
};
