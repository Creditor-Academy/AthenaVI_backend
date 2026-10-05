'use strict';

/** Where indexed slots (stat_1, member_2, â€¦) look for their list of entries. */
const LIST_SOURCE_KEYS = {
  stat: ['stats', 'metrics'],
  metric: ['stats', 'metrics'],
  member: ['team', 'members', 'people'],
  milestone: ['milestones', 'timeline', 'events'],
  card: ['cards', 'features', 'items', 'plans', 'tiers'],
  feature: ['features', 'cards', 'plans'],
  item: ['items', 'plans', 'tiers'],
  column: ['columns'],
  plan: ['plans', 'tiers', 'pricing', 'cards'],
  price: ['plans', 'tiers', 'pricing'],
  tier: ['tiers', 'plans', 'pricing'],
};

const INDEXED_SLOT_RE = /^(stat|metric|member|milestone|card|feature|item|column|plan|price|tier)_(\d+)$/;
const MEMBER_FIELD_RE = /^member_(\d+)_(name|role|email|title|bio|body|desc)$/;
const PLAN_FIELD_RE = /^plan_(\d+)_(label|name|price|body|cta|period|cents|caption)$/;
const PLAN_ITEM_RE = /^plan_(\d+)_item_(\d+)$/;
const PRICING_FEATURE_ROW_RE = /^feature_(\d+)$/;
const AGENDA_ITEM_RE = /^agenda_col_(\d+)_item_(\d+)$/;
const AGENDA_HEADING_RE = /^agenda_col_(\d+)_heading$/;
const DEPT_HEADING_RE = /^dept_(\d+)_heading$/;
const CARD_FIELD_RE = /^card_(\d+)_(title|body)$/;
const COL_FIELD_RE = /^col_(\d+)_(title|body)$/;
const ROW_FIELD_RE = /^row_(\d+)_(title|body)$/;
const FEATURE_FIELD_RE = /^feature_(\d+)_(title|body|text)$/;
/** Phone-highlights: FEATURE_L1_HEADING / FEATURE_R2_BODY â†’ columns[0..5] in L1,L2,L3,R1,R2,R3 order */
const FEATURE_SIDE_FIELD_RE = /^feature_([lr])(\d+)_(heading|body|title|text)$/;
/** Phone-triple side copy: HEADING_L / BODY_R */
const SIDE_HEADING_BODY_RE = /^(heading|body)_([lr])$/;
const MILESTONE_PART_RE = /^milestone_(\d+)_(label|detail)$/;
const QUADRANT_FIELD_RE = /^q(\d+)_(title|body)$/;
const STEP_FIELD_RE = /^step_(\d+)_(title|body)$/;
const FUNNEL_FIELD_RE = /^funnel_(\d+)_(title|body)$/;
const ITEM_FIELD_RE = /^item_(\d+)$/i;
const QUOTE_SLOT_RE = /^quote_(\d+)$/;
const ATTR_SLOT_RE = /^attr_(\d+)$/;
const NAME_SLOT_RE = /^name_(\d+)$/;
const ROLE_SLOT_RE = /^role_(\d+)$/;
const CONTACT_VALUE_RE = /^contact_(address|phone|email)$/;
const CENTERED_LAYOUT_RE = /centered|thank_you|big_number|banner/;
const MAIN_TITLE_SLOT_RE = /^(main_title|title|headline|heading)$/;
const INDEXED_BODY_SLOT_RE =
  /^(body|left_body|right_body|statement|lead|caption|footnote|intro|body_\d+|bullet_\d+|card_\d+_body|col_\d+_body|feature_\d+_(body|text)|agenda_col_\d+_item_\d+|item_\d+|bullet_\d+)$/;

/** Coerce AI/slot payloads to plain text â€” never return objects (React cannot render them). */
function coerceSlotText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (typeof value === 'object') {
    if (Array.isArray(value)) {
      return value.map(coerceSlotText).filter(Boolean).join('\n');
    }
    const nested = value.text ?? value.body ?? value.title ?? value.label ?? value.heading;
    if (nested != null && nested !== value) return coerceSlotText(nested);
    return '';
  }
  return String(value);
}

function itemToText(item) {
  if (item === null || item === undefined) return '';
  if (typeof item === 'string') return item.trim();
  if (typeof item !== 'object') return String(item);
  const head = item.value ?? item.number ?? item.date ?? item.year ?? item.period ?? '';
  const label = item.label ?? item.title ?? item.name ?? item.heading ?? '';
  const role = item.role ?? item.subtitle ?? '';
  const detail = item.text ?? item.body ?? item.description ?? item.summary ?? '';
  return [head, label, role, detail]
    .map((part) => coerceSlotText(part).trim())
    .filter(Boolean)
    .join('\n');
}

function itemsToTexts(value) {
  if (!Array.isArray(value)) return [];
  return value.map(itemToText).filter(Boolean);
}

function bulletBlock(list) {
  return list.map((line) => `â€¢ ${line}`).join('\n');
}

function stripMarkdownBold(text) {
  return String(text || '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/__(.+?)__/g, '$1');
}

function parseBulletLineRuns(line, mutedRole = 'muted', textRole = 'text') {
  const raw = typeof line === 'string' ? line.trim() : itemToText(line);
  if (!raw) return null;
  const cleaned = raw.replace(/^â€¢\s*/, '');
  const mdMatch = cleaned.match(/^\*\*(.+?)\*\*:\s*(.+)$/);
  if (mdMatch) {
    return [
      { text: 'â€¢ ', colorRole: textRole },
      { text: `${mdMatch[1]}:`, fontWeight: 700, colorRole: textRole },
      { text: ` ${stripMarkdownBold(mdMatch[2])}`, colorRole: mutedRole },
    ];
  }
  // **Label** without required colon (common AI variant)
  const mdLoose = cleaned.match(/^\*\*(.+?)\*\*\s*[:\-â€”â€“]?\s*(.*)$/);
  if (mdLoose && mdLoose[1]) {
    const label = mdLoose[1].trim();
    const detail = stripMarkdownBold(mdLoose[2] || '').trim();
    if (detail) {
      return [
        { text: 'â€¢ ', colorRole: textRole },
        { text: `${label}:`, fontWeight: 700, colorRole: textRole },
        { text: ` ${detail}`, colorRole: mutedRole },
      ];
    }
    return [
      { text: 'â€¢ ', colorRole: textRole },
      { text: label, fontWeight: 700, colorRole: textRole },
    ];
  }
  const colonMatch = cleaned.match(/^([^:]{2,40}):\s*(.+)$/);
  if (colonMatch) {
    return [
      { text: 'â€¢ ', colorRole: textRole },
      { text: `${colonMatch[1]}:`, fontWeight: 700, colorRole: textRole },
      { text: ` ${stripMarkdownBold(colonMatch[2])}`, colorRole: mutedRole },
    ];
  }
  if (line && typeof line === 'object' && (line.topic || line.label)) {
    const topic = String(line.topic ?? line.label ?? '').trim();
    const detail = String(line.text ?? line.body ?? '').trim();
    if (topic && detail) {
      return [
        { text: 'â€¢ ', colorRole: textRole },
        { text: `${topic}:`, fontWeight: 700, colorRole: textRole },
        { text: ` ${stripMarkdownBold(detail)}`, colorRole: mutedRole },
      ];
    }
  }
  return [{ text: `â€¢ ${stripMarkdownBold(cleaned)}`, colorRole: mutedRole }];
}

function buildBulletListRuns(content, onImage = false) {
  const items = bulletsOf(content);
  if (!items.length) return null;
  const textRole = onImage ? 'textOnImage' : 'text';
  const mutedRole = onImage ? 'textOnImageMuted' : 'muted';
  const runs = [];
  items.forEach((item, index) => {
    const lineRuns = parseBulletLineRuns(item, mutedRole, textRole);
    if (!lineRuns) return;
    if (index > 0) runs.push({ text: '\n', colorRole: mutedRole });
    runs.push(...lineRuns);
  });
  if (!runs.length) return null;
  return {
    text: bulletBlock(items.map((item) => stripMarkdownBold(typeof item === 'string' ? item : itemToText(item)))),
    runs,
  };
}

function applyMarkdownRunsToPlainText(textContent, onImage = false) {
  if (!textContent || textContent.runs?.length) return textContent;
  const raw = String(textContent.text || '');
  if (!raw.includes('**') && !raw.includes('__')) return textContent;
  const textRole = onImage ? 'textOnImage' : 'text';
  const mutedRole = onImage ? 'textOnImageMuted' : 'muted';
  const lines = raw.split('\n');
  const runs = [];
  lines.forEach((line, index) => {
    if (index > 0) runs.push({ text: '\n', colorRole: mutedRole });
    const trimmed = line.trim();
    if (/^â€¢/.test(trimmed) || /^\*\*/.test(trimmed)) {
      const lineRuns = parseBulletLineRuns(trimmed, mutedRole, textRole);
      if (lineRuns) {
        runs.push(...lineRuns);
        return;
      }
    }
    // Inline **bold** spans within a normal body line
    const parts = trimmed.split(/(\*\*[^*]+\*\*)/g).filter((p) => p.length);
    if (parts.length > 1) {
      parts.forEach((part) => {
        const bold = part.match(/^\*\*(.+)\*\*$/);
        if (bold) runs.push({ text: bold[1], fontWeight: 700, colorRole: textRole });
        else runs.push({ text: part, colorRole: mutedRole });
      });
      return;
    }
    runs.push({ text: stripMarkdownBold(line), colorRole: mutedRole });
  });
  return {
    ...textContent,
    text: stripMarkdownBold(raw),
    runs,
  };
}

function applyRichBulletsToTextContent(textContent, content, slotId, onImage = false) {
  const id = String(slotId || '').toLowerCase();
  if (id === 'bullets' || id === 'bullet_list') {
    const rich = buildBulletListRuns(content, onImage);
    if (rich) return { ...textContent, text: rich.text, runs: rich.runs };
  }
  // Per-column / body slots: parse or strip markdown so `**` never shows raw.
  if (
    /^bullet_\d+$/.test(id) ||
    /^body_\d+$/.test(id) ||
    /^card_\d+_body$/.test(id) ||
    /^col_\d+_body$/.test(id) ||
    id === 'body' ||
    id === 'left_body' ||
    id === 'right_body'
  ) {
    return applyMarkdownRunsToPlainText(textContent, onImage);
  }
  if (String(textContent?.text || '').includes('**')) {
    return applyMarkdownRunsToPlainText(textContent, onImage);
  }
  return textContent;
}

function bulletsOf(content) {
  return itemsToTexts(content.bullets);
}

function listForKind(kind, content) {
  const keys = LIST_SOURCE_KEYS[kind] || [`${kind}s`];
  for (const key of keys) {
    const list = itemsToTexts(content[key]);
    if (list.length) return list;
  }
  return [];
}

function objectListForKind(kind, content) {
  const keys = LIST_SOURCE_KEYS[kind] || [`${kind}s`];
  for (const key of keys) {
    const raw = content[key];
    if (Array.isArray(raw) && raw.length) return raw;
  }
  if (kind === 'plan' && content.pricing != null) {
    const pricing = content.pricing;
    if (Array.isArray(pricing) && pricing.length) return pricing;
    if (typeof pricing === 'object') {
      const nested = pricing.tiers || pricing.plans;
      if (Array.isArray(nested) && nested.length) return nested;
    }
  }
  return [];
}

function memberAt(content, index) {
  const list = objectListForKind('member', content);
  const item = list[index];
  if (!item) return '';
  if (typeof item === 'string') return item.trim();
  return item;
}

function planItemText(item) {
  if (item == null) return '';
  if (typeof item === 'string') return item.trim();
  if (typeof item === 'boolean') return item ? 'Yes' : '';
  if (typeof item !== 'object') return String(item).trim();
  return String(item.text ?? item.label ?? item.name ?? item.value ?? item.detail ?? '').trim();
}

function planAt(content, index) {
  const list = objectListForKind('plan', content);
  return list[index] || null;
}

function pricingFeatureRows(content) {
  const direct = content.features || content.planFeatures || content.comparison?.features;
  if (Array.isArray(direct) && direct.length) return direct;
  const rows = content.comparison?.rows;
  if (Array.isArray(rows) && rows.length) return rows;
  return [];
}

function agendaColumnAt(content, colIndex) {
  const columns = content.agenda?.columns;
  if (!Array.isArray(columns)) return null;
  return columns[colIndex] || null;
}

function structuredColumnAt(content, colIndex) {
  const lists = [content.columns, content.cards, content.features];
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    const col = list[colIndex];
    if (col != null) return col;
  }
  return null;
}

/** Map FEATURE_L1..L3,R1..R3 â†’ 0..5 */
function featureSideColumnIndex(side, num) {
  const n = Number(num) || 1;
  const s = String(side || '').toLowerCase();
  if (s === 'l') return Math.max(0, n - 1);
  if (s === 'r') return 3 + Math.max(0, n - 1);
  return Math.max(0, n - 1);
}

function titleLinesFromContent(content = {}) {
  const title = String(content.title || '').trim();
  const fromTitle = title.split(/\n+/).map((s) => s.trim()).filter(Boolean);
  if (fromTitle.length >= 2) return { line1: fromTitle[0], line2: fromTitle.slice(1).join(' ') };
  const runs = Array.isArray(content.titleRuns)
    ? content.titleRuns.map((r) => String(r?.text || '').trim()).filter(Boolean)
    : [];
  if (runs.length >= 2) return { line1: runs[0], line2: runs.slice(1).join(' ') };
  if (fromTitle.length === 1) return { line1: fromTitle[0], line2: '' };
  if (runs.length === 1) return { line1: runs[0], line2: '' };
  return { line1: title, line2: '' };
}

function isMainTitleSlot(slotId, role) {
  const lower = String(slotId || '').toLowerCase();
  const r = String(role || '').toLowerCase();
  if (MAIN_TITLE_SLOT_RE.test(lower)) return true;
  if (r === 'heading' && MAIN_TITLE_SLOT_RE.test(lower)) return true;
  return false;
}

function primaryStat(content) {
  const raw = content.stat || (Array.isArray(content.stats) ? content.stats[0] : null);
  if (!raw) return { value: '', label: '' };
  if (typeof raw === 'string') return { value: raw, label: content.subtitle || '' };
  return {
    value: String(raw.value ?? raw.number ?? '').trim(),
    label: String(raw.label ?? raw.title ?? raw.text ?? content.subtitle ?? '').trim(),
  };
}

function sideOf(content, side) {
  const src = content[side] || content.comparison?.[side] || {};
  const items = itemsToTexts(src.bullets || src.items || src.points);
  return {
    title: String(src.title || src.label || '').trim(),
    body: items.length ? bulletBlock(items) : String(src.body || src.text || '').trim(),
  };
}

function linesOf(value) {
  if (Array.isArray(value)) return itemsToTexts(value).join('\n');
  if (value && typeof value === 'object') return itemToText(value);
  return String(value || '').trim();
}

function tableRowsOf(content) {
  const table = content.table;
  if (!table) return [];
  const rows = Array.isArray(table) ? table : Array.isArray(table.rows) ? table.rows : [];
  const headers = Array.isArray(table?.headers) ? [table.headers] : [];
  return [...headers, ...rows].map((row) => (Array.isArray(row) ? row.map((c) => String(c ?? '')) : [String(row)]));
}

function chartDatasetAt(content, index) {
  if (!content || typeof content !== 'object') return null;
  if (Array.isArray(content.charts) && content.charts[index]) return content.charts[index];
  if (index === 0 && content.chart) return content.chart;
  if (index === 1 && content.chart2) return content.chart2;
  return null;
}

function chartForSlot(slotId, content = {}) {
  const id = String(slotId || '').toUpperCase();
  const chartMatch = id.match(/^CHART_(\d+)$/);
  if (chartMatch) {
    return chartDatasetAt(content, Number(chartMatch[1]) - 1);
  }
  if (/^(MAIN_CHART|DONUT_CHART|LINE_CHART|BAR_CHART|KPI_CHART)/.test(id)) {
    return content.chart || null;
  }
  return content.chart || null;
}

/** Distinct demo datasets so empty CHART_1/2/3 slots all render. */
function sampleChartDataset(index = 0, layoutId = '') {
  const i = Math.max(0, Number(index) || 0);
  if (/donut|pie/i.test(String(layoutId || ''))) {
    const sets = [
      { labels: ['A', 'B', 'C', 'D'], values: [40, 25, 20, 15] },
      { labels: ['A', 'B', 'C', 'D'], values: [30, 30, 25, 15] },
      { labels: ['A', 'B', 'C', 'D'], values: [50, 20, 18, 12] },
    ];
    return sets[i % sets.length];
  }
  const sets = [
    { labels: ['Q1', 'Q2', 'Q3', 'Q4'], values: [42, 58, 51, 67] },
    { labels: ['Q1', 'Q2', 'Q3', 'Q4'], values: [28, 36, 44, 39] },
    { labels: ['Q1', 'Q2', 'Q3', 'Q4'], values: [55, 48, 62, 71] },
  ];
  return sets[i % sets.length];
}

/** True only for real chart data slots â€” not CHART_HEADING / CHART_CAPTION / titles. */
function isChartElementSlot(slotId, role) {
  if (String(role || '').toLowerCase() === 'chart') return true;
  const id = String(slotId || '').toUpperCase();
  if (/^(MAIN_CHART|DONUT_CHART|LINE_CHART|BAR_CHART|KPI_CHART|PIE_CHART)(_|$)/.test(id)) {
    return true;
  }
  if (/^CHART_\d+$/.test(id)) return true;
  return false;
}

function resolveChartTypeForSlot(slot, chartData, content, layoutSchema) {
  const explicit = String(chartData?.type || chartData?.chartType || '').trim().toLowerCase();
  if (explicit) return explicit;
  const slotType = String(slot?.chartType || slot?.chart_type || '').trim().toLowerCase();
  if (slotType) return slotType;
  const slotId = String(slot?.id || '').toUpperCase();
  const layoutId = String(layoutSchema?.layout_id || '').toLowerCase();
  if (/^DONUT/.test(slotId) || /donut|pie/.test(layoutId)) return 'donut';
  if (/^LINE/.test(slotId) || /line|exponential|area/.test(layoutId)) return 'line';
  const title = `${content?.title || ''} ${content?.summary || ''} ${content?.body || ''}`.toLowerCase();
  const values = chartData?.series?.[0]?.values || chartData?.data || chartData?.values || [];
  const nums = (Array.isArray(values) ? values : []).map(Number).filter((value) => !Number.isNaN(value));
  const sum = nums.reduce((total, value) => total + value, 0);
  if (
    /share|percent|distribution|breakdown|producing|market share|composition|mix|split|portion/.test(title) ||
    (nums.length >= 3 && sum >= 85 && sum <= 115)
  ) {
    return 'donut';
  }
  if (/trend|growth|over time|trajectory|year-over-year|yoy/.test(title)) return 'line';
  return 'column-grouped';
}

function diagramCellAt(content, index) {
  const cells =
    content.diagram?.cells ||
    content.cells ||
    content.quadrants ||
    content.steps ||
    content.funnel ||
    [];
  return Array.isArray(cells) ? cells[index] : null;
}

function titleWordsFromBodyLocal(body, fallback) {
  const words = String(body || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 4)
    .join(' ');
  return words || fallback || '';
}

function layoutHasDedicatedColumnTitleSlots(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((s) => /^(card|col|row|feature)_\d+_title$/i.test(String(s.id || '')));
}

function resolveColumnTitleCandidate(col, index, slideTitle, seen, fallbackPrefix) {
  let title = String(col?.title ?? col?.heading ?? col?.label ?? '').trim();
  const body = String(col?.body ?? col?.text ?? col?.description ?? '').trim();
  const titleLower = title.toLowerCase();
  if (!title || titleLower === slideTitle || seen.has(titleLower)) {
    const fromBody = titleWordsFromBodyLocal(body, '');
    const fromBodyLower = String(fromBody || '')
      .trim()
      .toLowerCase();
    if (fromBody && fromBodyLower !== slideTitle && !seen.has(fromBodyLower)) {
      title = fromBody;
    } else {
      title = `${fallbackPrefix} ${index + 1}`;
    }
  }
  return title;
}

function uniqueColumnTitle(rawTitle, body, index, content, fallbackPrefix = 'Aspect') {
  const slideTitle = String(content?.title || '').trim().toLowerCase();
  const cols = content?.columns || content?.cards || content?.features || [];
  const seen = new Set();
  // Rebuild uniqueness from prior columns the same way we rewrite them, so `seen`
  // includes rewritten titles (not only raw LLM duplicates of the slide title).
  if (Array.isArray(cols)) {
    for (let i = 0; i < index; i += 1) {
      const resolved = resolveColumnTitleCandidate(cols[i], i, slideTitle, seen, fallbackPrefix);
      if (resolved) seen.add(resolved.toLowerCase());
    }
  }
  return resolveColumnTitleCandidate(
    { title: rawTitle, body },
    index,
    slideTitle,
    seen,
    fallbackPrefix
  );
}

function textForSlot(slotId, content = {}, layoutSchema = null) {
  const id = String(slotId || '').toLowerCase();
  const bullets = bulletsOf(content);

  const milestonePlain = id.match(/^milestone_(\d+)$/);
  if (milestonePlain) {
    const milestones = objectListForKind('milestone', content);
    const raw = milestones[Number(milestonePlain[1]) - 1];
    if (!raw) return '';
    if (typeof raw === 'string') return raw.trim();
    const label = String(raw.label ?? raw.date ?? raw.year ?? raw.period ?? raw.title ?? '').trim();
    const detail = String(raw.detail ?? raw.body ?? raw.text ?? raw.description ?? '').trim();
    if (label && detail) return `${label}\n${detail}`;
    return label || detail;
  }

  const indexed = id.match(INDEXED_SLOT_RE);
  if (indexed) {
    const index = Number(indexed[2]) - 1;
    if (indexed[1] === 'milestone') {
      const milestones = objectListForKind('milestone', content);
      const raw = milestones[index];
      if (!raw) return bullets[index] || '';
      if (typeof raw === 'string') return raw.trim();
      const label = String(raw.label ?? raw.date ?? raw.year ?? raw.period ?? raw.title ?? '').trim();
      const detail = String(raw.detail ?? raw.body ?? raw.text ?? raw.description ?? '').trim();
      if (label && detail) return `${label}\n${detail}`;
      return label || detail || itemToText(raw);
    }
    return listForKind(indexed[1], content)[index] || bullets[index] || '';
  }

  const memberField = id.match(MEMBER_FIELD_RE);
  if (memberField) {
    const member = memberAt(content, Number(memberField[1]) - 1);
    if (!member || typeof member !== 'object') return typeof member === 'string' ? member : '';
    const field = memberField[2];
    if (field === 'name') return String(member.name ?? '').trim();
    if (field === 'role' || field === 'title') return String(member.role ?? member.title ?? '').trim();
    if (field === 'email') return String(member.email ?? '').trim();
    if (field === 'bio' || field === 'body' || field === 'desc') {
      return String(member.bio ?? member.body ?? member.description ?? '').trim();
    }
  }

  const quadrantField = id.match(QUADRANT_FIELD_RE);
  if (quadrantField) {
    const cell = diagramCellAt(content, Number(quadrantField[1]) - 1);
    if (!cell) return '';
    if (quadrantField[2] === 'title') {
      return String(cell.title ?? cell.label ?? cell.heading ?? '').trim();
    }
    return String(cell.body ?? cell.text ?? cell.detail ?? '').trim();
  }

  const stepField = id.match(STEP_FIELD_RE);
  if (stepField) {
    const cell = diagramCellAt(content, Number(stepField[1]) - 1);
    if (!cell) return '';
    if (stepField[2] === 'title') {
      return String(cell.title ?? cell.label ?? cell.step ?? '').trim();
    }
    return String(cell.body ?? cell.text ?? cell.detail ?? '').trim();
  }

  const funnelField = id.match(FUNNEL_FIELD_RE);
  if (funnelField) {
    const list = content.funnel || content.diagram?.cells || content.cells || [];
    const cell = Array.isArray(list) ? list[Number(funnelField[1]) - 1] : null;
    if (!cell) return '';
    if (funnelField[2] === 'title') {
      return String(cell.title ?? cell.label ?? '').trim();
    }
    return String(cell.body ?? cell.text ?? '').trim();
  }

  const quoteSlot = id.match(QUOTE_SLOT_RE);
  if (quoteSlot) {
    const quotes = content.quotes || content.testimonials || (content.quote ? [content.quote] : []);
    const raw = Array.isArray(quotes) ? quotes[Number(quoteSlot[1]) - 1] : null;
    if (typeof raw === 'string') return raw.trim();
    return String(raw?.text ?? raw?.quote ?? '').trim();
  }

  const nameSlot = id.match(NAME_SLOT_RE);
  if (nameSlot) {
    const attrs = content.testimonials || content.attributions || content.quotes || [];
    const raw = Array.isArray(attrs) ? attrs[Number(nameSlot[1]) - 1] : null;
    if (typeof raw === 'string') return raw.trim();
    return String(raw?.name ?? raw?.author ?? raw?.attribution ?? '').trim();
  }

  const roleSlot = id.match(ROLE_SLOT_RE);
  if (roleSlot) {
    const attrs = content.testimonials || content.attributions || content.quotes || [];
    const raw = Array.isArray(attrs) ? attrs[Number(roleSlot[1]) - 1] : null;
    if (typeof raw === 'string') return '';
    return String(raw?.role ?? raw?.title ?? raw?.org ?? raw?.company ?? '').trim();
  }

  const attrSlot = id.match(ATTR_SLOT_RE);
  if (attrSlot) {
    const attrs = content.testimonials || content.attributions || [];
    const raw = Array.isArray(attrs) ? attrs[Number(attrSlot[1]) - 1] : null;
    if (typeof raw === 'string') return raw.trim();
    return String(raw?.name ?? raw?.attribution ?? raw?.author ?? '').trim();
  }

  const planItem = id.match(PLAN_ITEM_RE);
  if (planItem) {
    const plan = planAt(content, Number(planItem[1]) - 1);
    if (!plan) return '';
    const itemIndex = Number(planItem[2]) - 1;
    const items = Array.isArray(plan.items)
      ? plan.items
      : Array.isArray(plan.bullets)
        ? plan.bullets
        : Array.isArray(plan.features)
          ? plan.features
          : [];
    if (items[itemIndex] != null) return planItemText(items[itemIndex]);
    if (itemIndex === 0 && plan.storage != null) return planItemText(plan.storage);
    return '';
  }

  const planField = id.match(PLAN_FIELD_RE);
  if (planField) {
    const plan = planAt(content, Number(planField[1]) - 1);
    if (!plan) return '';
    const field = planField[2];
    if (field === 'label' || field === 'name') return String(plan.label ?? plan.name ?? plan.title ?? '').trim();
    if (field === 'price') return String(plan.price ?? plan.amount ?? '').trim();
    if (field === 'period') return String(plan.period ?? plan.interval ?? plan.billing ?? '').trim();
    if (field === 'cents') return String(plan.cents ?? plan.priceCents ?? '').trim();
    if (field === 'caption') return String(plan.caption ?? plan.tagline ?? plan.subtitle ?? '').trim();
    if (field === 'cta') {
      return String(plan.cta ?? plan.button ?? plan.callToAction ?? content.cta ?? '').trim();
    }
    if (field === 'body') {
      const items = Array.isArray(plan.items) ? plan.items : Array.isArray(plan.bullets) ? plan.bullets : [];
      return items.length
        ? items.map((item) => planItemText(item)).filter(Boolean).join('\n')
        : String(plan.body ?? plan.description ?? '').trim();
    }
  }

  const pricingFeatureRow = id.match(PRICING_FEATURE_ROW_RE);
  if (pricingFeatureRow) {
    const rows = pricingFeatureRows(content);
    const raw = rows[Number(pricingFeatureRow[1]) - 1];
    if (raw == null) return '';
    if (typeof raw === 'string') return raw.trim();
    return String(raw.label ?? raw.title ?? raw.name ?? raw.text ?? '').trim();
  }

  const agendaHeading = id.match(AGENDA_HEADING_RE);
  if (agendaHeading) {
    const col = agendaColumnAt(content, Number(agendaHeading[1]) - 1);
    return String(col?.heading ?? col?.title ?? '').trim();
  }

  const agendaItem = id.match(AGENDA_ITEM_RE);
  if (agendaItem) {
    const col = agendaColumnAt(content, Number(agendaItem[1]) - 1);
    const items = Array.isArray(col?.items) ? col.items : [];
    return String(items[Number(agendaItem[2]) - 1] ?? '').trim();
  }

  const cardField = id.match(CARD_FIELD_RE);
  if (cardField) {
    const col = structuredColumnAt(content, Number(cardField[1]) - 1);
    if (!col) return '';
    if (cardField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(cardField[1]) - 1,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const colField = id.match(COL_FIELD_RE);
  if (colField) {
    const col = structuredColumnAt(content, Number(colField[1]) - 1);
    if (!col) return '';
    if (colField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(colField[1]) - 1,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const rowField = id.match(ROW_FIELD_RE);
  if (rowField) {
    const col = structuredColumnAt(content, Number(rowField[1]) - 1);
    if (!col) return '';
    if (rowField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(rowField[1]) - 1,
        content,
        'Pillar'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const featureField = id.match(FEATURE_FIELD_RE);
  if (featureField) {
    const col = structuredColumnAt(content, Number(featureField[1]) - 1);
    if (!col) return '';
    if (featureField[2] === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        Number(featureField[1]) - 1,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const featureSide = id.match(FEATURE_SIDE_FIELD_RE);
  if (featureSide) {
    const idx = featureSideColumnIndex(featureSide[1], featureSide[2]);
    const col = structuredColumnAt(content, idx);
    if (!col) return '';
    const field = featureSide[3];
    if (field === 'heading' || field === 'title') {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        idx,
        content,
        'Aspect'
      );
    }
    return String(col.body ?? col.text ?? itemToText(col)).trim();
  }

  const sideHeadingBody = id.match(SIDE_HEADING_BODY_RE);
  if (sideHeadingBody) {
    const side = sideHeadingBody[2];
    const idx = side === 'l' ? 0 : 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      if (sideHeadingBody[1] === 'heading') {
        return uniqueColumnTitle(
          col.title ?? col.heading ?? col.label,
          col.body ?? col.text,
          idx,
          content,
          'Aspect'
        );
      }
      return String(col.body ?? col.text ?? itemToText(col)).trim();
    }
    const sideCopy = sideOf(content, side === 'l' ? 'left' : 'right');
    return sideHeadingBody[1] === 'heading' ? sideCopy.title : sideCopy.body;
  }

  if (id === 'heading_2') {
    const { line2 } = titleLinesFromContent(content);
    if (line2) return line2;
    return String(content.subtitle || '').trim();
  }

  if (id === 'subheading') {
    return (
      String(content.subtitle || '').trim() ||
      String(content.summary || '')
        .split(/[.!?]/)[0]
        ?.trim() ||
      ''
    );
  }

  const milestonePart = id.match(MILESTONE_PART_RE);
  if (milestonePart) {
    const milestones = objectListForKind('milestone', content);
    const raw = milestones[Number(milestonePart[1]) - 1];
    if (!raw) return '';
    if (typeof raw === 'string') {
      return milestonePart[2] === 'label' ? raw.trim() : '';
    }
    if (milestonePart[2] === 'label') {
      return String(raw.label ?? raw.date ?? raw.year ?? raw.period ?? raw.title ?? '').trim();
    }
    return String(raw.detail ?? raw.body ?? raw.text ?? raw.description ?? '').trim();
  }

  const itemSlot = id.match(ITEM_FIELD_RE);
  if (itemSlot) {
    const index = Number(itemSlot[1]) - 1;
    const fromItems = itemsToTexts(content.items);
    if (fromItems[index]) return fromItems[index];
    if (bullets[index]) return bullets[index];
    const col = structuredColumnAt(content, index);
    if (col) return itemToText(col);
    return '';
  }

  const deptHeading = id.match(DEPT_HEADING_RE);
  if (deptHeading) {
    const depts = content.departments || content.agenda?.columns;
    const dept = Array.isArray(depts) ? depts[Number(deptHeading[1]) - 1] : null;
    return String(dept?.heading ?? dept?.title ?? '').trim();
  }

  const contactValue = id.match(CONTACT_VALUE_RE);
  if (contactValue) {
    const contact = content.contact && typeof content.contact === 'object' ? content.contact : {};
    return String(contact[contactValue[1]] ?? '').trim();
  }

  if (id === 'contact_address_label' || id === 'contact_phone_label' || id === 'contact_email_label') {
    return id.includes('address') ? 'Address' : id.includes('phone') ? 'Phone' : 'Email';
  }

  switch (id) {
    case 'stat_value':
      return primaryStat(content).value;
    case 'stat_label':
      return primaryStat(content).label;
    case 'lead':
      return itemToText(content.lead) || listForKind('member', content)[0] || '';
    case 'center_body':
      return String(content.diagram?.center ?? content.center ?? content.overlap ?? '').trim();
    case 'attribution':
      return String(content.attribution || content.author || content.name || content.source || '').trim();
    case 'name':
      return String(content.name || content.author || content.attribution || '').trim();
    case 'role':
      return String(content.role || content.authorTitle || content.titleLine || '').trim();
    case 'cta':
      return String(
        content.cta ||
          content.callToAction ||
          content.closingCta ||
          (content.title ? `Explore ${String(content.title).split(/\s+/).slice(0, 3).join(' ')}` : '') ||
          'Learn more'
      ).trim();
    case 'contact':
      return linesOf(content.contact);
    case 'caption':
    case 'footnote':
      return String(content.caption || content.footnote || content.note || '').trim();
    case 'main_title':
      return String(content.title || '').trim();
    case 'section_number':
      return String(content.sectionNumber ?? content.section_number ?? '').trim();
    case 'left_title':
      return sideOf(content, 'left').title;
    case 'right_title':
      return sideOf(content, 'right').title;
    case 'left_body':
      return sideOf(content, 'left').body;
    case 'right_body':
      return sideOf(content, 'right').body;
    case 'pros_title':
      return String(content.prosTitle || content.comparison?.prosTitle || 'Pros').trim();
    case 'cons_title':
      return String(content.consTitle || content.comparison?.consTitle || 'Cons').trim();
    case 'pros':
      return bulletBlock(itemsToTexts(content.pros).length ? itemsToTexts(content.pros) : itemsToTexts(content.left?.bullets));
    case 'cons':
      return bulletBlock(itemsToTexts(content.cons).length ? itemsToTexts(content.cons) : itemsToTexts(content.right?.bullets));
    case 'bullets_left':
    case 'bullets_right': {
      const half = Math.ceil(bullets.length / 2);
      return bulletBlock(id.endsWith('left') ? bullets.slice(0, half) : bullets.slice(half));
    }
    case 'timeline': {
      const milestones = listForKind('milestone', content);
      return bulletBlock(milestones.length ? milestones : bullets);
    }
    case 'members': {
      const members = listForKind('member', content);
      return bulletBlock(members.length ? members : bullets);
    }
    case 'left_items':
    case 'right_items': {
      const milestones = listForKind('milestone', content);
      const source = milestones.length ? milestones : bullets;
      const half = Math.ceil(source.length / 2);
      return bulletBlock(id.startsWith('left') ? source.slice(0, half) : source.slice(half));
    }
    case 'table': {
      const rows = tableRowsOf(content);
      return rows.map((row) => row.join('   |   ')).join('\n');
    }
    default:
      break;
  }

  if (id === 'heading') {
    const { line1, line2 } = titleLinesFromContent(content);
    if (line1 && line2) return `${line1}\n${line2}`;
    return String(content.title || line1 || '').trim();
  }

  const metricTitle = id.match(/^metric_title_(\d+)$/);
  if (metricTitle) {
    const col = content.columns?.[Number(metricTitle[1]) - 1];
    return String(col?.title ?? col?.heading ?? '').trim();
  }
  const metricBody = id.match(/^metric_body_(\d+)$/);
  if (metricBody) {
    const col = content.columns?.[Number(metricBody[1]) - 1];
    return String(col?.body ?? col?.text ?? '').trim();
  }

  const statValue = id.match(/^stat_(\d+)_value$/);
  if (statValue) {
    const stat = content.stats?.[Number(statValue[1]) - 1];
    return String(stat?.value ?? stat?.number ?? '').trim();
  }
  const statLabel = id.match(/^stat_(\d+)_label$/);
  if (statLabel) {
    const stat = content.stats?.[Number(statLabel[1]) - 1];
    return String(stat?.label ?? stat?.title ?? stat?.text ?? '').trim();
  }

  const imageLabelSlot = id.match(/^image_(\d+)_label$/);
  if (imageLabelSlot) {
    const idx = Number(imageLabelSlot[1]) - 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      return uniqueColumnTitle(
        col.title ?? col.heading ?? col.label,
        col.body ?? col.text,
        idx,
        content,
        'Gallery'
      );
    }
    const items = Array.isArray(content.items) ? content.items : [];
    const item = items[idx];
    if (typeof item === 'string') {
      return uniqueColumnTitle(item, '', idx, content, 'Gallery');
    }
    if (item) {
      return uniqueColumnTitle(
        item.title ?? item.label ?? item.heading,
        item.body ?? item.text,
        idx,
        content,
        'Gallery'
      );
    }
    return `Gallery ${idx + 1}`;
  }

  const bulletSlot = id.match(/^bullet_(\d+)$/);
  if (bulletSlot) {
    const idx = Number(bulletSlot[1]) - 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      const title = String(col.title ?? col.heading ?? col.label ?? '').trim();
      const body = String(col.body ?? col.text ?? '').trim();
      // When layout has dedicated title slots, body/bullet slots must not repeat the title.
      if (layoutHasDedicatedColumnTitleSlots(layoutSchema)) {
        return body || itemToText(col) || '';
      }
      if (title && body) return `${title}\n${body}`;
      return body || title || itemToText(col);
    }
    return bullets[idx] || '';
  }

  if (
    id.includes('title') &&
    !id.includes('subtitle') &&
    // Never flood indexed process/card/column/row slots with the slide title.
    !/^metric_|^plan_|^col_|^card_|^row_|^feature_|^point_|^member_|^agenda_col_|^step_|^phase_|^item_/.test(
      id
    )
  ) {
    return coerceSlotText(content.title).trim();
  }
  if (id.includes('subtitle')) {
    return (
      coerceSlotText(content.subtitle).trim() ||
      coerceSlotText(content.summary).trim() ||
      (typeof content.body === 'string' ? content.body.split(/[.!?]/)[0]?.trim() : '') ||
      ''
    );
  }
  if (id === 'name' || id === 'author_name') {
    return String(content.name || content.author || content.attribution || '').trim();
  }
  if (id === 'role' || id === 'author_title') {
    return String(content.role || content.authorTitle || content.titleLine || '').trim();
  }
  if (id.includes('quote') || id === 'statement') {
    return coerceSlotText(content.quote || content.body).trim();
  }
  if (id === 'bullets' || id === 'bullet_list') return bulletBlock(bullets);

  const indexedBody = id.match(/^body_(\d+)$/);
  if (indexedBody) {
    const idx = Number(indexedBody[1]) - 1;
    const col = structuredColumnAt(content, idx);
    if (col) {
      const title = String(col.title ?? col.heading ?? col.label ?? '').trim();
      const body = String(col.body ?? col.text ?? '').trim();
      if (layoutHasDedicatedColumnTitleSlots(layoutSchema)) {
        return body || itemToText(col) || '';
      }
      if (title && body) return `${title}\n${body}`;
      return body || title || itemToText(col);
    }
    if (bullets[idx]) return bullets[idx];
    return '';
  }

  if (INDEXED_BODY_SLOT_RE.test(id)) {
    if (id === 'body') {
      if (content.body) return coerceSlotText(content.body).trim();
      if (content.summary) return coerceSlotText(content.summary).trim();
      if (bullets.length) return bulletBlock(bullets);
      return '';
    }
    if ((id === 'left_body' || id === 'right_body') && content[id]) {
      return coerceSlotText(content[id]).trim();
    }
    return '';
  }
  if (id === 'accent') return '';
  return '';
}

module.exports = {
  textForSlot,
  coerceSlotText,
  itemToText,
  itemsToTexts,
  bulletsOf,
  bulletBlock,
  isMainTitleSlot,
  chartForSlot,
  chartDatasetAt,
  sampleChartDataset,
  isChartElementSlot,
  resolveChartTypeForSlot,
  applyRichBulletsToTextContent,
};
