/**
 * Normalize FE canvas element content to a canonical stored shape.
 * Accepts PDF-contract aliases (src, nested chart data, cells tables, etc.).
 */

const TABLE_MAX = 8;

const CHART_TYPE_MAP = {
  column: 'bar',
  'column-grouped': 'bar',
  'column-stacked': 'bar',
  bar: 'bar',
  'bar-grouped': 'bar',
  'bar-stacked': 'bar',
  line: 'line',
  'line-points': 'line',
  'line-multi': 'line',
  area: 'area',
  'area-stacked': 'area',
  pie: 'pie',
  donut: 'doughnut',
  doughnut: 'doughnut',
  kpi: 'bar',
};

function mapChartType(chartType) {
  const raw = String(chartType || 'bar').trim().toLowerCase();
  return CHART_TYPE_MAP[raw] || (raw.includes('pie') ? 'pie' : raw.includes('line') ? 'line' : 'bar');
}

function normalizeImageContent(content = {}) {
  const next = { ...content };
  if (!next.url && next.src) next.url = next.src;
  if (next.src != null && next.url) {
    // keep src as alias for FE round-trip
    next.src = next.url;
  }
  return next;
}

function normalizeChartContent(content = {}) {
  const next = { ...content };
  const nested = next.data && typeof next.data === 'object' ? next.data : null;
  if (nested) {
    if (!Array.isArray(next.labels) && Array.isArray(nested.labels)) next.labels = nested.labels;
    if (!Array.isArray(next.series) && Array.isArray(nested.series)) next.series = nested.series;
  }
  if (next.chartType != null) {
    next.chartTypeRaw = next.chartType;
    next.chartType = mapChartType(next.chartType);
  } else {
    next.chartType = 'bar';
  }
  if (!Array.isArray(next.labels)) next.labels = [];
  if (!Array.isArray(next.series)) next.series = [];
  return next;
}

function normalizeTableContent(content = {}) {
  const next = { ...content };
  let rows = null;
  if (Array.isArray(next.cells)) {
    rows = next.cells;
  } else if (Array.isArray(next.rows) && next.rows.length && Array.isArray(next.rows[0])) {
    rows = next.rows;
  } else if (Array.isArray(next.rows) && typeof next.rows[0] === 'number') {
    // FE sometimes sends rows/cols as dimensions with empty cells
    rows = next.cells || [];
  }

  if (!rows) rows = [];

  // Clamp to 8×8
  rows = rows.slice(0, TABLE_MAX).map((row) => {
    const cells = Array.isArray(row) ? row : [row];
    return cells.slice(0, TABLE_MAX).map((c) => (c == null ? '' : String(c)));
  });

  next.rows = rows;
  next.cells = rows;
  if (next.hasHeader == null) next.hasHeader = rows.length > 0;
  next.rowCount = rows.length;
  next.colCount = rows.reduce((max, r) => Math.max(max, r.length), 0);
  return next;
}

function normalizeShapeContent(content = {}) {
  const next = { ...content };
  if (next.shape != null) next.shape = String(next.shape).trim().toLowerCase();
  if (next.stroke != null && next.line == null) next.line = next.stroke;
  if (next.strokeWidth != null) next.strokeWidth = Number(next.strokeWidth) || 0;
  if (next.shape === 'rounded-rect' || next.shape === 'pill') {
    if (next.borderRadius == null) {
      next.borderRadius = next.shape === 'pill' ? 999 : 16;
    }
  }
  if (next.shape === 'circle') {
    // Stored as circle; export maps to ellipse
  }
  return next;
}

function normalizeEmbedContent(content = {}) {
  const next = { ...content };
  if (!next.url && next.src) next.url = next.src;
  if (next.provider != null) next.provider = String(next.provider).trim().toLowerCase();
  if (next.title == null && next.url) next.title = String(next.url);
  return next;
}

function normalizeTextContent(content = {}) {
  return { ...content };
}

function normalizeElementContent(type, content) {
  if (!content || typeof content !== 'object') return content || {};
  const t = String(type || '').toLowerCase();
  if (t === 'image' || t === 'icon' || t === 'graphic') return normalizeImageContent(content);
  if (t === 'chart') return normalizeChartContent(content);
  if (t === 'table') return normalizeTableContent(content);
  if (t === 'shape') return normalizeShapeContent(content);
  if (t === 'embed') return normalizeEmbedContent(content);
  if (t === 'text' || t === 'textbox') return normalizeTextContent(content);
  return { ...content };
}

function normalizeElement(el) {
  if (!el || typeof el !== 'object') return el;
  const type = el.type;
  return {
    ...el,
    content: normalizeElementContent(type, el.content),
  };
}

function normalizeCanvasDoc(doc) {
  if (!doc || typeof doc !== 'object') return doc;
  const elements = Array.isArray(doc.elements) ? doc.elements.map(normalizeElement) : [];
  return {
    ...doc,
    version: doc.version || 1,
    canvas: doc.canvas || {},
    elements,
  };
}

/**
 * Enrich slide for FE PDF helpers without mutating DB shape permanently in callers.
 */
function enrichSlideForClient(slide) {
  if (!slide || typeof slide !== 'object') return slide;
  const content = slide.content && typeof slide.content === 'object' ? slide.content : {};
  const title = content.title != null ? content.title : slide.title || null;
  const description = Array.isArray(content.bullets)
    ? content.bullets
    : Array.isArray(slide.description)
      ? slide.description
      : undefined;
  return {
    ...slide,
    title: title != null ? title : undefined,
    description,
  };
}

function enrichSlidesForClient(slides) {
  return Array.isArray(slides) ? slides.map(enrichSlideForClient) : [];
}

module.exports = {
  TABLE_MAX,
  CHART_TYPE_MAP,
  mapChartType,
  normalizeElementContent,
  normalizeElement,
  normalizeCanvasDoc,
  enrichSlideForClient,
  enrichSlidesForClient,
};
