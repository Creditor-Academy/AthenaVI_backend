/**
 * Native PPTX charts that look like the editor's (PptChartRenderer).
 *
 * The editor draws a styled single-series visual, not a standard chart: only the first series,
 * one colour per bar / slice (theme colours if vivid enough, else a fixed palette), value labels
 * above the bars, no value axis, faint dashed gridlines, a smooth line, a legend under pies and
 * donuts. This mirrors those choices so the exported chart stays editable data and still looks
 * like the editor. A "kpi" chart is a big number and a label — exported as text.
 */

const { normalizeChartContent } = require('./chartContentNormalize');

/** Editor bar defaults (PptChartRenderer BarChart). */
function barDefaultColors(palette = {}) {
  return [palette.accent || '#6366F1', palette.primary || '#3B82F6', '#06B6D4', '#10B981', '#F59E0B', '#8B5CF6'];
}

/** Editor donut palette (PptChartRenderer DONUT_PALETTE, `base`). */
const DONUT_COLORS = ['#3B82F6', '#8B5CF6', '#10B981', '#F59E0B', '#EF4444', '#64748B'];

const hex6 = (value) => {
  const m = /#([0-9a-f]{6})\b/i.exec(String(value || ''));
  if (m) return `#${m[1].toUpperCase()}`;
  const s = /#([0-9a-f]{3})\b/i.exec(String(value || ''));
  return s ? `#${s[1].split('').map((c) => c + c).join('').toUpperCase()}` : null;
};

/** Editor isColorVibrant: a 6-digit hex whose channels differ by at least 36. */
function isColorVibrant(color) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(color || ''));
  if (!m) return false;
  const n = parseInt(m[1], 16);
  const channels = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  return Math.max(...channels) - Math.min(...channels) >= 36;
}

/** Editor resolveColor: hex / css as is, palette role names via the palette. */
function resolveChartColor(color, palette = {}, fallback) {
  if (!color) return fallback;
  if (typeof color === 'object') return hex6(color.color || color.stops?.[0]?.color) || fallback;
  const raw = String(color);
  if (/^(#|rgb|hsl)/i.test(raw) || raw.includes('gradient')) return hex6(raw) || fallback;
  return hex6(palette[raw.toLowerCase()]) || fallback;
}

function normalizeChartType(type) {
  const t = String(type || 'column').toLowerCase();
  return t === 'doughnut' ? 'donut' : t;
}

/** Editor getSeriesData: the first series only, with the editor's placeholder data. */
function seriesData(normalized) {
  const labels = normalized?.data?.labels || normalized?.labels || ['A', 'B', 'C', 'D'];
  const series = normalized?.data?.series || normalized?.series || [{ name: 'Series', values: [12, 19, 14, 22] }];
  let values = Array.isArray(series[0]?.values)
    ? series[0].values
    : Array.isArray(series) && typeof series[0] === 'number'
      ? series
      : null;
  if (!Array.isArray(values) || !values.length) values = [12, 19, 14, 22];
  return { labels, values: values.map((v) => Number(v) || 0), seriesName: series[0]?.name || 'Series' };
}

/**
 * What the editor draws for a chart element.
 * @returns {{ kind: 'kpi'|'pie'|'donut'|'line'|'area'|'bar'|'column', labels: string[],
 *   values: number[], seriesName: string, colors: string[], showLegend: boolean,
 *   kpi?: { value: string, label: string } }}
 */
function editorChartSpec(content = {}, palette = {}) {
  const normalized = normalizeChartContent(content, palette);
  const type = normalizeChartType(normalized.chartType);
  const { labels, values, seriesName } = seriesData(normalized);
  const provided = (normalized.colors || ['#475569']).map((c) => resolveChartColor(c, palette, null));
  const base = { labels: labels.map((l) => String(l ?? '')), values, seriesName, showLegend: false };

  if (type === 'kpi') {
    return {
      ...base,
      kind: 'kpi',
      colors: [hex6(palette.primary) || '#334155'],
      kpi: { value: String(values[0] ?? content.kpiValue ?? '42%'), label: String(content.kpiLabel || content.title || 'Metric') },
    };
  }
  if (type === 'pie' || type === 'donut') {
    const colors = values.map((_, i) => {
      const color = provided[i % provided.length];
      if (type === 'pie') return color || '#64748B';
      return isColorVibrant(color) ? color : DONUT_COLORS[i % DONUT_COLORS.length];
    });
    return { ...base, kind: type, colors, showLegend: normalized.showLabels !== false && labels.length > 0 };
  }
  if (type.includes('line') || type.includes('area')) {
    const color =
      [provided[0], hex6(palette.accent), hex6(palette.primary), '#6366F1'].find(isColorVibrant) ||
      provided[0] ||
      hex6(palette.primary) ||
      '#6366F1';
    return { ...base, kind: type.includes('area') ? 'area' : 'line', colors: [color] };
  }
  const defaults = barDefaultColors(palette).map((c) => hex6(c) || c);
  const colors = values.map((_, i) => {
    const raw = provided[i % provided.length] || defaults[i % defaults.length];
    return isColorVibrant(raw) ? raw : defaults[i % defaults.length];
  });
  const horizontal = type.includes('bar') && !type.includes('column');
  return { ...base, kind: horizontal ? 'bar' : 'column', colors };
}

const noHash = (c) => String(c).replace(/^#/, '').toUpperCase();

/**
 * pptxgenjs addChart arguments for a spec (not for kpi: that is text).
 * @param {object} spec        editorChartSpec(...)
 * @param {object} pptx        the PptxGenJS instance (chart type enum)
 * @param {object} box         { x, y, w, h } inches
 * @param {object} opts        { pt: stage px → points, dark: dark slide, fontFace }
 */
function pptxChartArgs(spec, pptx, box, { pt, dark = false, fontFace = null } = {}) {
  const ChartType = pptx.ChartType || pptx.charts || {};
  const ink = dark ? 'CBD5E1' : '6B7280';
  const grid = dark ? '334155' : 'E2E8F0';
  const data = [{ name: spec.seriesName, labels: spec.labels, values: spec.values }];
  const common = {
    x: box.x,
    y: box.y,
    w: box.w,
    h: box.h,
    showTitle: false,
    ...(fontFace ? { catAxisLabelFontFace: fontFace, dataLabelFontFace: fontFace, legendFontFace: fontFace } : {}),
  };

  if (spec.kind === 'pie' || spec.kind === 'donut') {
    const donut = spec.kind === 'donut';
    return {
      type: donut ? ChartType.doughnut || 'doughnut' : ChartType.pie || 'pie',
      data,
      options: {
        ...common,
        chartColors: spec.colors.map(noHash),
        showLegend: spec.showLegend,
        legendPos: 'b',
        legendFontSize: pt(9),
        legendColor: dark ? 'CBD5E1' : '475569',
        showValue: false,
        // The editor prints each slice's % on donuts only.
        showPercent: donut,
        showLabel: false,
        dataLabelColor: 'FFFFFF',
        dataLabelFontSize: pt(5.2 * 2.2),
        dataLabelFontBold: true,
        ...(donut ? { holeSize: 55 } : {}),
        // White gaps between donut slices, like the editor.
        dataBorder: donut ? { pt: 2, color: dark ? '0F172A' : 'FFFFFF' } : { pt: 0.5, color: dark ? '0F172A' : 'FFFFFF' },
      },
    };
  }

  const axes = {
    valAxisHidden: true,
    valGridLine: { color: grid, style: 'dash', size: 0.75 },
    catGridLine: { style: 'none' },
    catAxisLineShow: false,
    catAxisLabelColor: ink,
    catAxisLabelFontSize: pt(11),
    showLegend: false,
  };

  if (spec.kind === 'line' || spec.kind === 'area') {
    const color = noHash(spec.colors[0]);
    const lineOptions = {
      chartColors: [color],
      lineSize: 2.5,
      lineSmooth: true,
      lineDataSymbol: 'circle',
      lineDataSymbolSize: 7,
      lineDataSymbolLineColor: color,
    };
    if (spec.kind === 'area') {
      // The editor draws an area chart as a smooth line with dots over a soft fill. A native
      // area series has no outline or markers, so it's a combo: the fill, then the line on top.
      return {
        combo: [
          { type: ChartType.area || 'area', data, options: { chartColors: [color], chartColorsOpacity: 30 } },
          { type: ChartType.line || 'line', data, options: lineOptions },
        ],
        options: { ...common, ...axes },
      };
    }
    return {
      type: ChartType.line || 'line',
      data,
      options: { ...common, ...axes, ...lineOptions },
    };
  }

  return {
    type: ChartType.bar || 'bar',
    data,
    options: {
      ...common,
      ...axes,
      barDir: spec.kind === 'bar' ? 'bar' : 'col',
      // One colour per bar (pptxgenjs writes <c:dPt> for a single series with several colours).
      chartColors: spec.colors.map(noHash),
      barGapWidthPct: 40,
      showValue: true,
      dataLabelPosition: 'outEnd',
      dataLabelColor: dark ? 'E2E8F0' : '334155',
      dataLabelFontSize: pt(11),
      dataLabelFontBold: true,
    },
  };
}

module.exports = {
  editorChartSpec,
  pptxChartArgs,
  isColorVibrant,
  DONUT_COLORS,
};
