/** Normalize chart payloads from AI / layout compile into renderer-friendly shape. */

function coerceNumbers(values = []) {
  return (Array.isArray(values) ? values : [])
    .map((v) => Number(v))
    .filter((v) => !Number.isNaN(v));
}

function extractChartSeriesValues(chartData = {}) {
  const series = chartData.series;
  if (Array.isArray(series?.[0]?.values)) return coerceNumbers(series[0].values);
  if (Array.isArray(chartData.values)) return coerceNumbers(chartData.values);
  if (Array.isArray(chartData.data) && typeof chartData.data[0] === 'number') {
    return coerceNumbers(chartData.data);
  }
  if (Array.isArray(series) && typeof series[0] === 'number') return coerceNumbers(series);
  if (Array.isArray(series) && series[0] && typeof series[0] === 'object') {
    const fromObjects = series
      .map((row) => Number(row.value ?? row.y ?? row.v))
      .filter((v) => !Number.isNaN(v));
    if (fromObjects.length) return fromObjects;
  }
  // Chart.js-style: { datasets: [{ data: [...] }] }
  if (Array.isArray(chartData.datasets?.[0]?.data)) {
    return coerceNumbers(chartData.datasets[0].data);
  }
  if (chartData.data && typeof chartData.data === 'object' && !Array.isArray(chartData.data)) {
    if (Array.isArray(chartData.data.datasets?.[0]?.data)) {
      return coerceNumbers(chartData.data.datasets[0].data);
    }
  }
  return [];
}

function normalizeChartType(chartType) {
  const type = String(chartType || 'column-grouped').toLowerCase();
  if (type === 'doughnut') return 'donut';
  if (type === 'bar') return 'column-grouped';
  return type;
}

function mixHex(hex, toward, amount) {
  const raw = String(hex || '').replace('#', '');
  if (!/^[0-9a-fA-F]{6}$/.test(raw)) return hex;
  const t = String(toward || 'ffffff').replace('#', '');
  if (!/^[0-9a-fA-F]{6}$/.test(t)) return `#${raw}`;
  const a = Math.max(0, Math.min(1, Number(amount) || 0));
  const mix = (i) => {
    const from = parseInt(raw.slice(i, i + 2), 16);
    const to = parseInt(t.slice(i, i + 2), 16);
    return Math.round(from + (to - from) * a)
      .toString(16)
      .padStart(2, '0');
  };
  return `#${mix(0)}${mix(2)}${mix(4)}`;
}

/**
 * Premium multi-stop palette from deck theme — never a single flat purple.
 * @param {object} palette
 * @param {number} count
 * @returns {string[]}
 */
function buildPremiumChartColors(palette = {}, count = 5) {
  const n = Math.max(2, Math.min(12, Number(count) || 5));
  const primary = palette.primary || palette.accent || '#3B82F6';
  const secondary = palette.secondary || palette.accent || primary;
  const accent = palette.accent || secondary;
  const seeds = [primary, secondary, accent].filter(Boolean);
  const uniqueSeeds = [...new Set(seeds.map((c) => String(c).toLowerCase()))].map((lower) =>
    seeds.find((c) => String(c).toLowerCase() === lower)
  );

  const out = [];
  const push = (c) => {
    if (!c) return;
    const key = String(c).toLowerCase();
    if (out.some((x) => String(x).toLowerCase() === key)) return;
    out.push(c);
  };

  uniqueSeeds.forEach(push);
  // Soft tints / deeper shades for a curated premium look
  uniqueSeeds.forEach((c) => {
    push(mixHex(c, 'ffffff', 0.28));
    push(mixHex(c, '0f172a', 0.22));
  });
  if (palette.muted && String(palette.muted).startsWith('#')) push(palette.muted);

  // Guarantee enough stops
  let i = 0;
  while (out.length < n && i < 8) {
    const base = uniqueSeeds[i % uniqueSeeds.length] || primary;
    push(mixHex(base, i % 2 === 0 ? 'ffffff' : '1e293b', 0.15 + (i % 4) * 0.08));
    i += 1;
  }

  while (out.length < n) out.push(primary);
  return out.slice(0, Math.max(n, out.length));
}

function resolveChartColors(raw = {}, palette = {}, valueCount = 5) {
  const brand = raw.brandChartColors || raw.chartColors;
  const candidates = [
    Array.isArray(raw.colors) && raw.colors.length ? raw.colors : null,
    Array.isArray(brand) && brand.length ? brand : null,
  ].find(Boolean);

  if (candidates && candidates.length >= 2) {
    return candidates;
  }
  if (candidates && candidates.length === 1) {
    // Expand a single brand color into a premium family
    return buildPremiumChartColors({ ...palette, primary: candidates[0] }, Math.max(valueCount, 5));
  }
  return buildPremiumChartColors(palette, Math.max(valueCount, 5));
}

function normalizeChartContent(raw = {}, palette = {}) {
  const labels = Array.isArray(raw.labels)
    ? raw.labels
    : Array.isArray(raw.data?.labels)
      ? raw.data.labels
      : [];
  let values = extractChartSeriesValues(raw);
  if (!values.length && Array.isArray(raw.data?.series?.[0]?.values)) {
    values = coerceNumbers(raw.data.series[0].values);
  }

  if (!values.length && labels.length) {
    const step = Math.max(8, Math.round(100 / labels.length));
    values = labels.map((_, i) => Math.max(5, 100 - i * step));
  }

  const seriesName =
    raw.data?.series?.[0]?.name ||
    raw.series?.[0]?.name ||
    (typeof raw.series?.[0] === 'object' ? raw.series[0].name : null) ||
    'Series';

  const chartType = normalizeChartType(raw.chartType || raw.type);
  const seriesPayload = [{ name: seriesName, values }];
  const colors = resolveChartColors(raw, palette, values.length || labels.length || 5);

  return {
    chartType,
    labels,
    series: seriesPayload,
    data: { labels, series: seriesPayload },
    colors,
    premium: raw.premium !== false,
    showGrid: raw.showGrid !== false,
    showLabels: raw.showLabels !== false,
  };
}

module.exports = {
  normalizeChartContent,
  extractChartSeriesValues,
  normalizeChartType,
  buildPremiumChartColors,
};
