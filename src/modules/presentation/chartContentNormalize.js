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
  return [];
}

function normalizeChartType(chartType) {
  const type = String(chartType || 'column-grouped').toLowerCase();
  if (type === 'doughnut') return 'donut';
  if (type === 'bar') return 'column-grouped';
  return type;
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
  const colors =
    (Array.isArray(raw.colors) && raw.colors.length ? raw.colors : null) ||
    [palette?.primary || palette?.accent || '#6366F1'];

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
};
