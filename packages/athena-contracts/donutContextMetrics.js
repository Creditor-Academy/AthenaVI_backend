/**
 * Map slide content → chart_donut_context chrome slot ids (METRIC_*, PANEL_*).
 */

function mapDonutContextMetrics(content, schema, out = {}) {
  const layoutId = String(schema?.layout_id || '').toLowerCase();
  if (!/chart_donut_context/.test(layoutId)) return out;

  const chart = content?.chart && typeof content.chart === 'object' ? content.chart : null;
  const labels = chart?.labels || chart?.series?.[0]?.labels || [];
  const values =
    chart?.series?.[0]?.values ||
    chart?.values ||
    chart?.data ||
    (Array.isArray(content?.stats) ? content.stats.map((s) => s?.value ?? s?.number) : []);

  const ids = ['A', 'B', 'C', 'D'];
  ids.forEach((id, index) => {
    const stat = Array.isArray(content?.stats) ? content.stats[index] : null;
    const label = String(
      stat?.label ?? stat?.title ?? labels[index] ?? out[`METRIC_${id}_LABEL`] ?? ''
    ).trim();
    const rawVal = stat?.value ?? stat?.number ?? values[index];
    const value =
      rawVal != null && rawVal !== ''
        ? String(rawVal).includes('%')
          ? String(rawVal)
          : `${rawVal}%`
        : '';
    const desc = String(stat?.body ?? stat?.description ?? stat?.text ?? '').trim();
    if (label) out[`METRIC_${id}_LABEL`] = label;
    if (value) out[`METRIC_${id}_VALUE`] = value;
    if (desc) out[`METRIC_${id}_DESC`] = desc;
  });

  if (content?.title) out.PANEL_HEADING = out.PANEL_HEADING || content.title;
  const insight = String(content.body || content.summary || '').trim();
  if (insight) out.PANEL_SUBHEADING = out.PANEL_SUBHEADING || insight;

  const badge = String(content?.chart?.badge || content?.badge || '').trim();
  if (badge) out.BADGE = badge;

  return out;
}

function textForDonutContextSlot(slotId, content, layoutSchema, textForSlot) {
  const mapped = mapDonutContextMetrics(content, layoutSchema, {});
  const key = String(slotId || '').toUpperCase();
  if (mapped[key]) return mapped[key];
  return textForSlot ? textForSlot(slotId, content, layoutSchema) : '';
}

module.exports = {
  mapDonutContextMetrics,
  textForDonutContextSlot,
};

// ESM interop for frontend bundle
if (typeof exports !== 'undefined') {
  exports.mapDonutContextMetrics = mapDonutContextMetrics;
  exports.textForDonutContextSlot = textForDonutContextSlot;
}
