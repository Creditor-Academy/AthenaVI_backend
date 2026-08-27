/**
 * Infer chart data story from slide content — drives chart.type and layout selection.
 * Layout is chosen from the data shape, not a fixed template per deck.
 */

function chartDatasetCount(content = {}) {
  if (!content || typeof content !== 'object') return 0;
  if (Array.isArray(content.charts) && content.charts.length) {
    return content.charts.filter(
      (chart) => chart && (chart.labels?.length || chart.series?.length || chart.data?.length)
    ).length;
  }
  let count = 0;
  if (content.chart?.labels?.length || content.chart?.series?.length || content.chart?.data?.length) {
    count += 1;
  }
  if (content.chart2?.labels?.length || content.chart2?.series?.length || content.chart2?.data?.length) {
    count += 1;
  }
  return count;
}

function chartValues(chart) {
  if (!chart || typeof chart !== 'object') return [];
  const raw = chart.series?.[0]?.values || chart.data || chart.values || [];
  return (Array.isArray(raw) ? raw : []).map(Number).filter((value) => !Number.isNaN(value));
}

function chartLooksLikeComposition(chart) {
  const nums = chartValues(chart);
  if (nums.length < 3) return false;
  const sum = nums.reduce((total, value) => total + value, 0);
  return sum >= 85 && sum <= 115;
}

function chartLabelLooksTemporal(labels) {
  const arr = Array.isArray(labels) ? labels : [];
  if (arr.length < 2) return false;
  const temporal = arr.filter((label) =>
    /^(19|20)\d{2}$|^Q[1-4]\b|^(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/i.test(String(label).trim())
  );
  return temporal.length >= Math.ceil(arr.length * 0.6);
}

function slideText(content = {}) {
  return `${content.title || ''} ${content.summary || ''} ${content.body || ''}`.toLowerCase();
}

/**
 * @returns {{
 *   story: 'dual_metrics'|'trend'|'composition'|'ranking'|'simple'|'unknown',
 *   chartType: string|null,
 *   layoutId: string|null,
 *   needsBody: boolean,
 * }}
 */
function analyzeChartStory(content = {}) {
  const chart = content?.chart;
  const datasets = chartDatasetCount(content);
  const text = slideText(content);

  const compareLike = /compare|versus|\bvs\b|before.*after|two metrics|dual chart|side by side/.test(text);
  if (datasets >= 2 || compareLike) {
    return { story: 'dual_metrics', chartType: null, layoutId: 'chart_two_v1', needsBody: false };
  }

  if (!chart || typeof chart !== 'object') {
    if (/trend|growth|over time|trajectory|forecast|year-over-year|yoy/.test(text)) {
      return { story: 'trend', chartType: 'line', layoutId: 'chart_exponential_desc_v1', needsBody: true };
    }
    return { story: 'unknown', chartType: null, layoutId: null, needsBody: false };
  }

  const labels = Array.isArray(chart.labels) ? chart.labels : [];
  const explicitType = String(chart.type || chart.chartType || '').trim().toLowerCase();
  const isComposition =
    ['pie', 'donut', 'doughnut'].includes(explicitType) || chartLooksLikeComposition(chart);
  const isTemporal =
    chartLabelLooksTemporal(labels) ||
    /trend|growth|over time|trajectory|forecast|year-over-year|yoy/.test(text);
  const isShareNarrative = /market share|share of|percent|percentage|breakdown|composition|mix|portfolio split|portion of total/.test(
    text
  );

  if (isTemporal) {
    return {
      story: 'trend',
      chartType: explicitType || 'line',
      layoutId: 'chart_exponential_desc_v1',
      needsBody: true,
    };
  }

  if (isComposition && (isShareNarrative || chartLooksLikeComposition(chart))) {
    return {
      story: 'composition',
      chartType: explicitType || 'donut',
      layoutId: 'chart_donut_context_v1',
      needsBody: true,
    };
  }

  const isRanking = /top \d|leading|largest|biggest|rank|by country|by region|producers|production volume/.test(text);
  if (isRanking || labels.length >= 4) {
    return {
      story: 'ranking',
      chartType: explicitType || 'bar',
      layoutId: 'chart_with_description_v1',
      needsBody: true,
    };
  }

  if (labels.length >= 2) {
    return {
      story: 'simple',
      chartType: explicitType || 'bar',
      layoutId: 'chart_single_v1',
      needsBody: false,
    };
  }

  return {
    story: 'simple',
    chartType: explicitType || 'bar',
    layoutId: 'chart_single_v1',
    needsBody: false,
  };
}

function inferChartTypeFromStory(chart, content = {}, layoutSchema = null) {
  const explicit = String(chart?.type || chart?.chartType || '').trim().toLowerCase();
  if (explicit) return explicit;

  const layoutId = String(layoutSchema?.layout_id || '').toLowerCase();
  if (/donut|pie/.test(layoutId)) return 'donut';
  if (/line|exponential|area/.test(layoutId)) return 'line';

  const analysis = analyzeChartStory({ ...content, chart });
  return analysis.chartType || 'bar';
}

/**
 * True only when the slide has a real quantitative reason to be a chart.
 * Blocks invented bars for qualitative topics (security, features, benefits).
 */
function slideJustifiesChart({ content = {}, outlineSlide = {}, contentType, visualNeed } = {}) {
  const type = String(contentType || content?.content_type || '').toLowerCase();
  const need = String(visualNeed || content?.visual_need || '').toLowerCase();
  if (type !== 'chart' && need !== 'chart') return true;

  const hay = [
    content?.title,
    content?.summary,
    content?.body,
    content?.subtitle,
    Array.isArray(content?.bullets) ? content.bullets.join(' ') : '',
    outlineSlide?.title,
    outlineSlide?.summary,
    outlineSlide?.subtitle,
    Array.isArray(outlineSlide?.beats) ? outlineSlide.beats.join(' ') : '',
    outlineSlide?.visual,
  ]
    .filter(Boolean)
    .join(' ');

  // Clear quantitative signals in copy
  if (
    /\b(\d+\s*%|\d+\.\d+\s*%|\$\s*\d|\d+\s*(million|billion|k|m|bn)|revenue|arr\b|mrr\b|growth rate|market share|nps\b|cac\b|ltv\b|churn|conversion rate|yoy|qoq|quarterly|forecast|benchmark)\b/i.test(
      hay
    )
  ) {
    return true;
  }
  if (/\b(chart|graph|kpi|metrics?|statistics|analytics)\b/i.test(hay) && /\d/.test(hay)) {
    return true;
  }

  const chart = content?.chart;
  if (chart && typeof chart === 'object') {
    if (chartLabelLooksTemporal(chart.labels)) return true;
    if (chartLooksLikeComposition(chart)) return true;
    const labels = Array.isArray(chart.labels) ? chart.labels : [];
    // Labels that are just qualitative pillars (no units / periods) → not a real chart need
    const qualitativeOnly =
      labels.length > 0 &&
      labels.every((label) => {
        const s = String(label || '').trim();
        return s && !/\d|%|q[1-4]|20\d{2}|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec/i.test(s);
      });
    if (qualitativeOnly && /security|isolation|compliance|encryption|audit|feature|benefit|risk reduction/i.test(hay)) {
      return false;
    }
  }

  // Qualitative topic words without numbers → demote
  if (
    /security|isolation|compliance|encryption|audit trail|tenant isolation|key management|feature|benefit/i.test(
      hay
    ) &&
    !/\d/.test(hay)
  ) {
    return false;
  }

  // No numbers anywhere in the narrative → do not force a chart layout
  if (!/\d/.test(hay)) return false;

  return true;
}

/**
 * If chart was chosen without quantitative basis, fall back to image+text + photo.
 */
function demoteSpuriousChart({ contentType, visualNeed, content, outlineSlide, preferVisuals = true } = {}) {
  if (slideJustifiesChart({ content, outlineSlide, contentType, visualNeed })) {
    return { contentType, visualNeed, demoted: false };
  }
  return {
    contentType: 'image+text',
    visualNeed: preferVisuals === false ? 'none' : 'photo',
    demoted: true,
  };
}

module.exports = {
  analyzeChartStory,
  chartDatasetCount,
  chartLooksLikeComposition,
  chartLabelLooksTemporal,
  inferChartTypeFromStory,
  slideJustifiesChart,
  demoteSpuriousChart,
};
