const { DECK_LAYOUT_SLIDE_PURPOSES } = require('./deckLayout.constants');

const CONTENT_TYPE_FROM_CATALOG = {
  title: 'cover',
  section_divider: 'introduction',
  closing: 'conclusion',
  team: 'team',
  pricing: 'pricing',
  comparison: 'competition',
  timeline: 'roadmap',
  diagram: 'process',
  chart: 'statistics',
  stat: 'statistics',
  quote: 'benefits',
  'image+text': 'features',
  bullet_list: 'features',
  grid: 'features',
  agenda: 'introduction',
  device_frames: 'product',
};

function strLen(value) {
  if (value == null) return 0;
  return String(value).trim().length;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function listLen(value) {
  return asArray(value).length;
}

function hasChartPayload(chart) {
  if (!chart || typeof chart !== 'object') return false;
  return Boolean(
    (Array.isArray(chart.labels) && chart.labels.length) ||
      (Array.isArray(chart.series) && chart.series.length) ||
      (Array.isArray(chart.data) && chart.data.length)
  );
}

function hasTablePayload(table) {
  if (!table || typeof table !== 'object') return false;
  return Boolean(
    (Array.isArray(table.headers) && table.headers.length) ||
      (Array.isArray(table.rows) && table.rows.length) ||
      (Array.isArray(table.cells) && table.cells.length)
  );
}

function imageCountOf(input) {
  if (typeof input.imageCount === 'number' && input.imageCount >= 0) return input.imageCount;
  if (Array.isArray(input.images)) return input.images.filter(Boolean).length;
  if (input.image || input.imageUrl || input.heroImage) return 1;
  return 0;
}

function inferPurpose(input) {
  const raw = String(input.purpose || input.intent || input.slidePurpose || '').trim().toLowerCase();
  if (DECK_LAYOUT_SLIDE_PURPOSES.includes(raw)) return raw;
  const suggested = String(input.suggestedContentType || input.contentType || '').trim().toLowerCase();
  if (CONTENT_TYPE_FROM_CATALOG[suggested]) return CONTENT_TYPE_FROM_CATALOG[suggested];
  if (DECK_LAYOUT_SLIDE_PURPOSES.includes(suggested)) return suggested;
  return raw || 'introduction';
}

function inferContentTypes(input, counts) {
  if (Array.isArray(input.contentTypes) && input.contentTypes.length) {
    return [...new Set(input.contentTypes.map((t) => String(t).toLowerCase()))];
  }
  const types = [];
  if (counts.titleLength > 0) types.push('title');
  if (counts.subtitleLength > 0) types.push('subtitle');
  if (counts.bodyLength > 0 && counts.bulletCount === 0) types.push('paragraph');
  if (counts.bulletCount > 0) types.push('bullets');
  if (counts.imageCount > 0) types.push('image');
  if (counts.metricCount > 0) {
    types.push('statistic');
    types.push('metrics');
  }
  if (counts.cardCount > 0) types.push('cards');
  if (counts.hasChart) types.push('chart');
  if (counts.hasTable) types.push('table');
  if (counts.hasQuote) types.push('quote');
  return [...new Set(types)];
}

function inferDensity({ bodyLength, bulletCount, cardCount, metricCount, hasChart, hasTable }) {
  const heavy =
    bodyLength >= 280 ||
    bulletCount >= 6 ||
    cardCount >= 5 ||
    metricCount >= 5 ||
    (hasChart && bodyLength > 120);
  const light =
    bodyLength <= 80 &&
    bulletCount <= 2 &&
    cardCount <= 2 &&
    metricCount <= 2 &&
    !hasChart &&
    !hasTable;
  if (heavy) return 'high';
  if (light) return 'low';
  return 'medium';
}

/**
 * Normalize generated slide / outline content into SlideContentProfile.
 * @param {object} [input]
 */
function toSlideContentProfile(input = {}) {
  const titleLength = typeof input.titleLength === 'number' ? input.titleLength : strLen(input.title);
  const subtitleLength =
    typeof input.subtitleLength === 'number' ? input.subtitleLength : strLen(input.subtitle);
  const bodyLength =
    typeof input.bodyLength === 'number'
      ? input.bodyLength
      : strLen(input.body) + strLen(input.summary);

  const bulletCount =
    typeof input.bulletCount === 'number' ? input.bulletCount : listLen(input.bullets);

  const metricCount =
    typeof input.metricCount === 'number'
      ? input.metricCount
      : Math.max(listLen(input.stats), listLen(input.metrics));

  const cardCount =
    typeof input.cardCount === 'number'
      ? input.cardCount
      : Math.max(
          listLen(input.cards),
          listLen(input.members),
          listLen(input.plans),
          listLen(input.columns),
          listLen(input.agenda?.columns),
          listLen(input.beats),
          listLen(input.diagram?.cells),
          listLen(input.cells)
        );

  const columnCount =
    typeof input.columnCount === 'number'
      ? input.columnCount
      : Math.max(
          listLen(input.columns),
          listLen(input.agenda?.columns),
          listLen(input.beats),
          cardCount || 0
        ) || undefined;

  const hasChart = input.hasChart != null ? Boolean(input.hasChart) : hasChartPayload(input.chart);
  const hasTable = input.hasTable != null ? Boolean(input.hasTable) : hasTablePayload(input.table);
  const hasQuote =
    input.hasQuote != null ? Boolean(input.hasQuote) : Boolean(strLen(input.quote) || input.hasQuote);

  const imageCount = imageCountOf(input);

  const counts = {
    titleLength,
    subtitleLength,
    bodyLength,
    bulletCount,
    imageCount,
    metricCount,
    cardCount,
    hasChart,
    hasTable,
    hasQuote,
  };

  const density =
    input.density === 'low' || input.density === 'medium' || input.density === 'high'
      ? input.density
      : (() => {
          const wizard = String(input.wizardDensity || input.textDensityWizard || '').toLowerCase();
          if (wizard === 'detailed' || wizard === 'extensive') return 'high';
          if (wizard === 'concise' || wizard === 'minimal') {
            const inferred = inferDensity(counts);
            return inferred === 'high' ? 'medium' : 'low';
          }
          return inferDensity(counts);
        })();

  const profile = {
    slideNumber: input.slideNumber != null ? Number(input.slideNumber) : undefined,
    purpose: inferPurpose(input),
    contentTypes: inferContentTypes(input, counts),
    titleLength,
    subtitleLength,
    bodyLength,
    bulletCount,
    cardCount,
    imageCount,
    metricCount,
    columnCount: columnCount || undefined,
    hasChart,
    hasTable,
    hasQuote,
    density,
    wizardDensity: String(input.wizardDensity || '').toLowerCase() || undefined,
    allowPureImageGrid: input.allowPureImageGrid === true,
    wordCount: Math.max(
      0,
      Math.round((titleLength + subtitleLength + bodyLength) / 6) +
        Math.max(0, bulletCount * 8) +
        Math.max(0, cardCount * 10)
    ),
    textDensity: density,
    visualWeight:
      hasChart || hasTable || metricCount >= 3
        ? 'data-heavy'
        : imageCount > 0 && bodyLength < 140 && density !== 'high'
          ? 'image-heavy'
          : bodyLength >= 180 || bulletCount >= 5 || density === 'high'
            ? 'text-heavy'
            : 'balanced',
    contentStructure:
      hasChart || hasTable
        ? 'data'
        : cardCount >= 3
          ? 'cards'
          : bulletCount >= 3
            ? 'list'
            : imageCount > 0 && density !== 'high'
              ? 'visual'
              : 'narrative',
    chartType: String(input.chartType || input.chart?.type || '').toLowerCase() || undefined,
    hasTimeline: Boolean(input.hasTimeline || listLen(input.timeline?.steps) || listLen(input.steps)),
    hasPricing: Boolean(input.hasPricing || listLen(input.plans) >= 2 || listLen(input.pricing?.tiers) >= 2),
    hasTeam: Boolean(input.hasTeam || listLen(input.members) >= 2 || listLen(input.team) >= 2),
    hasContact: Boolean(
      input.hasContact ||
        input.contact ||
        input.cta ||
        /contact|connect|team|cta|invite|booking|email|phone/i.test(
          String(input.purpose || input.intent || input.title || '')
        )
    ),
    hasDeviceMockup: Boolean(input.hasDeviceMockup || input.mockup || input.deviceMockup || input.appScreenshot),
    preferredStyles: asArray(input.preferredStyles).map((s) => String(s).toLowerCase()),
    preferredMoods: asArray(input.preferredMoods).map((s) => String(s).toLowerCase()),
    industry: input.industry ? String(input.industry).toLowerCase() : undefined,
  };

  if (!profile.preferredStyles.length) delete profile.preferredStyles;
  if (!profile.preferredMoods.length) delete profile.preferredMoods;
  if (!profile.industry) delete profile.industry;
  if (profile.slideNumber == null || Number.isNaN(profile.slideNumber)) delete profile.slideNumber;

  return profile;
}

module.exports = {
  toSlideContentProfile,
};
