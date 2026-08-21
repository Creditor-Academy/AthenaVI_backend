const { CONTENT_TYPE_TO_SUPPORTED } = require('./layoutScoring.weights');

function supportedOf(layout) {
  return layout?.supportedElements && typeof layout.supportedElements === 'object'
    ? layout.supportedElements
    : null;
}

function capacityOf(layout) {
  return layout?.contentCapacity && typeof layout.contentCapacity === 'object'
    ? layout.contentCapacity
    : {};
}

function maxField(capacity, key) {
  if (capacity[key] == null || capacity[key] === '') return null;
  const n = Number(capacity[key]);
  if (!Number.isFinite(n)) return null;
  return n;
}

function isUnknownSupport(supported, key) {
  if (!supported) return true;
  return typeof supported[key] !== 'boolean';
}

function quoteIsPrimary(slide) {
  if (!slide.hasQuote) return false;
  const types = Array.isArray(slide.contentTypes) ? slide.contentTypes : [];
  if (types.includes('quote')) return true;
  return slide.bodyLength === 0 && slide.bulletCount === 0 && !slide.hasChart;
}

function cardsRequired(slide) {
  const types = Array.isArray(slide.contentTypes) ? slide.contentTypes : [];
  return slide.cardCount >= 2 && types.includes('cards');
}

function metricsRequired(slide) {
  const types = Array.isArray(slide.contentTypes) ? slide.contentTypes : [];
  const purpose = String(slide.purpose || '').toLowerCase();
  return (
    slide.metricCount >= 2 &&
    (types.includes('metrics') || types.includes('statistic') || purpose === 'statistics' || purpose === 'traction')
  );
}

function imageRequired(slide) {
  const types = Array.isArray(slide.contentTypes) ? slide.contentTypes : [];
  return slide.imageCount > 0 && types.includes('image');
}

/**
 * @returns {{ status: 'hardReject' | 'ok', reasons: string[], penalties: object[] }}
 */
function evaluateLayoutCompatibility(slide, layout) {
  const reasons = [];
  const penalties = [];
  const supported = supportedOf(layout);
  const capacity = capacityOf(layout);

  const pushSoft = (field, message) => {
    penalties.push({ kind: 'softPenalty', field, message });
  };

  if (slide.hasChart && !isUnknownSupport(supported, 'chart') && supported.chart !== true) {
    return {
      status: 'hardReject',
      reasons: ['Layout does not support charts'],
      penalties,
    };
  }

  if (slide.hasTable && !isUnknownSupport(supported, 'table') && supported.table !== true) {
    return {
      status: 'hardReject',
      reasons: ['Layout does not support tables'],
      penalties,
    };
  }

  if (quoteIsPrimary(slide) && !isUnknownSupport(supported, 'quote') && supported.quote !== true) {
    return {
      status: 'hardReject',
      reasons: ['Layout does not support a quote as primary content'],
      penalties,
    };
  }

  if (cardsRequired(slide)) {
    const maxCards = maxField(capacity, 'maxCards');
    const noCards =
      (!isUnknownSupport(supported, 'cards') && supported.cards === false) || maxCards === 0;
    if (noCards) {
      return {
        status: 'hardReject',
        reasons: ['Layout cannot render required cards'],
        penalties,
      };
    }
  }

  if (metricsRequired(slide)) {
    const maxMetrics = maxField(capacity, 'maxMetrics');
    const noMetrics =
      (!isUnknownSupport(supported, 'metrics') && supported.metrics === false) || maxMetrics === 0;
    if (noMetrics) {
      return {
        status: 'hardReject',
        reasons: ['Layout cannot render required metrics'],
        penalties,
      };
    }
  }

  if (slide.hasTimeline) {
    const timelineCapable =
      layout?.contentTypes?.includes?.('timeline') ||
      layout?.tags?.includes?.('timeline') ||
      layout?.supportedElements?.cards === true;
    if (!timelineCapable) {
      pushSoft('timeline', 'Timeline content may not fit this layout structure');
    }
  }

  if (slide.hasPricing) {
    const pricingCapable =
      layout?.category === 'pricing' || layout?.slidePurposes?.includes?.('pricing') || layout?.supportedElements?.cards;
    if (!pricingCapable) {
      pushSoft('pricing', 'Pricing comparison content may not fit this layout');
    }
  }

  if (imageRequired(slide) && !isUnknownSupport(supported, 'image') && supported.image === false) {
    return {
      status: 'hardReject',
      reasons: ['Layout cannot render the required image'],
      penalties,
    };
  }

  const checks = [
    ['maxTitleCharacters', slide.titleLength, 'title length'],
    ['maxSubtitleCharacters', slide.subtitleLength, 'subtitle length'],
    ['maxBodyCharacters', slide.bodyLength, 'body length'],
    ['maxBullets', slide.bulletCount, 'bullet count'],
    ['maxCards', slide.cardCount, 'card count'],
    ['maxImages', slide.imageCount, 'image count'],
    ['maxMetrics', slide.metricCount, 'metric count'],
    ['maxColumns', slide.columnCount || 0, 'column count'],
  ];

  for (const [key, need, label] of checks) {
    if (!need) continue;
    const max = maxField(capacity, key);
    if (max == null) continue;
    if (max > 0 && need > max) {
      pushSoft(key, `${label} ${need} exceeds ${key} ${max}`);
    }
  }

  if (slide.imageCount > 0 && !imageRequired(slide) && supported && supported.image === false) {
    pushSoft('image', 'Optional image cannot be shown on this text-only layout');
  }

  const layoutDensity = capacity.density;
  if (layoutDensity && slide.density) {
    if (
      (slide.density === 'high' && layoutDensity === 'low') ||
      (slide.density === 'low' && layoutDensity === 'high')
    ) {
      pushSoft('density', `Density mismatch (slide ${slide.density} vs layout ${layoutDensity})`);
    }
  }

  if (Array.isArray(slide.contentTypes)) {
    for (const type of slide.contentTypes) {
      const key = CONTENT_TYPE_TO_SUPPORTED[type];
      if (!key || !supported || isUnknownSupport(supported, key)) continue;
      if (supported[key] !== true && type !== 'image') {
        pushSoft(`contentTypes.${type}`, `Layout does not list support for ${type}`);
      }
    }
  }

  return { status: 'ok', reasons, penalties };
}

module.exports = {
  evaluateLayoutCompatibility,
  cardsRequired,
  metricsRequired,
  imageRequired,
};
