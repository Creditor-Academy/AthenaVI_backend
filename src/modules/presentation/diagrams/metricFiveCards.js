/**
 * Metric five cards — 5 vertical metric cards with icons, values, trend indicators, and descriptions.
 * CommonJS backend port for Athena VI Presentation diagram pipeline.
 * Layout id: metric_five_cards_v1.
 */

const M5C_GEOM = {
  viewW: 1000,
  viewH: 560,

  badgeX: 435,
  badgeY: 36,
  badgeW: 130,
  badgeH: 22,
  badgeIconSize: 14,

  headingX: 40,
  headingY: 68,
  headingW: 920,
  headingH: 44,

  subheadingX: 40,
  subheadingY: 118,
  subheadingW: 920,
  subheadingH: 22,

  cardY: 152,
  cardW: 172,
  cardH: 368,
  cardGap: 15,
  card1X: 40,
  card2X: 227,
  card3X: 414,
  card4X: 601,
  card5X: 788,

  cardIconX: 16,
  cardIconY: 16,
  cardIconSize: 28,
  cardIconBgSize: 44,

  cardValueX: 16,
  cardValueY: 76,
  cardValueW: 140,
  cardValueH: 46,

  labelX: 16,
  labelY: 128,
  labelW: 140,
  labelH: 24,

  cardTrendX: 16,
  cardTrendY: 156,
  cardTrendW: 142,
  cardTrendH: 38,

  cardDescX: 16,
  cardDescY: 208,
  cardDescW: 142,
  cardDescH: 95,
};

const M5C_COLORS = {
  card1: '#3B82F6',  // Blue
  card2: '#8B5CF6',  // Purple
  card3: '#10B981',  // Green
  card4: '#F59E0B',  // Amber
  card5: '#EC4899',  // Rose
};

const M5C_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Key metrics',
  SUBHEADING: 'A quick snapshot of the most important numbers at a glance.',

  CARD1_VALUE: '98%',
  CARD1_LABEL: 'Satisfaction',
  CARD1_TREND: '+12% vs. last quarter',
  CARD1_DESC: 'Consistently high happiness and cohort retention.',

  CARD2_VALUE: '3.2x',
  CARD2_LABEL: 'Average ROI',
  CARD2_TREND: '+18% vs. last quarter',
  CARD2_DESC: 'Accelerated payback and measurable efficiency gains.',

  CARD3_VALUE: '500+',
  CARD3_LABEL: 'Active teams',
  CARD3_TREND: '+22% vs. last quarter',
  CARD3_DESC: 'Rapid ongoing adoption across enterprise workflows.',

  CARD4_VALUE: '24h',
  CARD4_LABEL: 'Response time',
  CARD4_TREND: '+35% vs. last quarter',
  CARD4_DESC: 'Round-the-clock priority resolution and live support.',

  CARD5_VALUE: '12',
  CARD5_LABEL: 'Global markets',
  CARD5_TREND: '+40% vs. last quarter',
  CARD5_DESC: 'Worldwide presence with localized support teams.',
};

function isMetricFiveCardsLayout(layoutId) {
  return /metric_five_cards_v1$/i.test(String(layoutId || ''));
}

function isMetricFiveCardsTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase();
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'CARD1_VALUE' || sid === 'STAT_1_VALUE' || sid === 'METRIC1_VALUE'
    || sid === 'CARD1_LABEL' || sid === 'STAT_1_LABEL' || sid === 'METRIC1_LABEL'
    || sid === 'CARD1_TREND' || sid === 'STAT_1_TREND' || sid === 'METRIC1_TREND'
    || sid === 'CARD1_DESC' || sid === 'STAT_1_DESC' || sid === 'METRIC1_DESC'
    || sid === 'CARD2_VALUE' || sid === 'STAT_2_VALUE' || sid === 'METRIC2_VALUE'
    || sid === 'CARD2_LABEL' || sid === 'STAT_2_LABEL' || sid === 'METRIC2_LABEL'
    || sid === 'CARD2_TREND' || sid === 'STAT_2_TREND' || sid === 'METRIC2_TREND'
    || sid === 'CARD2_DESC' || sid === 'STAT_2_DESC' || sid === 'METRIC2_DESC'
    || sid === 'CARD3_VALUE' || sid === 'STAT_3_VALUE' || sid === 'METRIC3_VALUE'
    || sid === 'CARD3_LABEL' || sid === 'STAT_3_LABEL' || sid === 'METRIC3_LABEL'
    || sid === 'CARD3_TREND' || sid === 'STAT_3_TREND' || sid === 'METRIC3_TREND'
    || sid === 'CARD3_DESC' || sid === 'STAT_3_DESC' || sid === 'METRIC3_DESC'
    || sid === 'CARD4_VALUE' || sid === 'STAT_4_VALUE' || sid === 'METRIC4_VALUE'
    || sid === 'CARD4_LABEL' || sid === 'STAT_4_LABEL' || sid === 'METRIC4_LABEL'
    || sid === 'CARD4_TREND' || sid === 'STAT_4_TREND' || sid === 'METRIC4_TREND'
    || sid === 'CARD4_DESC' || sid === 'STAT_4_DESC' || sid === 'METRIC4_DESC'
    || sid === 'CARD5_VALUE' || sid === 'STAT_5_VALUE' || sid === 'METRIC5_VALUE'
    || sid === 'CARD5_LABEL' || sid === 'STAT_5_LABEL' || sid === 'METRIC5_LABEL'
    || sid === 'CARD5_TREND' || sid === 'STAT_5_TREND' || sid === 'METRIC5_TREND'
    || sid === 'CARD5_DESC' || sid === 'STAT_5_DESC' || sid === 'METRIC5_DESC';
}

function badgeSvg() {
  const g = M5C_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.badgeW} ${g.badgeH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.badgeW}" height="${g.badgeH}" fill="#DBEAFE" rx="6"/>
  </svg>`;
}

function badgeIconSvg() {
  const size = M5C_GEOM.badgeIconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>
    <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>
    <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>
  </svg>`;
}

function cardBgSvg(color) {
  const g = M5C_GEOM;
  const cleanColor = color.replace('#', '');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.cardW} ${g.cardH}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="m5cGrad_${cleanColor}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:${color};stop-opacity:0.08" />
        <stop offset="100%" style="stop-color:${color};stop-opacity:0.15" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${g.cardW}" height="${g.cardH}" fill="url(#m5cGrad_${cleanColor})" stroke="${color}" stroke-width="1.5" stroke-opacity="0.2" rx="16"/>
  </svg>`;
}

function iconBgSvg(color) {
  const size = M5C_GEOM.cardIconBgSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="0" y="0" width="${size}" height="${size}" fill="${color}" fill-opacity="0.15" rx="11"/>
  </svg>`;
}

function card1IconSvg() {
  const size = M5C_GEOM.cardIconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size / 2}" cy="10" r="6" fill="none" stroke="currentColor" stroke-width="2.2"/>
    <path d="M${size / 2 - 6} 21 Q${size / 2} 17 ${size / 2 + 6} 21 L${size / 2 + 6} 26 L${size / 2 - 6} 26 Z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
  </svg>`;
}

function card2IconSvg() {
  const size = M5C_GEOM.cardIconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="3" y="3" width="22" height="22" rx="3" fill="none" stroke="currentColor" stroke-width="2"/>
    <rect x="6" y="11" width="3.5" height="9" fill="currentColor" rx="0.6"/>
    <rect x="12" y="8" width="3.5" height="12" fill="currentColor" rx="0.6"/>
    <rect x="18" y="14" width="3.5" height="6" fill="currentColor" rx="0.6"/>
  </svg>`;
}

function card3IconSvg() {
  const size = M5C_GEOM.cardIconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="9" cy="9" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="19" cy="9" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="14" cy="19" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <path d="M11 11 L12.5 16" stroke="currentColor" stroke-width="1.8"/>
    <path d="M17 11 L15.5 16" stroke="currentColor" stroke-width="1.8"/>
  </svg>`;
}

function card4IconSvg() {
  const size = M5C_GEOM.cardIconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size / 2}" cy="${size / 2}" r="10" fill="none" stroke="currentColor" stroke-width="2.2"/>
    <polyline points="${size / 2},${size / 2 - 5} ${size / 2},${size / 2} ${size / 2 + 4},${size / 2}" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function card5IconSvg() {
  const size = M5C_GEOM.cardIconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size / 2}" cy="${size / 2}" r="10" fill="none" stroke="currentColor" stroke-width="2"/>
    <line x1="4" y1="${size / 2}" x2="24" y2="${size / 2}" stroke="currentColor" stroke-width="1.8"/>
    <ellipse cx="${size / 2}" cy="${size / 2}" rx="4.5" ry="10" fill="none" stroke="currentColor" stroke-width="1.8"/>
  </svg>`;
}

function trendArrowSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12" width="12" height="12">
    <path d="M2 8 L6 4 L10 8" fill="none" stroke="#10B981" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function hexLum(hex) {
  const s = String(hex || '').replace('#', '');
  if (s.length !== 6) return 1;
  const r = parseInt(s.slice(0, 2), 16) / 255;
  const g = parseInt(s.slice(2, 4), 16) / 255;
  const b = parseInt(s.slice(4, 6), 16) / 255;
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function headingInk(palette = {}) {
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff';
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827';
}

function metricFiveCardsChromeSpecs() {
  const g = M5C_GEOM;
  const specs = [];

  specs.push({
    slotId: 'M5C_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: '#DBEAFE',
    layer: 3,
    kind: 'badge',
  });

  specs.push({
    slotId: 'M5C_BADGE_ICON',
    x: g.badgeX + 10,
    y: g.badgeY + 4,
    w: g.badgeIconSize,
    h: g.badgeIconSize,
    color: '#3B82F6',
    layer: 10,
    kind: 'badgeIcon',
  });

  const cards = [
    { x: g.card1X, color: M5C_COLORS.card1, id: 1 },
    { x: g.card2X, color: M5C_COLORS.card2, id: 2 },
    { x: g.card3X, color: M5C_COLORS.card3, id: 3 },
    { x: g.card4X, color: M5C_COLORS.card4, id: 4 },
    { x: g.card5X, color: M5C_COLORS.card5, id: 5 },
  ];

  cards.forEach((card) => {
    specs.push({
      slotId: `M5C_CARD${card.id}_BG`,
      x: card.x,
      y: g.cardY,
      w: g.cardW,
      h: g.cardH,
      color: card.color,
      layer: 3,
      kind: 'cardBg',
    });

    specs.push({
      slotId: `M5C_CARD${card.id}_ICON_BG`,
      x: card.x + g.cardIconX,
      y: g.cardY + g.cardIconY,
      w: g.cardIconBgSize,
      h: g.cardIconBgSize,
      color: card.color,
      layer: 5,
      kind: 'iconBg',
    });

    specs.push({
      slotId: `M5C_CARD${card.id}_ICON`,
      x: card.x + g.cardIconX + (g.cardIconBgSize - g.cardIconSize) / 2,
      y: g.cardY + g.cardIconY + (g.cardIconBgSize - g.cardIconSize) / 2,
      w: g.cardIconSize,
      h: g.cardIconSize,
      color: card.color,
      layer: 10,
      kind: `card${card.id}Icon`,
    });

    specs.push({
      slotId: `M5C_CARD${card.id}_ARROW`,
      x: card.x + g.cardTrendX,
      y: g.cardY + g.cardTrendY + 3,
      w: 12,
      h: 12,
      color: '#10B981',
      layer: 10,
      kind: 'trendArrow',
    });
  });

  return specs;
}

function metricFiveCardsOverlay(gx, gy, gw, gh) {
  const g = M5C_GEOM;
  const sx = gw / g.viewW;
  const sy = gh / g.viewH;
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  });

  const overlays = {
    badge: box(g.badgeX + g.badgeIconSize + 14, g.badgeY, g.badgeW - g.badgeIconSize - 20, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
  };

  const cardXs = [g.card1X, g.card2X, g.card3X, g.card4X, g.card5X];
  cardXs.forEach((cardX, i) => {
    const num = i + 1;
    overlays[`card${num}Value`] = box(cardX + g.cardValueX, g.cardY + g.cardValueY, g.cardValueW, g.cardValueH);
    overlays[`card${num}Label`] = box(cardX + g.labelX, g.cardY + g.labelY, g.labelW, g.labelH);
    overlays[`card${num}Trend`] = box(cardX + g.cardTrendX + 16, g.cardY + g.cardTrendY, g.cardTrendW - 16, g.cardTrendH);
    overlays[`card${num}Desc`] = box(cardX + g.cardDescX, g.cardY + g.cardDescY, g.cardDescW, g.cardDescH);
  });

  return overlays;
}

function specToMetricFiveCardsContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'cardBg') return { svg: cardBgSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'card1Icon') return { svg: card1IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card2Icon') return { svg: card2IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card3Icon') return { svg: card3IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card4Icon') return { svg: card4IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card5Icon') return { svg: card5IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'trendArrow') return { svg: trendArrowSvg(), colorMode: 'fixed', fill: spec.color };
  return null;
}

function plainTextFromContent(content = {}) {
  if (typeof content.text === 'string' && content.text.trim()) return content.text;
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map((r) => r.text || '').join('');
    if (joined.trim()) return joined;
  }
  return '';
}

function filledContent(el, slotId, style) {
  const sid = String(slotId || '').toUpperCase();
  const existing = plainTextFromContent(el?.content);
  const defaultKey = sid.replace('STAT_1_', 'CARD1_').replace('STAT_2_', 'CARD2_').replace('STAT_3_', 'CARD3_').replace('STAT_4_', 'CARD4_').replace('STAT_5_', 'CARD5_')
    .replace('METRIC1_', 'CARD1_').replace('METRIC2_', 'CARD2_').replace('METRIC3_', 'CARD3_').replace('METRIC4_', 'CARD4_').replace('METRIC5_', 'CARD5_');
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (M5C_DEFAULTS[defaultKey] || M5C_DEFAULTS[sid] || existing);
  return {
    ...(el?.content || {}),
    ...style,
    text,
    runs: null,
    listType: null,
    letterSpacing: style.letterSpacing !== undefined ? style.letterSpacing : '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  };
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
}

function layoutMetricFiveCards(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / M5C_GEOM.viewW;
  const sy = canvasH / M5C_GEOM.viewH;
  const overlay = metricFiveCardsOverlay(0, 0, canvasW, canvasH);
  const chromeRe = /^M5C_/i;

  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  );

  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricFiveCardsTextSlot(el.slotId));
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]));

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId.toUpperCase());
    return {
      id: prev?.id || newId('txt-m5c'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    };
  };

  const next = [
    placeText('BADGE', overlay.badge, {
      align: 'center', verticalAlign: 'center', fontSize: 9, fontWeight: 700, color: '#2563EB', clipToSlot: false, lineHeight: 1, letterSpacing: '1px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'center', verticalAlign: 'top', fontSize: 40, fontWeight: 800, color: headingInk(palette), clipToSlot: false, lineHeight: 1.1,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'center', verticalAlign: 'top', fontSize: 13.5, fontWeight: 400, color: '#94A3B8', clipToSlot: false, lineHeight: 1.4,
    }, 'subheading'),
  ];

  for (let i = 1; i <= 5; i++) {
    const vSlot = bySlot.has(`CARD${i}_VALUE`) ? `CARD${i}_VALUE` : (bySlot.has(`STAT_${i}_VALUE`) ? `STAT_${i}_VALUE` : `CARD${i}_VALUE`);
    const lSlot = bySlot.has(`CARD${i}_LABEL`) ? `CARD${i}_LABEL` : (bySlot.has(`STAT_${i}_LABEL`) ? `STAT_${i}_LABEL` : `CARD${i}_LABEL`);
    const tSlot = bySlot.has(`CARD${i}_TREND`) ? `CARD${i}_TREND` : (bySlot.has(`STAT_${i}_TREND`) ? `STAT_${i}_TREND` : `CARD${i}_TREND`);
    const dSlot = bySlot.has(`CARD${i}_DESC`) ? `CARD${i}_DESC` : (bySlot.has(`STAT_${i}_DESC`) ? `STAT_${i}_DESC` : `CARD${i}_DESC`);

    next.push(
      placeText(vSlot, overlay[`card${i}Value`], {
        align: 'left', verticalAlign: 'center', fontSize: 38, fontWeight: 900, color: headingInk(palette), clipToSlot: false, lineHeight: 1,
      }, 'heading'),
      placeText(lSlot, overlay[`card${i}Label`], {
        align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 700, color: '#1E293B', clipToSlot: false, lineHeight: 1.3,
      }, 'caption'),
      placeText(tSlot, overlay[`card${i}Trend`], {
        align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 600, color: '#10B981', clipToSlot: false, lineHeight: 1.25, wrap: 'wrap',
      }, 'caption'),
      placeText(dSlot, overlay[`card${i}Desc`], {
        align: 'left', verticalAlign: 'top', fontSize: 11.5, fontWeight: 400, color: '#64748B', clipToSlot: false, lineHeight: 1.35, wrap: 'wrap',
      }, 'body')
    );
  }

  const chrome = metricFiveCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToMetricFiveCardsContent(spec);
    if (!graphic) return null;
    return {
      id: prev?.id || newId('shp-m5c'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement: {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.max(4, Math.round(spec.w * sx)),
        height: Math.max(4, Math.round(spec.h * sy)),
        rotation: 0,
        opacity: 1,
      },
      content: { svg: graphic.svg, colorMode: graphic.colorMode, fill: graphic.fill, alt: spec.slotId },
      role: 'decoration',
      slotId: spec.slotId,
    };
  }).filter(Boolean);

  return [...chrome, ...next];
}

function metricFiveCardsPreviewSvg(previewHints = {}, theme = {}) {
  const slots = previewHints?.slots || {};
  const stats = previewHints?.stats || [];

  const badgeText = slots.BADGE?.text || previewHints?.badge || M5C_DEFAULTS.BADGE;
  const headingText = slots.HEADING?.text || previewHints?.heading || M5C_DEFAULTS.HEADING;
  const subheadingText = slots.SUBHEADING?.text || previewHints?.subheading || M5C_DEFAULTS.SUBHEADING;

  const v1 = slots.CARD1_VALUE?.text || slots.STAT_1_VALUE?.text || (stats[0]?.value) || M5C_DEFAULTS.CARD1_VALUE;
  const l1 = slots.CARD1_LABEL?.text || slots.STAT_1_LABEL?.text || (stats[0]?.label) || M5C_DEFAULTS.CARD1_LABEL;
  const t1 = slots.CARD1_TREND?.text || M5C_DEFAULTS.CARD1_TREND;
  const d1 = slots.CARD1_DESC?.text || M5C_DEFAULTS.CARD1_DESC;

  const v2 = slots.CARD2_VALUE?.text || slots.STAT_2_VALUE?.text || (stats[1]?.value) || M5C_DEFAULTS.CARD2_VALUE;
  const l2 = slots.CARD2_LABEL?.text || slots.STAT_2_LABEL?.text || (stats[1]?.label) || M5C_DEFAULTS.CARD2_LABEL;
  const t2 = slots.CARD2_TREND?.text || M5C_DEFAULTS.CARD2_TREND;
  const d2 = slots.CARD2_DESC?.text || M5C_DEFAULTS.CARD2_DESC;

  const v3 = slots.CARD3_VALUE?.text || slots.STAT_3_VALUE?.text || (stats[2]?.value) || M5C_DEFAULTS.CARD3_VALUE;
  const l3 = slots.CARD3_LABEL?.text || slots.STAT_3_LABEL?.text || (stats[2]?.label) || M5C_DEFAULTS.CARD3_LABEL;
  const t3 = slots.CARD3_TREND?.text || M5C_DEFAULTS.CARD3_TREND;
  const d3 = slots.CARD3_DESC?.text || M5C_DEFAULTS.CARD3_DESC;

  const v4 = slots.CARD4_VALUE?.text || slots.STAT_4_VALUE?.text || (stats[3]?.value) || M5C_DEFAULTS.CARD4_VALUE;
  const l4 = slots.CARD4_LABEL?.text || slots.STAT_4_LABEL?.text || (stats[3]?.label) || M5C_DEFAULTS.CARD4_LABEL;
  const t4 = slots.CARD4_TREND?.text || M5C_DEFAULTS.CARD4_TREND;
  const d4 = slots.CARD4_DESC?.text || M5C_DEFAULTS.CARD4_DESC;

  const v5 = slots.CARD5_VALUE?.text || slots.STAT_5_VALUE?.text || (stats[4]?.value) || M5C_DEFAULTS.CARD5_VALUE;
  const l5 = slots.CARD5_LABEL?.text || slots.STAT_5_LABEL?.text || (stats[4]?.label) || M5C_DEFAULTS.CARD5_LABEL;
  const t5 = slots.CARD5_TREND?.text || M5C_DEFAULTS.CARD5_TREND;
  const d5 = slots.CARD5_DESC?.text || M5C_DEFAULTS.CARD5_DESC;

  const c1 = M5C_COLORS.card1;
  const c2 = M5C_COLORS.card2;
  const c3 = M5C_COLORS.card3;
  const c4 = M5C_COLORS.card4;
  const c5 = M5C_COLORS.card5;

  const splitDesc = (desc, fallback1, fallback2) => {
    if (!desc) return [fallback1, fallback2];
    const words = String(desc).split(' ');
    if (words.length <= 3) return [desc, ''];
    const mid = Math.ceil(words.length / 2);
    return [words.slice(0, mid).join(' '), words.slice(mid).join(' ')];
  };

  const splitTrend = (trend, fallback) => {
    const text = trend || fallback || '';
    const words = String(text).split(' ');
    if (words.length <= 2) return [text, ''];
    return [words.slice(0, -1).join(' '), words.slice(-1).join(' ')];
  };

  const [t1a, t1b] = splitTrend(t1, '+12% vs. last quarter');
  const [t2a, t2b] = splitTrend(t2, '+18% vs. last quarter');
  const [t3a, t3b] = splitTrend(t3, '+22% vs. last quarter');
  const [t4a, t4b] = splitTrend(t4, '+35% vs. last quarter');
  const [t5a, t5b] = splitTrend(t5, '+40% vs. last quarter');

  const [d1a, d1b] = splitDesc(d1, 'High happiness and', 'cohort retention.');
  const [d2a, d2b] = splitDesc(d2, 'Accelerated payback', 'and efficiency gains.');
  const [d3a, d3b] = splitDesc(d3, 'Rapid adoption across', 'global teams.');
  const [d4a, d4b] = splitDesc(d4, 'Priority resolution', 'and live support.');
  const [d5a, d5b] = splitDesc(d5, 'Worldwide coverage', 'with local presence.');

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <defs>
      <linearGradient id="m5cg1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c1}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c1}" stop-opacity="0.15"/>
      </linearGradient>
      <linearGradient id="m5cg2" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c2}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c2}" stop-opacity="0.15"/>
      </linearGradient>
      <linearGradient id="m5cg3" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c3}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c3}" stop-opacity="0.15"/>
      </linearGradient>
      <linearGradient id="m5cg4" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c4}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c4}" stop-opacity="0.15"/>
      </linearGradient>
      <linearGradient id="m5cg5" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c5}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c5}" stop-opacity="0.15"/>
      </linearGradient>
    </defs>

    <rect width="1000" height="560" fill="#FFFFFF" rx="12"/>

    <!-- Badge (Centered) -->
    <rect x="${M5C_GEOM.badgeX}" y="${M5C_GEOM.badgeY}" width="${M5C_GEOM.badgeW}" height="${M5C_GEOM.badgeH}" rx="6" fill="#DBEAFE"/>
    <g transform="translate(${M5C_GEOM.badgeX + 12}, ${M5C_GEOM.badgeY + 4})">
      <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>
      <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>
      <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>
    </g>
    <text x="${M5C_GEOM.badgeX + 32}" y="${M5C_GEOM.badgeY + 15}" fill="#2563EB" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" letter-spacing="0.5px">${badgeText}</text>

    <!-- Heading (Centered) -->
    <text x="500" y="104" text-anchor="middle" fill="#0F172A" font-size="40" font-weight="800" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${headingText}</text>

    <!-- Subheading (Centered) -->
    <text x="500" y="134" text-anchor="middle" fill="#475569" font-size="14" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${subheadingText}</text>

    <!-- CARD 1 -->
    <rect x="${M5C_GEOM.card1X}" y="${M5C_GEOM.cardY}" width="${M5C_GEOM.cardW}" height="${M5C_GEOM.cardH}" rx="16" fill="url(#m5cg1)" stroke="${c1}" stroke-width="1.5" stroke-opacity="0.2"/>
    <rect x="${M5C_GEOM.card1X + 16}" y="${M5C_GEOM.cardY + 16}" width="44" height="44" rx="11" fill="${c1}" fill-opacity="0.15"/>
    <g transform="translate(${M5C_GEOM.card1X + 24}, ${M5C_GEOM.cardY + 24})">
      <circle cx="14" cy="10" r="6" fill="none" stroke="${c1}" stroke-width="2.2"/>
      <path d="M8 21 Q14 17 20 21 L20 26 L8 26 Z" fill="none" stroke="${c1}" stroke-width="2.2" stroke-linejoin="round"/>
    </g>
    <text x="${M5C_GEOM.card1X + 16}" y="${M5C_GEOM.cardY + 114}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v1}</text>
    <text x="${M5C_GEOM.card1X + 16}" y="${M5C_GEOM.cardY + 142}" fill="#1E293B" font-size="14" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l1}</text>
    <path d="M${M5C_GEOM.card1X + 17} ${M5C_GEOM.cardY + 168} L${M5C_GEOM.card1X + 21} ${M5C_GEOM.cardY + 162} L${M5C_GEOM.card1X + 25} ${M5C_GEOM.cardY + 168}" fill="none" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="${M5C_GEOM.card1X + 30}" y="${M5C_GEOM.cardY + 168}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t1a}</text>
    ${t1b ? `<text x="${M5C_GEOM.card1X + 30}" y="${M5C_GEOM.cardY + 182}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t1b}</text>` : ''}
    <text x="${M5C_GEOM.card1X + 16}" y="${M5C_GEOM.cardY + 208}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d1a}</text>
    <text x="${M5C_GEOM.card1X + 16}" y="${M5C_GEOM.cardY + 224}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d1b}</text>

    <!-- CARD 2 -->
    <rect x="${M5C_GEOM.card2X}" y="${M5C_GEOM.cardY}" width="${M5C_GEOM.cardW}" height="${M5C_GEOM.cardH}" rx="16" fill="url(#m5cg2)" stroke="${c2}" stroke-width="1.5" stroke-opacity="0.2"/>
    <rect x="${M5C_GEOM.card2X + 16}" y="${M5C_GEOM.cardY + 16}" width="44" height="44" rx="11" fill="${c2}" fill-opacity="0.15"/>
    <g transform="translate(${M5C_GEOM.card2X + 24}, ${M5C_GEOM.cardY + 24})">
      <rect x="3" y="3" width="22" height="22" rx="3" fill="none" stroke="${c2}" stroke-width="2"/>
      <rect x="6" y="11" width="3.5" height="9" fill="${c2}" rx="0.6"/>
      <rect x="12" y="8" width="3.5" height="12" fill="${c2}" rx="0.6"/>
      <rect x="18" y="14" width="3.5" height="6" fill="${c2}" rx="0.6"/>
    </g>
    <text x="${M5C_GEOM.card2X + 16}" y="${M5C_GEOM.cardY + 114}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v2}</text>
    <text x="${M5C_GEOM.card2X + 16}" y="${M5C_GEOM.cardY + 142}" fill="#1E293B" font-size="14" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l2}</text>
    <path d="M${M5C_GEOM.card2X + 17} ${M5C_GEOM.cardY + 168} L${M5C_GEOM.card2X + 21} ${M5C_GEOM.cardY + 162} L${M5C_GEOM.card2X + 25} ${M5C_GEOM.cardY + 168}" fill="none" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="${M5C_GEOM.card2X + 30}" y="${M5C_GEOM.cardY + 168}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t2a}</text>
    ${t2b ? `<text x="${M5C_GEOM.card2X + 30}" y="${M5C_GEOM.cardY + 182}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t2b}</text>` : ''}
    <text x="${M5C_GEOM.card2X + 16}" y="${M5C_GEOM.cardY + 208}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d2a}</text>
    <text x="${M5C_GEOM.card2X + 16}" y="${M5C_GEOM.cardY + 224}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d2b}</text>

    <!-- CARD 3 -->
    <rect x="${M5C_GEOM.card3X}" y="${M5C_GEOM.cardY}" width="${M5C_GEOM.cardW}" height="${M5C_GEOM.cardH}" rx="16" fill="url(#m5cg3)" stroke="${c3}" stroke-width="1.5" stroke-opacity="0.2"/>
    <rect x="${M5C_GEOM.card3X + 16}" y="${M5C_GEOM.cardY + 16}" width="44" height="44" rx="11" fill="${c3}" fill-opacity="0.15"/>
    <g transform="translate(${M5C_GEOM.card3X + 24}, ${M5C_GEOM.cardY + 24})">
      <circle cx="9" cy="9" r="4" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="19" cy="9" r="4" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="14" cy="19" r="4" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <path d="M11 11 L12.5 16" stroke="${c3}" stroke-width="1.8"/>
      <path d="M17 11 L15.5 16" stroke="${c3}" stroke-width="1.8"/>
    </g>
    <text x="${M5C_GEOM.card3X + 16}" y="${M5C_GEOM.cardY + 114}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v3}</text>
    <text x="${M5C_GEOM.card3X + 16}" y="${M5C_GEOM.cardY + 142}" fill="#1E293B" font-size="14" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l3}</text>
    <path d="M${M5C_GEOM.card3X + 17} ${M5C_GEOM.cardY + 168} L${M5C_GEOM.card3X + 21} ${M5C_GEOM.cardY + 162} L${M5C_GEOM.card3X + 25} ${M5C_GEOM.cardY + 168}" fill="none" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="${M5C_GEOM.card3X + 30}" y="${M5C_GEOM.cardY + 168}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t3a}</text>
    ${t3b ? `<text x="${M5C_GEOM.card3X + 30}" y="${M5C_GEOM.cardY + 182}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t3b}</text>` : ''}
    <text x="${M5C_GEOM.card3X + 16}" y="${M5C_GEOM.cardY + 208}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d3a}</text>
    <text x="${M5C_GEOM.card3X + 16}" y="${M5C_GEOM.cardY + 224}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d3b}</text>

    <!-- CARD 4 -->
    <rect x="${M5C_GEOM.card4X}" y="${M5C_GEOM.cardY}" width="${M5C_GEOM.cardW}" height="${M5C_GEOM.cardH}" rx="16" fill="url(#m5cg4)" stroke="${c4}" stroke-width="1.5" stroke-opacity="0.2"/>
    <rect x="${M5C_GEOM.card4X + 16}" y="${M5C_GEOM.cardY + 16}" width="44" height="44" rx="11" fill="${c4}" fill-opacity="0.15"/>
    <g transform="translate(${M5C_GEOM.card4X + 24}, ${M5C_GEOM.cardY + 24})">
      <circle cx="14" cy="14" r="10" fill="none" stroke="${c4}" stroke-width="2.2"/>
      <polyline points="14,9 14,14 18,14" fill="none" stroke="${c4}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <text x="${M5C_GEOM.card4X + 16}" y="${M5C_GEOM.cardY + 114}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v4}</text>
    <text x="${M5C_GEOM.card4X + 16}" y="${M5C_GEOM.cardY + 142}" fill="#1E293B" font-size="14" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l4}</text>
    <path d="M${M5C_GEOM.card4X + 17} ${M5C_GEOM.cardY + 168} L${M5C_GEOM.card4X + 21} ${M5C_GEOM.cardY + 162} L${M5C_GEOM.card4X + 25} ${M5C_GEOM.cardY + 168}" fill="none" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="${M5C_GEOM.card4X + 30}" y="${M5C_GEOM.cardY + 168}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t4a}</text>
    ${t4b ? `<text x="${M5C_GEOM.card4X + 30}" y="${M5C_GEOM.cardY + 182}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t4b}</text>` : ''}
    <text x="${M5C_GEOM.card4X + 16}" y="${M5C_GEOM.cardY + 208}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d4a}</text>
    <text x="${M5C_GEOM.card4X + 16}" y="${M5C_GEOM.cardY + 224}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d4b}</text>

    <!-- CARD 5 -->
    <rect x="${M5C_GEOM.card5X}" y="${M5C_GEOM.cardY}" width="${M5C_GEOM.cardW}" height="${M5C_GEOM.cardH}" rx="16" fill="url(#m5cg5)" stroke="${c5}" stroke-width="1.5" stroke-opacity="0.2"/>
    <rect x="${M5C_GEOM.card5X + 16}" y="${M5C_GEOM.cardY + 16}" width="44" height="44" rx="11" fill="${c5}" fill-opacity="0.15"/>
    <g transform="translate(${M5C_GEOM.card5X + 24}, ${M5C_GEOM.cardY + 24})">
      <circle cx="14" cy="14" r="10" fill="none" stroke="${c5}" stroke-width="2"/>
      <line x1="4" y1="14" x2="24" y2="14" stroke="${c5}" stroke-width="1.8"/>
      <ellipse cx="14" cy="14" rx="4.5" ry="10" fill="none" stroke="${c5}" stroke-width="1.8"/>
    </g>
    <text x="${M5C_GEOM.card5X + 16}" y="${M5C_GEOM.cardY + 114}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v5}</text>
    <text x="${M5C_GEOM.card5X + 16}" y="${M5C_GEOM.cardY + 142}" fill="#1E293B" font-size="14" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l5}</text>
    <path d="M${M5C_GEOM.card5X + 17} ${M5C_GEOM.cardY + 168} L${M5C_GEOM.card5X + 21} ${M5C_GEOM.cardY + 162} L${M5C_GEOM.card5X + 25} ${M5C_GEOM.cardY + 168}" fill="none" stroke="#10B981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <text x="${M5C_GEOM.card5X + 30}" y="${M5C_GEOM.cardY + 168}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t5a}</text>
    ${t5b ? `<text x="${M5C_GEOM.card5X + 30}" y="${M5C_GEOM.cardY + 182}" fill="#10B981" font-size="11" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t5b}</text>` : ''}
    <text x="${M5C_GEOM.card5X + 16}" y="${M5C_GEOM.cardY + 208}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d5a}</text>
    <text x="${M5C_GEOM.card5X + 16}" y="${M5C_GEOM.cardY + 224}" fill="#64748B" font-size="11.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d5b}</text>
  </svg>`;
}

module.exports = {
  isMetricFiveCardsLayout,
  isMetricFiveCardsTextSlot,
  layoutMetricFiveCards,
  metricFiveCardsPreviewSvg,
  M5C_GEOM,
  M5C_DEFAULTS,
  M5C_COLORS,
};
