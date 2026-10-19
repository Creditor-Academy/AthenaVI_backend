/**
 * Metric five — Five side-by-side metrics with icons and gradient underlines.
 * CommonJS backend port for Athena VI Presentation diagram pipeline.
 * Layout id: metric_five_v1.
 */

const MFIVE_GEOM = {
  viewW: 1000,
  viewH: 560,

  decoX: 40,
  decoY: 55,
  decoW: 50,
  decoH: 6,

  headingX: 40,
  headingY: 75,
  headingW: 700,
  headingH: 55,

  metric1X: 40,
  metric2X: 228,
  metric3X: 416,
  metric4X: 604,
  metric5X: 792,
  metricY: 175,
  metricW: 168,
  metricH: 260,

  iconX: 58,
  iconY: 0,
  iconSize: 34,
  iconBgSize: 52,

  valueX: 0,
  valueY: 75,
  valueW: 168,
  valueH: 65,

  labelX: 0,
  labelY: 148,
  labelW: 168,
  labelH: 28,

  underlineX: 49,
  underlineY: 190,
  underlineW: 70,
  underlineH: 5,

  divider1X: 218,
  divider2X: 406,
  divider3X: 594,
  divider4X: 782,
  dividerY: 195,
  dividerW: 1,
  dividerH: 190,

  decoCirclesX: 0,
  decoCirclesY: 440,
  decoCirclesW: 200,
  decoCirclesH: 120,
};

const MFIVE_COLORS = {
  metric1: '#3B82F6',  // Blue
  metric2: '#8B5CF6',  // Purple
  metric3: '#10B981',  // Green
  metric4: '#F59E0B',  // Amber
  metric5: '#EC4899',  // Rose
  deco: '#3B82F6',
  divider: '#E2E8F0',
  decoCircles: '#DBEAFE',
};

const MFIVE_DEFAULTS = {
  HEADING: 'Key metrics',

  METRIC1_VALUE: '98%',
  METRIC1_LABEL: 'Satisfaction',
  STAT_1_VALUE: '98%',
  STAT_1_LABEL: 'Satisfaction',

  METRIC2_VALUE: '3.2x',
  METRIC2_LABEL: 'Average ROI',
  STAT_2_VALUE: '3.2x',
  STAT_2_LABEL: 'Average ROI',

  METRIC3_VALUE: '500+',
  METRIC3_LABEL: 'Active teams',
  STAT_3_VALUE: '500+',
  STAT_3_LABEL: 'Active teams',

  METRIC4_VALUE: '24h',
  METRIC4_LABEL: 'Response time',
  STAT_4_VALUE: '24h',
  STAT_4_LABEL: 'Response time',

  METRIC5_VALUE: '12',
  METRIC5_LABEL: 'Global markets',
  STAT_5_VALUE: '12',
  STAT_5_LABEL: 'Global markets',
};

function isMetricFiveLayout(layoutId) {
  return /metric_five_v1$/i.test(String(layoutId || ''));
}

function isMetricFiveTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase();
  return sid === 'HEADING'
    || sid === 'METRIC1_VALUE' || sid === 'STAT_1_VALUE'
    || sid === 'METRIC1_LABEL' || sid === 'STAT_1_LABEL'
    || sid === 'METRIC2_VALUE' || sid === 'STAT_2_VALUE'
    || sid === 'METRIC2_LABEL' || sid === 'STAT_2_LABEL'
    || sid === 'METRIC3_VALUE' || sid === 'STAT_3_VALUE'
    || sid === 'METRIC3_LABEL' || sid === 'STAT_3_LABEL'
    || sid === 'METRIC4_VALUE' || sid === 'STAT_4_VALUE'
    || sid === 'METRIC4_LABEL' || sid === 'STAT_4_LABEL'
    || sid === 'METRIC5_VALUE' || sid === 'STAT_5_VALUE'
    || sid === 'METRIC5_LABEL' || sid === 'STAT_5_LABEL';
}

function decoSvg() {
  const g = MFIVE_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.decoW} ${g.decoH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.decoW}" height="${g.decoH}" fill="${MFIVE_COLORS.deco}" rx="3"/>
  </svg>`;
}

function iconBgSvg(color) {
  const size = MFIVE_GEOM.iconBgSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size / 2}" cy="${size / 2}" r="${size / 2}" fill="${color}" fill-opacity="0.15"/>
  </svg>`;
}

function icon1Svg() {
  const size = MFIVE_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="11" cy="11" r="5" fill="none" stroke="currentColor" stroke-width="2.2"/>
    <circle cx="23" cy="11" r="5" fill="none" stroke="currentColor" stroke-width="2.2"/>
    <path d="M6 24 Q9 21 12 21 Q15 21 17 21 Q20 21 23 21 Q26 21 28 24 L28 29 L6 29 Z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>
  </svg>`;
}

function icon2Svg() {
  const size = MFIVE_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <path d="M6 24 L12 12 L18 18 L28 8" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="22,8 28,8 28,14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function icon3Svg() {
  const size = MFIVE_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="9" cy="9" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="21" cy="9" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="25" cy="21" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="15" cy="24" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <path d="M11.5 11.5 L13.5 20" stroke="currentColor" stroke-width="1.8"/>
    <path d="M18.5 11.5 L16.5 20" stroke="currentColor" stroke-width="1.8"/>
    <path d="M22 17 L19 21" stroke="currentColor" stroke-width="1.8"/>
  </svg>`;
}

function icon4Svg() {
  const size = MFIVE_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="17" cy="17" r="11" fill="none" stroke="currentColor" stroke-width="2.2"/>
    <polyline points="17,10 17,17 22,17" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function icon5Svg() {
  const size = MFIVE_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="17" cy="17" r="11" fill="none" stroke="currentColor" stroke-width="2.2"/>
    <line x1="6" y1="17" x2="28" y2="17" stroke="currentColor" stroke-width="2"/>
    <ellipse cx="17" cy="17" rx="5" ry="11" fill="none" stroke="currentColor" stroke-width="2"/>
  </svg>`;
}

function underlineSvg(color) {
  const g = MFIVE_GEOM;
  const clean = color.replace('#', '');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.underlineW} ${g.underlineH}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="m5UnderlineGrad_${clean}" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style="stop-color:${color};stop-opacity:0.25" />
        <stop offset="50%" style="stop-color:${color};stop-opacity:1" />
        <stop offset="100%" style="stop-color:${color};stop-opacity:0.25" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${g.underlineW}" height="${g.underlineH}" fill="url(#m5UnderlineGrad_${clean})" rx="2.5"/>
  </svg>`;
}

function dividerSvg() {
  const g = MFIVE_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.dividerW} ${g.dividerH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.dividerW}" height="${g.dividerH}" fill="${MFIVE_COLORS.divider}"/>
  </svg>`;
}

function decoCirclesSvg() {
  const w = 200;
  const h = 120;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <circle cx="30" cy="60" r="80" fill="${MFIVE_COLORS.decoCircles}" opacity="0.25"/>
    <circle cx="80" cy="90" r="60" fill="${MFIVE_COLORS.decoCircles}" opacity="0.4"/>
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

function metricFiveChromeSpecs() {
  const g = MFIVE_GEOM;
  const specs = [];

  specs.push({
    slotId: 'MFIVE_DECO',
    x: g.decoX,
    y: g.decoY,
    w: g.decoW,
    h: g.decoH,
    color: MFIVE_COLORS.deco,
    layer: 10,
    kind: 'deco',
  });

  const metrics = [
    { x: g.metric1X, color: MFIVE_COLORS.metric1, id: 1 },
    { x: g.metric2X, color: MFIVE_COLORS.metric2, id: 2 },
    { x: g.metric3X, color: MFIVE_COLORS.metric3, id: 3 },
    { x: g.metric4X, color: MFIVE_COLORS.metric4, id: 4 },
    { x: g.metric5X, color: MFIVE_COLORS.metric5, id: 5 },
  ];

  metrics.forEach((metric) => {
    specs.push({
      slotId: `MFIVE_METRIC${metric.id}_ICON_BG`,
      x: metric.x + g.iconX,
      y: g.metricY + g.iconY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: metric.color,
      layer: 5,
      kind: 'iconBg',
    });

    specs.push({
      slotId: `MFIVE_METRIC${metric.id}_ICON`,
      x: metric.x + g.iconX + (g.iconBgSize - g.iconSize) / 2,
      y: g.metricY + g.iconY + (g.iconBgSize - g.iconSize) / 2,
      w: g.iconSize,
      h: g.iconSize,
      color: metric.color,
      layer: 10,
      kind: `icon${metric.id}`,
    });

    specs.push({
      slotId: `MFIVE_METRIC${metric.id}_UNDERLINE`,
      x: metric.x + g.underlineX,
      y: g.metricY + g.underlineY,
      w: g.underlineW,
      h: g.underlineH,
      color: metric.color,
      layer: 10,
      kind: 'underline',
    });
  });

  const dividers = [g.divider1X, g.divider2X, g.divider3X, g.divider4X];
  dividers.forEach((dx, i) => {
    specs.push({
      slotId: `MFIVE_DIVIDER${i + 1}`,
      x: dx,
      y: g.dividerY,
      w: g.dividerW,
      h: g.dividerH,
      color: MFIVE_COLORS.divider,
      layer: 5,
      kind: 'divider',
    });
  });

  specs.push({
    slotId: 'MFIVE_DECO_CIRCLES',
    x: g.decoCirclesX,
    y: g.decoCirclesY,
    w: g.decoCirclesW,
    h: g.decoCirclesH,
    color: MFIVE_COLORS.decoCircles,
    layer: 3,
    kind: 'decoCircles',
  });

  return specs;
}

function metricFiveOverlay(gx, gy, gw, gh) {
  const g = MFIVE_GEOM;
  const sx = gw / g.viewW;
  const sy = gh / g.viewH;
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  });

  const overlays = {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
  };

  const metricXs = [g.metric1X, g.metric2X, g.metric3X, g.metric4X, g.metric5X];
  metricXs.forEach((mx, i) => {
    const num = i + 1;
    overlays[`metric${num}Value`] = box(mx + g.valueX, g.metricY + g.valueY, g.valueW, g.valueH);
    overlays[`metric${num}Label`] = box(mx + g.labelX, g.metricY + g.labelY, g.labelW, g.labelH);
  });

  return overlays;
}

function specToMetricFiveContent(spec) {
  if (spec.kind === 'deco') return { svg: decoSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'icon1') return { svg: icon1Svg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'icon2') return { svg: icon2Svg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'icon3') return { svg: icon3Svg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'icon4') return { svg: icon4Svg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'icon5') return { svg: icon5Svg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'underline') return { svg: underlineSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'divider') return { svg: dividerSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'decoCircles') return { svg: decoCirclesSvg(), colorMode: 'fixed', fill: spec.color };
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
  const defaultKey = sid.replace('STAT_1_', 'METRIC1_').replace('STAT_2_', 'METRIC2_').replace('STAT_3_', 'METRIC3_').replace('STAT_4_', 'METRIC4_').replace('STAT_5_', 'METRIC5_');
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (MFIVE_DEFAULTS[defaultKey] || MFIVE_DEFAULTS[sid] || existing);
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

function layoutMetricFive(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / MFIVE_GEOM.viewW;
  const sy = canvasH / MFIVE_GEOM.viewH;
  const overlay = metricFiveOverlay(0, 0, canvasW, canvasH);
  const chromeRe = /^MFIVE_/i;

  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  );

  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricFiveTextSlot(el.slotId));
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]));

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId.toUpperCase());
    return {
      id: prev?.id || newId('txt-m5'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    };
  };

  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 44, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
  ];

  for (let i = 1; i <= 5; i++) {
    const vSlot = bySlot.has(`METRIC${i}_VALUE`) ? `METRIC${i}_VALUE` : (bySlot.has(`STAT_${i}_VALUE`) ? `STAT_${i}_VALUE` : `METRIC${i}_VALUE`);
    const lSlot = bySlot.has(`METRIC${i}_LABEL`) ? `METRIC${i}_LABEL` : (bySlot.has(`STAT_${i}_LABEL`) ? `STAT_${i}_LABEL` : `METRIC${i}_LABEL`);

    next.push(
      placeText(vSlot, overlay[`metric${i}Value`], {
        align: 'center', verticalAlign: 'center', fontSize: 42, fontWeight: 900, color: headingInk(palette), clipToSlot: true, lineHeight: 1,
      }, 'heading'),
      placeText(lSlot, overlay[`metric${i}Label`], {
        align: 'center', verticalAlign: 'center', fontSize: 14.5, fontWeight: 700, color: '#64748B', clipToSlot: true, lineHeight: 1.3,
      }, 'caption')
    );
  }

  const chrome = metricFiveChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToMetricFiveContent(spec);
    if (!graphic) return null;
    return {
      id: prev?.id || newId('shp-m5'),
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

function metricFivePreviewSvg(previewHints = {}, theme = {}) {
  const slots = previewHints?.slots || {};
  const stats = previewHints?.stats || [];

  const headingText = slots.HEADING?.text || previewHints?.heading || MFIVE_DEFAULTS.HEADING;

  const v1 = slots.METRIC1_VALUE?.text || slots.STAT_1_VALUE?.text || (stats[0]?.value) || MFIVE_DEFAULTS.METRIC1_VALUE;
  const l1 = slots.METRIC1_LABEL?.text || slots.STAT_1_LABEL?.text || (stats[0]?.label) || MFIVE_DEFAULTS.METRIC1_LABEL;

  const v2 = slots.METRIC2_VALUE?.text || slots.STAT_2_VALUE?.text || (stats[1]?.value) || MFIVE_DEFAULTS.METRIC2_VALUE;
  const l2 = slots.METRIC2_LABEL?.text || slots.STAT_2_LABEL?.text || (stats[1]?.label) || MFIVE_DEFAULTS.METRIC2_LABEL;

  const v3 = slots.METRIC3_VALUE?.text || slots.STAT_3_VALUE?.text || (stats[2]?.value) || MFIVE_DEFAULTS.METRIC3_VALUE;
  const l3 = slots.METRIC3_LABEL?.text || slots.STAT_3_LABEL?.text || (stats[2]?.label) || MFIVE_DEFAULTS.METRIC3_LABEL;

  const v4 = slots.METRIC4_VALUE?.text || slots.STAT_4_VALUE?.text || (stats[3]?.value) || MFIVE_DEFAULTS.METRIC4_VALUE;
  const l4 = slots.METRIC4_LABEL?.text || slots.STAT_4_LABEL?.text || (stats[3]?.label) || MFIVE_DEFAULTS.METRIC4_LABEL;

  const v5 = slots.METRIC5_VALUE?.text || slots.STAT_5_VALUE?.text || (stats[4]?.value) || MFIVE_DEFAULTS.METRIC5_VALUE;
  const l5 = slots.METRIC5_LABEL?.text || slots.STAT_5_LABEL?.text || (stats[4]?.label) || MFIVE_DEFAULTS.METRIC5_LABEL;

  const c1 = MFIVE_COLORS.metric1;
  const c2 = MFIVE_COLORS.metric2;
  const c3 = MFIVE_COLORS.metric3;
  const c4 = MFIVE_COLORS.metric4;
  const c5 = MFIVE_COLORS.metric5;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <defs>
      <linearGradient id="m5ug1" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c1}" stop-opacity="0.25"/>
        <stop offset="50%" stop-color="${c1}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c1}" stop-opacity="0.25"/>
      </linearGradient>
      <linearGradient id="m5ug2" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c2}" stop-opacity="0.25"/>
        <stop offset="50%" stop-color="${c2}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c2}" stop-opacity="0.25"/>
      </linearGradient>
      <linearGradient id="m5ug3" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c3}" stop-opacity="0.25"/>
        <stop offset="50%" stop-color="${c3}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c3}" stop-opacity="0.25"/>
      </linearGradient>
      <linearGradient id="m5ug4" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c4}" stop-opacity="0.25"/>
        <stop offset="50%" stop-color="${c4}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c4}" stop-opacity="0.25"/>
      </linearGradient>
      <linearGradient id="m5ug5" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c5}" stop-opacity="0.25"/>
        <stop offset="50%" stop-color="${c5}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c5}" stop-opacity="0.25"/>
      </linearGradient>
    </defs>

    <rect width="1000" height="560" fill="#FFFFFF" rx="12"/>

    <circle cx="30" cy="500" r="80" fill="${MFIVE_COLORS.decoCircles}" opacity="0.25"/>
    <circle cx="80" cy="530" r="60" fill="${MFIVE_COLORS.decoCircles}" opacity="0.4"/>

    <rect x="${MFIVE_GEOM.decoX}" y="${MFIVE_GEOM.decoY}" width="${MFIVE_GEOM.decoW}" height="${MFIVE_GEOM.decoH}" rx="3" fill="${MFIVE_COLORS.deco}"/>

    <text x="${MFIVE_GEOM.headingX}" y="${MFIVE_GEOM.headingY + 38}" fill="#0F172A" font-size="44" font-weight="800" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${headingText}</text>

    <rect x="${MFIVE_GEOM.divider1X}" y="${MFIVE_GEOM.dividerY}" width="1" height="${MFIVE_GEOM.dividerH}" fill="${MFIVE_COLORS.divider}"/>
    <rect x="${MFIVE_GEOM.divider2X}" y="${MFIVE_GEOM.dividerY}" width="1" height="${MFIVE_GEOM.dividerH}" fill="${MFIVE_COLORS.divider}"/>
    <rect x="${MFIVE_GEOM.divider3X}" y="${MFIVE_GEOM.dividerY}" width="1" height="${MFIVE_GEOM.dividerH}" fill="${MFIVE_COLORS.divider}"/>
    <rect x="${MFIVE_GEOM.divider4X}" y="${MFIVE_GEOM.dividerY}" width="1" height="${MFIVE_GEOM.dividerH}" fill="${MFIVE_COLORS.divider}"/>

    <!-- METRIC 1 -->
    <circle cx="${MFIVE_GEOM.metric1X + 84}" cy="${MFIVE_GEOM.metricY + 26}" r="26" fill="${c1}" fill-opacity="0.15"/>
    <g transform="translate(${MFIVE_GEOM.metric1X + 67}, ${MFIVE_GEOM.metricY + 9})">
      <circle cx="11" cy="11" r="5" fill="none" stroke="${c1}" stroke-width="2.2"/>
      <circle cx="23" cy="11" r="5" fill="none" stroke="${c1}" stroke-width="2.2"/>
      <path d="M6 24 Q9 21 12 21 Q15 21 17 21 Q20 21 23 21 Q26 21 28 24 L28 29 L6 29 Z" fill="none" stroke="${c1}" stroke-width="2.2" stroke-linejoin="round"/>
    </g>
    <text x="${MFIVE_GEOM.metric1X + 84}" y="${MFIVE_GEOM.metricY + 120}" fill="#0F172A" font-size="42" font-weight="900" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v1}</text>
    <text x="${MFIVE_GEOM.metric1X + 84}" y="${MFIVE_GEOM.metricY + 168}" fill="#64748B" font-size="14.5" font-weight="700" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l1}</text>
    <rect x="${MFIVE_GEOM.metric1X + MFIVE_GEOM.underlineX}" y="${MFIVE_GEOM.metricY + MFIVE_GEOM.underlineY}" width="${MFIVE_GEOM.underlineW}" height="${MFIVE_GEOM.underlineH}" rx="2.5" fill="url(#m5ug1)"/>

    <!-- METRIC 2 -->
    <circle cx="${MFIVE_GEOM.metric2X + 84}" cy="${MFIVE_GEOM.metricY + 26}" r="26" fill="${c2}" fill-opacity="0.15"/>
    <g transform="translate(${MFIVE_GEOM.metric2X + 67}, ${MFIVE_GEOM.metricY + 9})">
      <path d="M6 24 L12 12 L18 18 L28 8" fill="none" stroke="${c2}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
      <polyline points="22,8 28,8 28,14" fill="none" stroke="${c2}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <text x="${MFIVE_GEOM.metric2X + 84}" y="${MFIVE_GEOM.metricY + 120}" fill="#0F172A" font-size="42" font-weight="900" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v2}</text>
    <text x="${MFIVE_GEOM.metric2X + 84}" y="${MFIVE_GEOM.metricY + 168}" fill="#64748B" font-size="14.5" font-weight="700" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l2}</text>
    <rect x="${MFIVE_GEOM.metric2X + MFIVE_GEOM.underlineX}" y="${MFIVE_GEOM.metricY + MFIVE_GEOM.underlineY}" width="${MFIVE_GEOM.underlineW}" height="${MFIVE_GEOM.underlineH}" rx="2.5" fill="url(#m5ug2)"/>

    <!-- METRIC 3 -->
    <circle cx="${MFIVE_GEOM.metric3X + 84}" cy="${MFIVE_GEOM.metricY + 26}" r="26" fill="${c3}" fill-opacity="0.15"/>
    <g transform="translate(${MFIVE_GEOM.metric3X + 67}, ${MFIVE_GEOM.metricY + 9})">
      <circle cx="9" cy="9" r="4" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="21" cy="9" r="4" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="25" cy="21" r="4" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="15" cy="24" r="4" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <path d="M11.5 11.5 L13.5 20" stroke="${c3}" stroke-width="1.8"/>
      <path d="M18.5 11.5 L16.5 20" stroke="${c3}" stroke-width="1.8"/>
      <path d="M22 17 L19 21" stroke="${c3}" stroke-width="1.8"/>
    </g>
    <text x="${MFIVE_GEOM.metric3X + 84}" y="${MFIVE_GEOM.metricY + 120}" fill="#0F172A" font-size="42" font-weight="900" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v3}</text>
    <text x="${MFIVE_GEOM.metric3X + 84}" y="${MFIVE_GEOM.metricY + 168}" fill="#64748B" font-size="14.5" font-weight="700" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l3}</text>
    <rect x="${MFIVE_GEOM.metric3X + MFIVE_GEOM.underlineX}" y="${MFIVE_GEOM.metricY + MFIVE_GEOM.underlineY}" width="${MFIVE_GEOM.underlineW}" height="${MFIVE_GEOM.underlineH}" rx="2.5" fill="url(#m5ug3)"/>

    <!-- METRIC 4 -->
    <circle cx="${MFIVE_GEOM.metric4X + 84}" cy="${MFIVE_GEOM.metricY + 26}" r="26" fill="${c4}" fill-opacity="0.15"/>
    <g transform="translate(${MFIVE_GEOM.metric4X + 67}, ${MFIVE_GEOM.metricY + 9})">
      <circle cx="17" cy="17" r="11" fill="none" stroke="${c4}" stroke-width="2.2"/>
      <polyline points="17,10 17,17 22,17" fill="none" stroke="${c4}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <text x="${MFIVE_GEOM.metric4X + 84}" y="${MFIVE_GEOM.metricY + 120}" fill="#0F172A" font-size="42" font-weight="900" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v4}</text>
    <text x="${MFIVE_GEOM.metric4X + 84}" y="${MFIVE_GEOM.metricY + 168}" fill="#64748B" font-size="14.5" font-weight="700" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l4}</text>
    <rect x="${MFIVE_GEOM.metric4X + MFIVE_GEOM.underlineX}" y="${MFIVE_GEOM.metricY + MFIVE_GEOM.underlineY}" width="${MFIVE_GEOM.underlineW}" height="${MFIVE_GEOM.underlineH}" rx="2.5" fill="url(#m5ug4)"/>

    <!-- METRIC 5 -->
    <circle cx="${MFIVE_GEOM.metric5X + 84}" cy="${MFIVE_GEOM.metricY + 26}" r="26" fill="${c5}" fill-opacity="0.15"/>
    <g transform="translate(${MFIVE_GEOM.metric5X + 67}, ${MFIVE_GEOM.metricY + 9})">
      <circle cx="17" cy="17" r="11" fill="none" stroke="${c5}" stroke-width="2.2"/>
      <line x1="6" y1="17" x2="28" y2="17" stroke="${c5}" stroke-width="2"/>
      <ellipse cx="17" cy="17" rx="5" ry="11" fill="none" stroke="${c5}" stroke-width="2"/>
    </g>
    <text x="${MFIVE_GEOM.metric5X + 84}" y="${MFIVE_GEOM.metricY + 120}" fill="#0F172A" font-size="42" font-weight="900" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v5}</text>
    <text x="${MFIVE_GEOM.metric5X + 84}" y="${MFIVE_GEOM.metricY + 168}" fill="#64748B" font-size="14.5" font-weight="700" text-anchor="middle" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l5}</text>
    <rect x="${MFIVE_GEOM.metric5X + MFIVE_GEOM.underlineX}" y="${MFIVE_GEOM.metricY + MFIVE_GEOM.underlineY}" width="${MFIVE_GEOM.underlineW}" height="${MFIVE_GEOM.underlineH}" rx="2.5" fill="url(#m5ug5)"/>
  </svg>`;
}

module.exports = {
  isMetricFiveLayout,
  isMetricFiveTextSlot,
  layoutMetricFive,
  metricFivePreviewSvg,
  MFIVE_GEOM,
  MFIVE_DEFAULTS,
  MFIVE_COLORS,
};
