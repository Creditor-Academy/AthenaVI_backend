/**
 * Metric six para — Supporting paragraph with 6 metrics in a clean 3x2 grid (cardless).
 * CommonJS backend port for Athena VI Presentation diagram pipeline.
 * Layout id: metric_six_para_v1, stat_six_para.
 */

const M6P_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Badge at top
  badgeX: 40,
  badgeY: 30,
  badgeW: 130,
  badgeH: 22,
  badgeIconSize: 14,

  // Heading
  headingX: 40,
  headingY: 58,
  headingW: 920,
  headingH: 40,

  // Supporting paragraph (BODY)
  bodyX: 40,
  bodyY: 104,
  bodyW: 920,
  bodyH: 52,

  // 6 Metrics in 3 cols x 2 rows (open cardless layout)
  col1X: 40,
  col2X: 360,
  col3X: 680,
  colW: 280,
  row1Y: 175,
  row2Y: 350,
  rowH: 145,

  // Inside each metric column
  iconX: 0,
  iconY: 0,
  iconSize: 20,
  iconBgSize: 38,

  pillX: 215,
  pillY: 8,
  pillW: 65,
  pillH: 22,

  valueX: 0,
  valueY: 54,
  valueW: 280,
  valueH: 44,

  labelX: 0,
  labelY: 102,
  labelW: 280,
  labelH: 24,

  underlineX: 0,
  underlineY: 132,
  underlineW: 60,
  underlineH: 4,

  // Hairline dividing rules between cells
  dividerV1X: 340,
  dividerV2X: 660,
  dividerVY: 180,
  dividerVW: 1,
  dividerVH: 315,

  dividerHX: 40,
  dividerHY: 335,
  dividerHW: 920,
  dividerHH: 1,
};

const M6P_COLORS = {
  card1: '#3B82F6',  // Blue
  card2: '#8B5CF6',  // Purple
  card3: '#10B981',  // Green
  card4: '#F59E0B',  // Amber
  card5: '#06B6D4',  // Cyan
  card6: '#EC4899',  // Rose
  divider: '#E2E8F0',
};

const M6P_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Key performance metrics',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',

  STAT_1_VALUE: '98%',
  STAT_1_LABEL: 'Satisfaction',
  CARD1_TREND: '+12%',

  STAT_2_VALUE: '3.2x',
  STAT_2_LABEL: 'Average ROI',
  CARD2_TREND: '+18%',

  STAT_3_VALUE: '500+',
  STAT_3_LABEL: 'Active teams',
  CARD3_TREND: '+22%',

  STAT_4_VALUE: '24h',
  STAT_4_LABEL: 'Response time',
  CARD4_TREND: '+35%',

  STAT_5_VALUE: '12',
  STAT_5_LABEL: 'Global markets',
  CARD5_TREND: '+40%',

  STAT_6_VALUE: '4.9',
  STAT_6_LABEL: 'Customer rating',
  CARD6_TREND: '★ 4.9',
};

const { isMetricSixCardsLayout } = require('./metricSixCards');

function isMetricSixParaLayout(layoutId, schema = null) {
  if (isMetricSixCardsLayout(layoutId, schema)) return false;
  const id = String(layoutId || schema?.layout_id || schema?.id || schema?.layoutId || '').toLowerCase();
  return /metric_six_para_v1$/i.test(id) || /stat_six_para$/i.test(id);
}

function isMetricSixParaTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase();
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'BODY' || sid === 'PARAGRAPH' || sid === 'SUBHEADING'
    || sid === 'STAT_1_VALUE' || sid === 'CARD1_VALUE' || sid === 'METRIC1_VALUE'
    || sid === 'STAT_1_LABEL' || sid === 'CARD1_LABEL' || sid === 'METRIC1_LABEL'
    || sid === 'CARD1_TREND' || sid === 'STAT_1_TREND'
    || sid === 'STAT_2_VALUE' || sid === 'CARD2_VALUE' || sid === 'METRIC2_VALUE'
    || sid === 'STAT_2_LABEL' || sid === 'CARD2_LABEL' || sid === 'METRIC2_LABEL'
    || sid === 'CARD2_TREND' || sid === 'STAT_2_TREND'
    || sid === 'STAT_3_VALUE' || sid === 'CARD3_VALUE' || sid === 'METRIC3_VALUE'
    || sid === 'STAT_3_LABEL' || sid === 'CARD3_LABEL' || sid === 'METRIC3_LABEL'
    || sid === 'CARD3_TREND' || sid === 'STAT_3_TREND'
    || sid === 'STAT_4_VALUE' || sid === 'CARD4_VALUE' || sid === 'METRIC4_VALUE'
    || sid === 'STAT_4_LABEL' || sid === 'CARD4_LABEL' || sid === 'METRIC4_LABEL'
    || sid === 'CARD4_TREND' || sid === 'STAT_4_TREND'
    || sid === 'STAT_5_VALUE' || sid === 'CARD5_VALUE' || sid === 'METRIC5_VALUE'
    || sid === 'STAT_5_LABEL' || sid === 'CARD5_LABEL' || sid === 'METRIC5_LABEL'
    || sid === 'CARD5_TREND' || sid === 'STAT_5_TREND'
    || sid === 'STAT_6_VALUE' || sid === 'CARD6_VALUE' || sid === 'METRIC6_VALUE'
    || sid === 'STAT_6_LABEL' || sid === 'CARD6_LABEL' || sid === 'METRIC6_LABEL'
    || sid === 'CARD6_TREND' || sid === 'STAT_6_TREND';
}

function badgeShapeSvg() {
  const g = M6P_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.badgeW} ${g.badgeH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.badgeW}" height="${g.badgeH}" fill="#DBEAFE" rx="6"/>
    <g transform="translate(10, 4)">
      <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>
      <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>
      <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>
    </g>
  </svg>`;
}

function gridDividersSvg() {
  const g = M6P_GEOM;
  const relV1 = g.dividerV1X - g.dividerHX;
  const relV2 = g.dividerV2X - g.dividerHX;
  const relH = g.dividerHY - g.dividerVY;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.dividerHW} ${g.dividerVH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="${relV1}" y="0" width="1" height="${g.dividerVH}" fill="${M6P_COLORS.divider}"/>
    <rect x="${relV2}" y="0" width="1" height="${g.dividerVH}" fill="${M6P_COLORS.divider}"/>
    <rect x="0" y="${relH}" width="${g.dividerHW}" height="1" fill="${M6P_COLORS.divider}"/>
  </svg>`;
}

function pillBgSvg(color) {
  const g = M6P_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.pillW} ${g.pillH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.pillW}" height="${g.pillH}" fill="${color}" fill-opacity="0.12" stroke="${color}" stroke-width="0.8" stroke-opacity="0.25" rx="6"/>
  </svg>`;
}

function underlineSvg(color) {
  const g = M6P_GEOM;
  const cleanColor = color.replace('#', '');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.underlineW} ${g.underlineH}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="m6pu_${cleanColor}" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style="stop-color:${color};stop-opacity:0.3" />
        <stop offset="50%" style="stop-color:${color};stop-opacity:1" />
        <stop offset="100%" style="stop-color:${color};stop-opacity:0.3" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${g.underlineW}" height="${g.underlineH}" fill="url(#m6pu_${cleanColor})" rx="2"/>
  </svg>`;
}

function metricIconWithBgSvg(id, color) {
  const size = M6P_GEOM.iconBgSize;
  let iconPath = '';
  if (id === 1) {
    iconPath = `<circle cx="10" cy="7" r="4.5" fill="none" stroke="${color}" stroke-width="2"/>
    <path d="M4 18 C4 13.5, 7.5 12.5, 10 12.5 C12.5 12.5, 16 13.5, 16 18" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round"/>`;
  } else if (id === 2) {
    iconPath = `<polyline points="3,15 8,10 12,13 18,6" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="13,6 18,6 18,11" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>`;
  } else if (id === 3) {
    iconPath = `<circle cx="6" cy="7" r="3" fill="none" stroke="${color}" stroke-width="1.8"/>
    <circle cx="14" cy="7" r="3" fill="none" stroke="${color}" stroke-width="1.8"/>
    <circle cx="10" cy="15" r="3" fill="none" stroke="${color}" stroke-width="1.8"/>
    <line x1="8" y1="9" x2="9" y2="12.5" stroke="${color}" stroke-width="1.4"/>
    <line x1="12" y1="9" x2="11" y2="12.5" stroke="${color}" stroke-width="1.4"/>`;
  } else if (id === 4) {
    iconPath = `<circle cx="10" cy="10" r="7.5" fill="none" stroke="${color}" stroke-width="2"/>
    <polyline points="10,6 10,10 13.5,10" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`;
  } else if (id === 5) {
    iconPath = `<circle cx="10" cy="10" r="7.5" fill="none" stroke="${color}" stroke-width="2"/>
    <line x1="2.5" y1="10" x2="17.5" y2="10" stroke="${color}" stroke-width="1.5"/>
    <ellipse cx="10" cy="10" rx="3.8" ry="7.5" fill="none" stroke="${color}" stroke-width="1.5"/>`;
  } else if (id === 6) {
    iconPath = `<polygon points="10,2.5 12.3,7.3 17.5,8.1 13.8,11.8 14.7,17 10,14.5 5.3,17 6.2,11.8 2.5,8.1 7.7,7.3" fill="none" stroke="${color}" stroke-width="1.6" stroke-linejoin="round"/>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size / 2}" cy="${size / 2}" r="${size / 2}" fill="${color}" fill-opacity="0.14"/>
    <g transform="translate(9, 9)">
      ${iconPath}
    </g>
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#0F172A';
}

function metricSixParaChromeSpecs() {
  const g = M6P_GEOM;
  const specs = [];

  // Badge background + icon combined into 1 graphic
  specs.push({
    slotId: 'M6P_BADGE_SHAPE',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: '#DBEAFE',
    layer: 3,
    kind: 'badgeShape',
  });

  // Hairline grid dividers combined into 1 graphic
  specs.push({
    slotId: 'M6P_GRID_DIVIDERS',
    x: g.dividerHX,
    y: g.dividerVY,
    w: g.dividerHW,
    h: g.dividerVH,
    color: M6P_COLORS.divider,
    layer: 3,
    kind: 'gridDividers',
  });

  const metrics = [
    { x: g.col1X, y: g.row1Y, color: M6P_COLORS.card1, id: 1 },
    { x: g.col2X, y: g.row1Y, color: M6P_COLORS.card2, id: 2 },
    { x: g.col3X, y: g.row1Y, color: M6P_COLORS.card3, id: 3 },
    { x: g.col1X, y: g.row2Y, color: M6P_COLORS.card4, id: 4 },
    { x: g.col2X, y: g.row2Y, color: M6P_COLORS.card5, id: 5 },
    { x: g.col3X, y: g.row2Y, color: M6P_COLORS.card6, id: 6 },
  ];

  metrics.forEach((m) => {
    // Icon with circular tint background combined into 1 graphic
    specs.push({
      slotId: `M6P_METRIC${m.id}_ICON`,
      x: m.x + g.iconX,
      y: m.y + g.iconY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: m.color,
      layer: 8,
      kind: `metric${m.id}Icon`,
    });

    // Trend pill background
    specs.push({
      slotId: `M6P_METRIC${m.id}_PILL_BG`,
      x: m.x + g.pillX,
      y: m.y + g.pillY,
      w: g.pillW,
      h: g.pillH,
      color: m.color,
      layer: 5,
      kind: 'pillBg',
    });

    // Gradient accent underline
    specs.push({
      slotId: `M6P_METRIC${m.id}_UNDERLINE`,
      x: m.x + g.underlineX,
      y: m.y + g.underlineY,
      w: g.underlineW,
      h: g.underlineH,
      color: m.color,
      layer: 4,
      kind: 'underline',
    });
  });

  return specs;
}

function metricSixParaOverlay(gx, gy, gw, gh) {
  const g = M6P_GEOM;
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
    body: box(g.bodyX, g.bodyY, g.bodyW, g.bodyH),
  };

  const metrics = [
    { x: g.col1X, y: g.row1Y, id: 1 },
    { x: g.col2X, y: g.row1Y, id: 2 },
    { x: g.col3X, y: g.row1Y, id: 3 },
    { x: g.col1X, y: g.row2Y, id: 4 },
    { x: g.col2X, y: g.row2Y, id: 5 },
    { x: g.col3X, y: g.row2Y, id: 6 },
  ];

  metrics.forEach((m) => {
    overlays[`card${m.id}Value`] = box(m.x + g.valueX, m.y + g.valueY, g.valueW, g.valueH);
    overlays[`card${m.id}Label`] = box(m.x + g.labelX, m.y + g.labelY, g.labelW, g.labelH);
    overlays[`card${m.id}Trend`] = box(m.x + g.pillX, m.y + g.pillY, g.pillW, g.pillH);
  });

  return overlays;
}

function specToMetricSixParaContent(spec) {
  if (spec.kind === 'badgeShape') return { svg: badgeShapeSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'gridDividers') return { svg: gridDividersSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'pillBg') return { svg: pillBgSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'underline') return { svg: underlineSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (/^metric\dIcon$/.test(spec.kind)) {
    const id = parseInt(spec.kind.replace('metric', '').replace('Icon', ''), 10);
    return { svg: metricIconWithBgSvg(id, spec.color), colorMode: 'fixed', fill: spec.color };
  }
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
  const defaultKey = sid
    .replace('STAT_1_', 'STAT_1_').replace('CARD1_', 'STAT_1_').replace('METRIC1_', 'STAT_1_')
    .replace('STAT_2_', 'STAT_2_').replace('CARD2_', 'STAT_2_').replace('METRIC2_', 'STAT_2_')
    .replace('STAT_3_', 'STAT_3_').replace('CARD3_', 'STAT_3_').replace('METRIC3_', 'STAT_3_')
    .replace('STAT_4_', 'STAT_4_').replace('CARD4_', 'STAT_4_').replace('METRIC4_', 'STAT_4_')
    .replace('STAT_5_', 'STAT_5_').replace('CARD5_', 'STAT_5_').replace('METRIC5_', 'STAT_5_')
    .replace('STAT_6_', 'STAT_6_').replace('CARD6_', 'STAT_6_').replace('METRIC6_', 'STAT_6_');
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (M6P_DEFAULTS[defaultKey] || M6P_DEFAULTS[sid] || existing || '');
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

function layoutMetricSixPara(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / M6P_GEOM.viewW;
  const sy = canvasH / M6P_GEOM.viewH;
  const overlay = metricSixParaOverlay(0, 0, canvasW, canvasH);
  const chromeRe = /^M6P_/i;

  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  );

  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricSixParaTextSlot(el.slotId));
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]));

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId.toUpperCase());
    return {
      id: prev?.id || newId('txt-m6p'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    };
  };

  const bodySlot = bySlot.has('BODY') ? 'BODY' : (bySlot.has('PARAGRAPH') ? 'PARAGRAPH' : (bySlot.has('SUBHEADING') ? 'SUBHEADING' : 'BODY'));

  const next = [
    placeText('BADGE', overlay.badge, {
      align: 'left', verticalAlign: 'center', fontSize: 9.5, fontWeight: 700, color: '#2563EB', clipToSlot: false, lineHeight: 1, letterSpacing: '1px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 32, fontWeight: 800, color: headingInk(palette), clipToSlot: false, lineHeight: 1.15,
    }, 'heading'),
    placeText(bodySlot, overlay.body, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: false, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
  ];

  const cardColors = [
    M6P_COLORS.card1,
    M6P_COLORS.card2,
    M6P_COLORS.card3,
    M6P_COLORS.card4,
    M6P_COLORS.card5,
    M6P_COLORS.card6,
  ];

  for (let i = 1; i <= 6; i++) {
    const vSlot = bySlot.has(`STAT_${i}_VALUE`) ? `STAT_${i}_VALUE` : (bySlot.has(`CARD${i}_VALUE`) ? `CARD${i}_VALUE` : (bySlot.has(`METRIC${i}_VALUE`) ? `METRIC${i}_VALUE` : `STAT_${i}_VALUE`));
    const lSlot = bySlot.has(`STAT_${i}_LABEL`) ? `STAT_${i}_LABEL` : (bySlot.has(`CARD${i}_LABEL`) ? `CARD${i}_LABEL` : (bySlot.has(`METRIC${i}_LABEL`) ? `METRIC${i}_LABEL` : `STAT_${i}_LABEL`));
    const tSlot = bySlot.has(`CARD${i}_TREND`) ? `CARD${i}_TREND` : (bySlot.has(`STAT_${i}_TREND`) ? `STAT_${i}_TREND` : `CARD${i}_TREND`);

    next.push(
      placeText(vSlot, overlay[`card${i}Value`], {
        align: 'left', verticalAlign: 'center', fontSize: 36, fontWeight: 900, color: headingInk(palette), clipToSlot: false, lineHeight: 1,
      }, 'heading'),
      placeText(lSlot, overlay[`card${i}Label`], {
        align: 'left', verticalAlign: 'center', fontSize: 13.5, fontWeight: 700, color: '#1E293B', clipToSlot: false, lineHeight: 1.3,
      }, 'caption'),
      placeText(tSlot, overlay[`card${i}Trend`], {
        align: 'center', verticalAlign: 'center', fontSize: 10, fontWeight: 700, color: cardColors[i - 1], clipToSlot: false, lineHeight: 1,
      }, 'caption')
    );
  }

  const chrome = metricSixParaChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToMetricSixParaContent(spec);
    if (!graphic) return null;
    return {
      id: prev?.id || newId('shp-m6p'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement: {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.max(1, Math.round(spec.w * sx)),
        height: Math.max(1, Math.round(spec.h * sy)),
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

/**
 * Polished SVG Preview for Metric Six Para thumbnail in slide picker.
 * Exact 1000x560 slide canvas matching rendered slide layout — WITHOUT CARDS.
 */
function metricSixParaPreviewSvg(previewHints = {}, theme = {}) {
  const slots = previewHints?.slots || {};
  const stats = previewHints?.stats || [];

  const badgeText = slots.BADGE?.text || previewHints?.badge || M6P_DEFAULTS.BADGE;
  const headingText = slots.HEADING?.text || previewHints?.heading || M6P_DEFAULTS.HEADING;
  const bodyText = slots.BODY?.text || slots.PARAGRAPH?.text || slots.SUBHEADING?.text || previewHints?.bodyText || previewHints?.subheading || M6P_DEFAULTS.BODY;

  const v1 = slots.STAT_1_VALUE?.text || slots.CARD1_VALUE?.text || (stats[0]?.value) || M6P_DEFAULTS.STAT_1_VALUE;
  const l1 = slots.STAT_1_LABEL?.text || slots.CARD1_LABEL?.text || (stats[0]?.label) || M6P_DEFAULTS.STAT_1_LABEL;
  const t1 = slots.CARD1_TREND?.text || M6P_DEFAULTS.CARD1_TREND;

  const v2 = slots.STAT_2_VALUE?.text || slots.CARD2_VALUE?.text || (stats[1]?.value) || M6P_DEFAULTS.STAT_2_VALUE;
  const l2 = slots.STAT_2_LABEL?.text || slots.CARD2_LABEL?.text || (stats[1]?.label) || M6P_DEFAULTS.STAT_2_LABEL;
  const t2 = slots.CARD2_TREND?.text || M6P_DEFAULTS.CARD2_TREND;

  const v3 = slots.STAT_3_VALUE?.text || slots.CARD3_VALUE?.text || (stats[2]?.value) || M6P_DEFAULTS.STAT_3_VALUE;
  const l3 = slots.STAT_3_LABEL?.text || slots.CARD3_LABEL?.text || (stats[2]?.label) || M6P_DEFAULTS.STAT_3_LABEL;
  const t3 = slots.CARD3_TREND?.text || M6P_DEFAULTS.CARD3_TREND;

  const v4 = slots.STAT_4_VALUE?.text || slots.CARD4_VALUE?.text || (stats[3]?.value) || M6P_DEFAULTS.STAT_4_VALUE;
  const l4 = slots.STAT_4_LABEL?.text || slots.CARD4_LABEL?.text || (stats[3]?.label) || M6P_DEFAULTS.STAT_4_LABEL;
  const t4 = slots.CARD4_TREND?.text || M6P_DEFAULTS.CARD4_TREND;

  const v5 = slots.STAT_5_VALUE?.text || slots.CARD5_VALUE?.text || (stats[4]?.value) || M6P_DEFAULTS.STAT_5_VALUE;
  const l5 = slots.STAT_5_LABEL?.text || slots.CARD5_LABEL?.text || (stats[4]?.label) || M6P_DEFAULTS.STAT_5_LABEL;
  const t5 = slots.CARD5_TREND?.text || M6P_DEFAULTS.CARD5_TREND;

  const v6 = slots.STAT_6_VALUE?.text || slots.CARD6_VALUE?.text || (stats[5]?.value) || M6P_DEFAULTS.STAT_6_VALUE;
  const l6 = slots.STAT_6_LABEL?.text || slots.CARD6_LABEL?.text || (stats[5]?.label) || M6P_DEFAULTS.STAT_6_LABEL;
  const t6 = slots.CARD6_TREND?.text || M6P_DEFAULTS.CARD6_TREND;

  const c1 = M6P_COLORS.card1;
  const c2 = M6P_COLORS.card2;
  const c3 = M6P_COLORS.card3;
  const c4 = M6P_COLORS.card4;
  const c5 = M6P_COLORS.card5;
  const c6 = M6P_COLORS.card6;

  const g = M6P_GEOM;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <defs>
      <linearGradient id="m6pu1" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c1}" stop-opacity="0.3"/>
        <stop offset="50%" stop-color="${c1}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c1}" stop-opacity="0.3"/>
      </linearGradient>
      <linearGradient id="m6pu2" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c2}" stop-opacity="0.3"/>
        <stop offset="50%" stop-color="${c2}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c2}" stop-opacity="0.3"/>
      </linearGradient>
      <linearGradient id="m6pu3" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c3}" stop-opacity="0.3"/>
        <stop offset="50%" stop-color="${c3}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c3}" stop-opacity="0.3"/>
      </linearGradient>
      <linearGradient id="m6pu4" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c4}" stop-opacity="0.3"/>
        <stop offset="50%" stop-color="${c4}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c4}" stop-opacity="0.3"/>
      </linearGradient>
      <linearGradient id="m6pu5" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c5}" stop-opacity="0.3"/>
        <stop offset="50%" stop-color="${c5}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c5}" stop-opacity="0.3"/>
      </linearGradient>
      <linearGradient id="m6pu6" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c6}" stop-opacity="0.3"/>
        <stop offset="50%" stop-color="${c6}" stop-opacity="1"/>
        <stop offset="100%" stop-color="${c6}" stop-opacity="0.3"/>
      </linearGradient>
    </defs>

    <!-- Slide Canvas Background -->
    <rect width="1000" height="560" fill="#FFFFFF" rx="12"/>

    <!-- Badge -->
    <rect x="${g.badgeX}" y="${g.badgeY}" width="${g.badgeW}" height="${g.badgeH}" rx="6" fill="#DBEAFE"/>
    <g transform="translate(${g.badgeX + 12}, ${g.badgeY + 4})">
      <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>
      <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>
      <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>
    </g>
    <text x="${g.badgeX + 32}" y="${g.badgeY + 15}" fill="#2563EB" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" letter-spacing="0.5px">${badgeText}</text>

    <!-- Heading -->
    <text x="${g.headingX}" y="90" fill="#0F172A" font-size="30" font-weight="800" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${headingText}</text>

    <!-- Supporting Paragraph -->
    <text x="${g.bodyX}" y="122" fill="#64748B" font-size="13.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${bodyText.length > 95 ? bodyText.slice(0, 92) + '...' : bodyText}</text>
    <text x="${g.bodyX}" y="142" fill="#64748B" font-size="13.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">Scannable and balanced across enterprise execution workflows.</text>

    <!-- Hairline Grid Dividers (Open cardless layout) -->
    <rect x="${g.dividerV1X}" y="${g.dividerVY}" width="1" height="${g.dividerVH}" fill="${M6P_COLORS.divider}"/>
    <rect x="${g.dividerV2X}" y="${g.dividerVY}" width="1" height="${g.dividerVH}" fill="${M6P_COLORS.divider}"/>
    <rect x="${g.dividerHX}" y="${g.dividerHY}" width="${g.dividerHW}" height="1" fill="${M6P_COLORS.divider}"/>

    <!-- METRIC 1 (Blue) -->
    <circle cx="${g.col1X + 19}" cy="${g.row1Y + 19}" r="19" fill="${c1}" fill-opacity="0.14"/>
    <g transform="translate(${g.col1X + 9}, ${g.row1Y + 9})">
      <circle cx="10" cy="7" r="4.5" fill="none" stroke="${c1}" stroke-width="2"/>
      <path d="M4 18 C4 13.5, 7.5 12.5, 10 12.5 C12.5 12.5, 16 13.5, 16 18" fill="none" stroke="${c1}" stroke-width="2" stroke-linecap="round"/>
    </g>
    <rect x="${g.col1X + g.pillX}" y="${g.row1Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="6" fill="${c1}" fill-opacity="0.12" stroke="${c1}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col1X + g.pillX + g.pillW / 2}" y="${g.row1Y + g.pillY + 15}" text-anchor="middle" fill="${c1}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t1}</text>
    <text x="${g.col1X}" y="${g.row1Y + 90}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v1}</text>
    <text x="${g.col1X}" y="${g.row1Y + 118}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l1}</text>
    <rect x="${g.col1X}" y="${g.row1Y + 132}" width="${g.underlineW}" height="${g.underlineH}" rx="2" fill="url(#m6pu1)"/>

    <!-- METRIC 2 (Purple) -->
    <circle cx="${g.col2X + 19}" cy="${g.row1Y + 19}" r="19" fill="${c2}" fill-opacity="0.14"/>
    <g transform="translate(${g.col2X + 9}, ${g.row1Y + 9})">
      <polyline points="3,15 8,10 12,13 18,6" fill="none" stroke="${c2}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
      <polyline points="13,6 18,6 18,11" fill="none" stroke="${c2}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <rect x="${g.col2X + g.pillX}" y="${g.row1Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="6" fill="${c2}" fill-opacity="0.12" stroke="${c2}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col2X + g.pillX + g.pillW / 2}" y="${g.row1Y + g.pillY + 15}" text-anchor="middle" fill="${c2}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t2}</text>
    <text x="${g.col2X}" y="${g.row1Y + 90}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v2}</text>
    <text x="${g.col2X}" y="${g.row1Y + 118}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l2}</text>
    <rect x="${g.col2X}" y="${g.row1Y + 132}" width="${g.underlineW}" height="${g.underlineH}" rx="2" fill="url(#m6pu2)"/>

    <!-- METRIC 3 (Green) -->
    <circle cx="${g.col3X + 19}" cy="${g.row1Y + 19}" r="19" fill="${c3}" fill-opacity="0.14"/>
    <g transform="translate(${g.col3X + 9}, ${g.row1Y + 9})">
      <circle cx="6" cy="7" r="3" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="14" cy="7" r="3" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="10" cy="15" r="3" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <line x1="8" y1="9" x2="9" y2="12.5" stroke="${c3}" stroke-width="1.4"/>
      <line x1="12" y1="9" x2="11" y2="12.5" stroke="${c3}" stroke-width="1.4"/>
    </g>
    <rect x="${g.col3X + g.pillX}" y="${g.row1Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="6" fill="${c3}" fill-opacity="0.12" stroke="${c3}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col3X + g.pillX + g.pillW / 2}" y="${g.row1Y + g.pillY + 15}" text-anchor="middle" fill="${c3}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t3}</text>
    <text x="${g.col3X}" y="${g.row1Y + 90}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v3}</text>
    <text x="${g.col3X}" y="${g.row1Y + 118}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l3}</text>
    <rect x="${g.col3X}" y="${g.row1Y + 132}" width="${g.underlineW}" height="${g.underlineH}" rx="2" fill="url(#m6pu3)"/>

    <!-- METRIC 4 (Amber) -->
    <circle cx="${g.col1X + 19}" cy="${g.row2Y + 19}" r="19" fill="${c4}" fill-opacity="0.14"/>
    <g transform="translate(${g.col1X + 9}, ${g.row2Y + 9})">
      <circle cx="10" cy="10" r="7.5" fill="none" stroke="${c4}" stroke-width="2"/>
      <polyline points="10,6 10,10 13.5,10" fill="none" stroke="${c4}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <rect x="${g.col1X + g.pillX}" y="${g.row2Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="6" fill="${c4}" fill-opacity="0.12" stroke="${c4}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col1X + g.pillX + g.pillW / 2}" y="${g.row2Y + g.pillY + 15}" text-anchor="middle" fill="${c4}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t4}</text>
    <text x="${g.col1X}" y="${g.row2Y + 90}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v4}</text>
    <text x="${g.col1X}" y="${g.row2Y + 118}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l4}</text>
    <rect x="${g.col1X}" y="${g.row2Y + 132}" width="${g.underlineW}" height="${g.underlineH}" rx="2" fill="url(#m6pu4)"/>

    <!-- METRIC 5 (Cyan) -->
    <circle cx="${g.col2X + 19}" cy="${g.row2Y + 19}" r="19" fill="${c5}" fill-opacity="0.14"/>
    <g transform="translate(${g.col2X + 9}, ${g.row2Y + 9})">
      <circle cx="10" cy="10" r="7.5" fill="none" stroke="${c5}" stroke-width="2"/>
      <line x1="2.5" y1="10" x2="17.5" y2="10" stroke="${c5}" stroke-width="1.5"/>
      <ellipse cx="10" cy="10" rx="3.8" ry="7.5" fill="none" stroke="${c5}" stroke-width="1.5"/>
    </g>
    <rect x="${g.col2X + g.pillX}" y="${g.row2Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="6" fill="${c5}" fill-opacity="0.12" stroke="${c5}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col2X + g.pillX + g.pillW / 2}" y="${g.row2Y + g.pillY + 15}" text-anchor="middle" fill="${c5}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t5}</text>
    <text x="${g.col2X}" y="${g.row2Y + 90}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v5}</text>
    <text x="${g.col2X}" y="${g.row2Y + 118}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l5}</text>
    <rect x="${g.col2X}" y="${g.row2Y + 132}" width="${g.underlineW}" height="${g.underlineH}" rx="2" fill="url(#m6pu5)"/>

    <!-- METRIC 6 (Rose) -->
    <circle cx="${g.col3X + 19}" cy="${g.row2Y + 19}" r="19" fill="${c6}" fill-opacity="0.14"/>
    <g transform="translate(${g.col3X + 9}, ${g.row2Y + 9})">
      <polygon points="10,2.5 12.3,7.3 17.5,8.1 13.8,11.8 14.7,17 10,14.5 5.3,17 6.2,11.8 2.5,8.1 7.7,7.3" fill="none" stroke="${c6}" stroke-width="1.6" stroke-linejoin="round"/>
    </g>
    <rect x="${g.col3X + g.pillX}" y="${g.row2Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="6" fill="${c6}" fill-opacity="0.12" stroke="${c6}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col3X + g.pillX + g.pillW / 2}" y="${g.row2Y + g.pillY + 15}" text-anchor="middle" fill="${c6}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t6}</text>
    <text x="${g.col3X}" y="${g.row2Y + 90}" fill="#0F172A" font-size="38" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v6}</text>
    <text x="${g.col3X}" y="${g.row2Y + 118}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l6}</text>
    <rect x="${g.col3X}" y="${g.row2Y + 132}" width="${g.underlineW}" height="${g.underlineH}" rx="2" fill="url(#m6pu6)"/>
  </svg>`;
}

module.exports = {
  isMetricSixParaLayout,
  isMetricSixParaTextSlot,
  layoutMetricSixPara,
  metricSixParaPreviewSvg,
  M6P_GEOM,
  M6P_DEFAULTS,
  M6P_COLORS,
};
