/**
 * Metric six cards — Supporting paragraph with 6 high-impact metric cards in a 3x2 grid.
 * CommonJS backend port for Athena VI Presentation diagram pipeline.
 * Layout id: metric_six_cards_v1.
 */

const M6C_GEOM = {
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

  // 6 Cards in 3 cols x 2 rows
  cardW: 293,
  cardH: 154,
  col1X: 40,
  col2X: 353,
  col3X: 666,
  row1Y: 172,
  row2Y: 344,

  // Inside each card
  iconX: 16,
  iconY: 16,
  iconSize: 24,
  iconBgSize: 42,

  pillX: 220,
  pillY: 18,
  pillW: 58,
  pillH: 20,

  valueX: 16,
  valueY: 68,
  valueW: 260,
  valueH: 44,

  labelX: 16,
  labelY: 116,
  labelW: 260,
  labelH: 24,
};

const M6C_COLORS = {
  card1: '#3B82F6',  // Blue
  card2: '#8B5CF6',  // Purple
  card3: '#10B981',  // Green
  card4: '#F59E0B',  // Amber
  card5: '#06B6D4',  // Cyan
  card6: '#EC4899',  // Rose
};

const M6C_DEFAULTS = {
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

function isMetricSixCardsLayout(layoutId, schema = null) {
  const id = String(layoutId || schema?.layout_id || schema?.id || schema?.layoutId || '').toLowerCase();
  if (/metric_six_cards/i.test(id)) return true;
  const variant = String(schema?.variant || schema?.dataVariant || schema?.preview?.dataVariant || '').toLowerCase();
  if ((/metric_six/i.test(id) || /stat_six/i.test(id)) && variant === 'cards') return true;
  return false;
}

function isMetricSixCardsTextSlot(slotId) {
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

function badgeSvg() {
  const g = M6C_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.badgeW} ${g.badgeH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.badgeW}" height="${g.badgeH}" fill="#DBEAFE" rx="6"/>
  </svg>`;
}

function badgeIconSvg() {
  const size = M6C_GEOM.badgeIconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>
    <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>
    <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>
  </svg>`;
}

function cardBgSvg(color) {
  const g = M6C_GEOM;
  const cleanColor = color.replace('#', '');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.cardW} ${g.cardH}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="m6cGrad_${cleanColor}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:${color};stop-opacity:0.07" />
        <stop offset="100%" style="stop-color:${color};stop-opacity:0.15" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${g.cardW}" height="${g.cardH}" fill="url(#m6cGrad_${cleanColor})" stroke="${color}" stroke-width="1.5" stroke-opacity="0.22" rx="16"/>
  </svg>`;
}

function iconBgSvg(color) {
  const size = M6C_GEOM.iconBgSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="0" y="0" width="${size}" height="${size}" fill="${color}" fill-opacity="0.15" rx="11"/>
  </svg>`;
}

function pillBgSvg(color) {
  const g = M6C_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.pillW} ${g.pillH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.pillW}" height="${g.pillH}" fill="${color}" fill-opacity="0.12" stroke="${color}" stroke-width="0.8" stroke-opacity="0.25" rx="5"/>
  </svg>`;
}

function card1IconSvg() {
  const size = M6C_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="12" cy="8" r="5" fill="none" stroke="currentColor" stroke-width="2"/>
    <path d="M5 21 C5 16, 9 15, 12 15 C15 15, 19 16, 19 21" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
  </svg>`;
}

function card2IconSvg() {
  const size = M6C_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <polyline points="4,18 10,12 15,16 22,7" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="16,7 22,7 22,13" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function card3IconSvg() {
  const size = M6C_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="7" cy="8" r="3.5" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="17" cy="8" r="3.5" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="12" cy="18" r="3.5" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <line x1="9.5" y1="10" x2="11" y2="15" stroke="currentColor" stroke-width="1.5"/>
    <line x1="14.5" y1="10" x2="13" y2="15" stroke="currentColor" stroke-width="1.5"/>
  </svg>`;
}

function card4IconSvg() {
  const size = M6C_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
    <polyline points="12,7 12,12 16,12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`;
}

function card5IconSvg() {
  const size = M6C_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
    <line x1="3" y1="12" x2="21" y2="12" stroke="currentColor" stroke-width="1.6"/>
    <ellipse cx="12" cy="12" rx="4.5" ry="9" fill="none" stroke="currentColor" stroke-width="1.6"/>
  </svg>`;
}

function card6IconSvg() {
  const size = M6C_GEOM.iconSize;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <polygon points="12,3 14.8,8.8 21.2,9.7 16.6,14.2 17.7,20.6 12,17.6 6.3,20.6 7.4,14.2 2.8,9.7 9.2,8.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
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

function metricSixCardsChromeSpecs() {
  const g = M6C_GEOM;
  const specs = [];

  // Badge background
  specs.push({
    slotId: 'M6C_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: '#DBEAFE',
    layer: 3,
    kind: 'badge',
  });

  // Badge icon
  specs.push({
    slotId: 'M6C_BADGE_ICON',
    x: g.badgeX + 10,
    y: g.badgeY + 4,
    w: g.badgeIconSize,
    h: g.badgeIconSize,
    color: '#3B82F6',
    layer: 10,
    kind: 'badgeIcon',
  });

  const cards = [
    { x: g.col1X, y: g.row1Y, color: M6C_COLORS.card1, id: 1 },
    { x: g.col2X, y: g.row1Y, color: M6C_COLORS.card2, id: 2 },
    { x: g.col3X, y: g.row1Y, color: M6C_COLORS.card3, id: 3 },
    { x: g.col1X, y: g.row2Y, color: M6C_COLORS.card4, id: 4 },
    { x: g.col2X, y: g.row2Y, color: M6C_COLORS.card5, id: 5 },
    { x: g.col3X, y: g.row2Y, color: M6C_COLORS.card6, id: 6 },
  ];

  cards.forEach((card) => {
    // Card background with rounded corners and gradient fill
    specs.push({
      slotId: `M6C_CARD${card.id}_BG`,
      x: card.x,
      y: card.y,
      w: g.cardW,
      h: g.cardH,
      color: card.color,
      layer: 3,
      kind: 'cardBg',
    });

    // Icon background (tinted square with rx=11)
    specs.push({
      slotId: `M6C_CARD${card.id}_ICON_BG`,
      x: card.x + g.iconX,
      y: card.y + g.iconY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: card.color,
      layer: 5,
      kind: 'iconBg',
    });

    // Icon inside card
    specs.push({
      slotId: `M6C_CARD${card.id}_ICON`,
      x: card.x + g.iconX + (g.iconBgSize - g.iconSize) / 2,
      y: card.y + g.iconY + (g.iconBgSize - g.iconSize) / 2,
      w: g.iconSize,
      h: g.iconSize,
      color: card.color,
      layer: 10,
      kind: `card${card.id}Icon`,
    });

    // Trend pill background
    specs.push({
      slotId: `M6C_CARD${card.id}_PILL_BG`,
      x: card.x + g.pillX,
      y: card.y + g.pillY,
      w: g.pillW,
      h: g.pillH,
      color: card.color,
      layer: 5,
      kind: 'pillBg',
    });
  });

  return specs;
}

function metricSixCardsOverlay(gx, gy, gw, gh) {
  const g = M6C_GEOM;
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

  const cards = [
    { x: g.col1X, y: g.row1Y, id: 1 },
    { x: g.col2X, y: g.row1Y, id: 2 },
    { x: g.col3X, y: g.row1Y, id: 3 },
    { x: g.col1X, y: g.row2Y, id: 4 },
    { x: g.col2X, y: g.row2Y, id: 5 },
    { x: g.col3X, y: g.row2Y, id: 6 },
  ];

  cards.forEach((card) => {
    overlays[`card${card.id}Value`] = box(card.x + g.valueX, card.y + g.valueY, g.valueW, g.valueH);
    overlays[`card${card.id}Label`] = box(card.x + g.labelX, card.y + g.labelY, g.labelW, g.labelH);
    overlays[`card${card.id}Trend`] = box(card.x + g.pillX, card.y + g.pillY, g.pillW, g.pillH);
  });

  return overlays;
}

function specToMetricSixCardsContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'cardBg') return { svg: cardBgSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'pillBg') return { svg: pillBgSvg(spec.color), colorMode: 'fixed', fill: spec.color };
  if (spec.kind === 'card1Icon') return { svg: card1IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card2Icon') return { svg: card2IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card3Icon') return { svg: card3IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card4Icon') return { svg: card4IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card5Icon') return { svg: card5IconSvg(), colorMode: 'recolor', fill: spec.color };
  if (spec.kind === 'card6Icon') return { svg: card6IconSvg(), colorMode: 'recolor', fill: spec.color };
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
    : (M6C_DEFAULTS[defaultKey] || M6C_DEFAULTS[sid] || existing || '');
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

function layoutMetricSixCards(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / M6C_GEOM.viewW;
  const sy = canvasH / M6C_GEOM.viewH;
  const overlay = metricSixCardsOverlay(0, 0, canvasW, canvasH);
  const chromeRe = /^M6C_/i;

  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  );

  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricSixCardsTextSlot(el.slotId));
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]));

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId.toUpperCase());
    return {
      id: prev?.id || newId('txt-m6c'),
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
    M6C_COLORS.card1,
    M6C_COLORS.card2,
    M6C_COLORS.card3,
    M6C_COLORS.card4,
    M6C_COLORS.card5,
    M6C_COLORS.card6,
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

  const chrome = metricSixCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToMetricSixCardsContent(spec);
    if (!graphic) return null;
    return {
      id: prev?.id || newId('shp-m6c'),
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

/**
 * Polished SVG Preview for Metric Six Cards thumbnail in slide picker.
 * Exact 1000x560 slide canvas matching rendered slide layout.
 */
function metricSixCardsPreviewSvg(previewHints = {}, theme = {}) {
  const slots = previewHints?.slots || {};
  const stats = previewHints?.stats || [];

  const badgeText = slots.BADGE?.text || previewHints?.badge || M6C_DEFAULTS.BADGE;
  const headingText = slots.HEADING?.text || previewHints?.heading || M6C_DEFAULTS.HEADING;
  const bodyText = slots.BODY?.text || slots.PARAGRAPH?.text || slots.SUBHEADING?.text || previewHints?.bodyText || previewHints?.subheading || M6C_DEFAULTS.BODY;

  const v1 = slots.STAT_1_VALUE?.text || slots.CARD1_VALUE?.text || (stats[0]?.value) || M6C_DEFAULTS.STAT_1_VALUE;
  const l1 = slots.STAT_1_LABEL?.text || slots.CARD1_LABEL?.text || (stats[0]?.label) || M6C_DEFAULTS.STAT_1_LABEL;
  const t1 = slots.CARD1_TREND?.text || M6C_DEFAULTS.CARD1_TREND;

  const v2 = slots.STAT_2_VALUE?.text || slots.CARD2_VALUE?.text || (stats[1]?.value) || M6C_DEFAULTS.STAT_2_VALUE;
  const l2 = slots.STAT_2_LABEL?.text || slots.CARD2_LABEL?.text || (stats[1]?.label) || M6C_DEFAULTS.STAT_2_LABEL;
  const t2 = slots.CARD2_TREND?.text || M6C_DEFAULTS.CARD2_TREND;

  const v3 = slots.STAT_3_VALUE?.text || slots.CARD3_VALUE?.text || (stats[2]?.value) || M6C_DEFAULTS.STAT_3_VALUE;
  const l3 = slots.STAT_3_LABEL?.text || slots.CARD3_LABEL?.text || (stats[2]?.label) || M6C_DEFAULTS.STAT_3_LABEL;
  const t3 = slots.CARD3_TREND?.text || M6C_DEFAULTS.CARD3_TREND;

  const v4 = slots.STAT_4_VALUE?.text || slots.CARD4_VALUE?.text || (stats[3]?.value) || M6C_DEFAULTS.STAT_4_VALUE;
  const l4 = slots.STAT_4_LABEL?.text || slots.CARD4_LABEL?.text || (stats[3]?.label) || M6C_DEFAULTS.STAT_4_LABEL;
  const t4 = slots.CARD4_TREND?.text || M6C_DEFAULTS.CARD4_TREND;

  const v5 = slots.STAT_5_VALUE?.text || slots.CARD5_VALUE?.text || (stats[4]?.value) || M6C_DEFAULTS.STAT_5_VALUE;
  const l5 = slots.STAT_5_LABEL?.text || slots.CARD5_LABEL?.text || (stats[4]?.label) || M6C_DEFAULTS.STAT_5_LABEL;
  const t5 = slots.CARD5_TREND?.text || M6C_DEFAULTS.CARD5_TREND;

  const v6 = slots.STAT_6_VALUE?.text || slots.CARD6_VALUE?.text || (stats[5]?.value) || M6C_DEFAULTS.STAT_6_VALUE;
  const l6 = slots.STAT_6_LABEL?.text || slots.CARD6_LABEL?.text || (stats[5]?.label) || M6C_DEFAULTS.STAT_6_LABEL;
  const t6 = slots.CARD6_TREND?.text || M6C_DEFAULTS.CARD6_TREND;

  const c1 = M6C_COLORS.card1;
  const c2 = M6C_COLORS.card2;
  const c3 = M6C_COLORS.card3;
  const c4 = M6C_COLORS.card4;
  const c5 = M6C_COLORS.card5;
  const c6 = M6C_COLORS.card6;

  const g = M6C_GEOM;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <defs>
      <linearGradient id="m6cg1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c1}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c1}" stop-opacity="0.16"/>
      </linearGradient>
      <linearGradient id="m6cg2" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c2}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c2}" stop-opacity="0.16"/>
      </linearGradient>
      <linearGradient id="m6cg3" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c3}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c3}" stop-opacity="0.16"/>
      </linearGradient>
      <linearGradient id="m6cg4" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c4}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c4}" stop-opacity="0.16"/>
      </linearGradient>
      <linearGradient id="m6cg5" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c5}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c5}" stop-opacity="0.16"/>
      </linearGradient>
      <linearGradient id="m6cg6" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c6}" stop-opacity="0.08"/>
        <stop offset="100%" stop-color="${c6}" stop-opacity="0.16"/>
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

    <!-- CARD 1 (Blue) -->
    <rect x="${g.col1X}" y="${g.row1Y}" width="${g.cardW}" height="${g.cardH}" rx="16" fill="url(#m6cg1)" stroke="${c1}" stroke-width="1.5" stroke-opacity="0.25"/>
    <rect x="${g.col1X + 16}" y="${g.row1Y + 16}" width="42" height="42" rx="11" fill="${c1}" fill-opacity="0.15"/>
    <g transform="translate(${g.col1X + 25}, ${g.row1Y + 25})">
      <circle cx="12" cy="8" r="5" fill="none" stroke="${c1}" stroke-width="2"/>
      <path d="M5 21 C5 16, 9 15, 12 15 C15 15, 19 16, 19 21" fill="none" stroke="${c1}" stroke-width="2" stroke-linecap="round"/>
    </g>
    <rect x="${g.col1X + g.pillX}" y="${g.row1Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="5" fill="${c1}" fill-opacity="0.12" stroke="${c1}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col1X + g.pillX + g.pillW / 2}" y="${g.row1Y + g.pillY + 14}" text-anchor="middle" fill="${c1}" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t1}</text>
    <text x="${g.col1X + 16}" y="${g.row1Y + 104}" fill="#0F172A" font-size="36" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v1}</text>
    <text x="${g.col1X + 16}" y="${g.row1Y + 132}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l1}</text>

    <!-- CARD 2 (Purple) -->
    <rect x="${g.col2X}" y="${g.row1Y}" width="${g.cardW}" height="${g.cardH}" rx="16" fill="url(#m6cg2)" stroke="${c2}" stroke-width="1.5" stroke-opacity="0.25"/>
    <rect x="${g.col2X + 16}" y="${g.row1Y + 16}" width="42" height="42" rx="11" fill="${c2}" fill-opacity="0.15"/>
    <g transform="translate(${g.col2X + 25}, ${g.row1Y + 25})">
      <polyline points="4,18 10,12 15,16 22,7" fill="none" stroke="${c2}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
      <polyline points="16,7 22,7 22,13" fill="none" stroke="${c2}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <rect x="${g.col2X + g.pillX}" y="${g.row1Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="5" fill="${c2}" fill-opacity="0.12" stroke="${c2}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col2X + g.pillX + g.pillW / 2}" y="${g.row1Y + g.pillY + 14}" text-anchor="middle" fill="${c2}" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t2}</text>
    <text x="${g.col2X + 16}" y="${g.row1Y + 104}" fill="#0F172A" font-size="36" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v2}</text>
    <text x="${g.col2X + 16}" y="${g.row1Y + 132}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l2}</text>

    <!-- CARD 3 (Green) -->
    <rect x="${g.col3X}" y="${g.row1Y}" width="${g.cardW}" height="${g.cardH}" rx="16" fill="url(#m6cg3)" stroke="${c3}" stroke-width="1.5" stroke-opacity="0.25"/>
    <rect x="${g.col3X + 16}" y="${g.row1Y + 16}" width="42" height="42" rx="11" fill="${c3}" fill-opacity="0.15"/>
    <g transform="translate(${g.col3X + 25}, ${g.row1Y + 25})">
      <circle cx="7" cy="8" r="3.5" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="17" cy="8" r="3.5" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <circle cx="12" cy="18" r="3.5" fill="none" stroke="${c3}" stroke-width="1.8"/>
      <line x1="9.5" y1="10" x2="11" y2="15" stroke="${c3}" stroke-width="1.5"/>
      <line x1="14.5" y1="10" x2="13" y2="15" stroke="${c3}" stroke-width="1.5"/>
    </g>
    <rect x="${g.col3X + g.pillX}" y="${g.row1Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="5" fill="${c3}" fill-opacity="0.12" stroke="${c3}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col3X + g.pillX + g.pillW / 2}" y="${g.row1Y + g.pillY + 14}" text-anchor="middle" fill="${c3}" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t3}</text>
    <text x="${g.col3X + 16}" y="${g.row1Y + 104}" fill="#0F172A" font-size="36" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v3}</text>
    <text x="${g.col3X + 16}" y="${g.row1Y + 132}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l3}</text>

    <!-- CARD 4 (Amber) -->
    <rect x="${g.col1X}" y="${g.row2Y}" width="${g.cardW}" height="${g.cardH}" rx="16" fill="url(#m6cg4)" stroke="${c4}" stroke-width="1.5" stroke-opacity="0.25"/>
    <rect x="${g.col1X + 16}" y="${g.row2Y + 16}" width="42" height="42" rx="11" fill="${c4}" fill-opacity="0.15"/>
    <g transform="translate(${g.col1X + 25}, ${g.row2Y + 25})">
      <circle cx="12" cy="12" r="9" fill="none" stroke="${c4}" stroke-width="2"/>
      <polyline points="12,7 12,12 16,12" fill="none" stroke="${c4}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <rect x="${g.col1X + g.pillX}" y="${g.row2Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="5" fill="${c4}" fill-opacity="0.12" stroke="${c4}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col1X + g.pillX + g.pillW / 2}" y="${g.row2Y + g.pillY + 14}" text-anchor="middle" fill="${c4}" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t4}</text>
    <text x="${g.col1X + 16}" y="${g.row2Y + 104}" fill="#0F172A" font-size="36" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v4}</text>
    <text x="${g.col1X + 16}" y="${g.row2Y + 132}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l4}</text>

    <!-- CARD 5 (Cyan) -->
    <rect x="${g.col2X}" y="${g.row2Y}" width="${g.cardW}" height="${g.cardH}" rx="16" fill="url(#m6cg5)" stroke="${c5}" stroke-width="1.5" stroke-opacity="0.25"/>
    <rect x="${g.col2X + 16}" y="${g.row2Y + 16}" width="42" height="42" rx="11" fill="${c5}" fill-opacity="0.15"/>
    <g transform="translate(${g.col2X + 25}, ${g.row2Y + 25})">
      <circle cx="12" cy="12" r="9" fill="none" stroke="${c5}" stroke-width="2"/>
      <line x1="3" y1="12" x2="21" y2="12" stroke="${c5}" stroke-width="1.6"/>
      <ellipse cx="12" cy="12" rx="4.5" ry="9" fill="none" stroke="${c5}" stroke-width="1.6"/>
    </g>
    <rect x="${g.col2X + g.pillX}" y="${g.row2Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="5" fill="${c5}" fill-opacity="0.12" stroke="${c5}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col2X + g.pillX + g.pillW / 2}" y="${g.row2Y + g.pillY + 14}" text-anchor="middle" fill="${c5}" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t5}</text>
    <text x="${g.col2X + 16}" y="${g.row2Y + 104}" fill="#0F172A" font-size="36" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v5}</text>
    <text x="${g.col2X + 16}" y="${g.row2Y + 132}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l5}</text>

    <!-- CARD 6 (Rose) -->
    <rect x="${g.col3X}" y="${g.row2Y}" width="${g.cardW}" height="${g.cardH}" rx="16" fill="url(#m6cg6)" stroke="${c6}" stroke-width="1.5" stroke-opacity="0.25"/>
    <rect x="${g.col3X + 16}" y="${g.row2Y + 16}" width="42" height="42" rx="11" fill="${c6}" fill-opacity="0.15"/>
    <g transform="translate(${g.col3X + 25}, ${g.row2Y + 25})">
      <polygon points="12,3 14.8,8.8 21.2,9.7 16.6,14.2 17.7,20.6 12,17.6 6.3,20.6 7.4,14.2 2.8,9.7 9.2,8.8" fill="none" stroke="${c6}" stroke-width="1.8" stroke-linejoin="round"/>
    </g>
    <rect x="${g.col3X + g.pillX}" y="${g.row2Y + g.pillY}" width="${g.pillW}" height="${g.pillH}" rx="5" fill="${c6}" fill-opacity="0.12" stroke="${c6}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.col3X + g.pillX + g.pillW / 2}" y="${g.row2Y + g.pillY + 14}" text-anchor="middle" fill="${c6}" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t6}</text>
    <text x="${g.col3X + 16}" y="${g.row2Y + 104}" fill="#0F172A" font-size="36" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v6}</text>
    <text x="${g.col3X + 16}" y="${g.row2Y + 132}" fill="#1E293B" font-size="13.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l6}</text>
  </svg>`;
}

module.exports = {
  isMetricSixCardsLayout,
  isMetricSixCardsTextSlot,
  layoutMetricSixCards,
  metricSixCardsPreviewSvg,
  M6C_GEOM,
  M6C_DEFAULTS,
  M6C_COLORS,
};
