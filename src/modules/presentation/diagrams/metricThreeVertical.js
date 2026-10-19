/**
 * Metric three vertical — Three high-impact metrics stacked vertically in clean rows.
 * Available in both cardless (open rows with hairline dividers) and cards variants.
 * Layout IDs: metric_three_vertical_v1, metric_three_vertical_cards_v1.
 */

const M3V_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Badge at top
  badgeX: 50,
  badgeY: 34,
  badgeW: 140,
  badgeH: 24,
  badgeIconSize: 14,

  // Heading
  headingX: 50,
  headingY: 66,
  headingW: 900,
  headingH: 36,

  // Supporting paragraph (BODY)
  bodyX: 50,
  bodyY: 104,
  bodyW: 900,
  bodyH: 26,

  // 3 Vertical Rows (stacked vertically)
  rowX: 50,
  rowW: 900,
  rowH: 114,
  gap: 14,

  row1Y: 142,
  row2Y: 270,
  row3Y: 398,

  // Inside each row
  iconBgX: 20,
  iconBgY: 27,
  iconBgSize: 60,
  iconSize: 28,

  valX: 102,
  valY: 24,
  valW: 160,
  valH: 66,

  trendX: 280,
  trendY: 28,
  trendW: 92,
  trendH: 24,

  labelX: 280,
  labelY: 56,
  labelW: 380,
  labelH: 24,

  descX: 280,
  descY: 80,
  descW: 380,
  descH: 28,

  trackX: 680,
  trackY: 62,
  trackW: 195,
  trackH: 8,

  statusPillX: 775,
  statusPillY: 28,
  statusPillW: 100,
  statusPillH: 24,
};

const M3V_COLORS = {
  row1: '#2563EB', // Blue
  row1Bg: '#EFF6FF',
  row1Border: '#BFDBFE',

  row2: '#7C3AED', // Purple
  row2Bg: '#F5F3FF',
  row2Border: '#DDD6FE',

  row3: '#059669', // Emerald
  row3Bg: '#ECFDF5',
  row3Border: '#A7F3D0',

  badgeBg: '#DBEAFE',
  badgeText: '#2563EB',
  divider: '#E2E8F0',
  trackBg: '#E2E8F0',
};

const M3V_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Key metrics',
  BODY: 'Three vital performance benchmarks demonstrating organizational impact, efficiency, and scale.',

  STAT_1_VALUE: '98%',
  STAT_1_LABEL: 'Customer satisfaction',
  STAT_1_DESC: 'Direct survey response rate across enterprise accounts.',
  STAT_1_TREND: '★ 98% Score',
  STAT_1_STATUS: 'Exceeds target',

  STAT_2_VALUE: '3.2x',
  STAT_2_LABEL: 'Average ROI',
  STAT_2_DESC: 'Consistently outperforming benchmark industry sector averages.',
  STAT_2_TREND: '+28% YoY',
  STAT_2_STATUS: 'Top quartile',

  STAT_3_VALUE: '500+',
  STAT_3_LABEL: 'Active teams',
  STAT_3_DESC: 'Cross-functional engineering and product teams collaborating daily.',
  STAT_3_TREND: '+120 new',
  STAT_3_STATUS: 'Global scale',
};

function isMetricThreeVerticalCardsLayout(layoutId, schema = null) {
  const id = String(layoutId || schema?.layout_id || schema?.id || schema?.layoutId || '').toLowerCase();
  if (/metric_three_vertical_cards/i.test(id)) return true;
  const variant = String(schema?.variant || schema?.dataVariant || schema?.preview?.dataVariant || '').toLowerCase();
  if ((/metric_three_vertical/i.test(id) || /stat_vertical/i.test(id)) && variant === 'cards') return true;
  return false;
}

function isMetricThreeVerticalLayout(layoutId, schema = null) {
  const id = String(layoutId || schema?.layout_id || schema?.id || schema?.layoutId || '').toLowerCase();
  if (isMetricThreeVerticalCardsLayout(layoutId, schema)) return false;
  return /metric_three_vertical_v1$/i.test(id) || (/stat_vertical$/i.test(id) && !isMetricThreeVerticalCardsLayout(layoutId, schema));
}

function isMetricThreeVerticalTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase();
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'BODY' || sid === 'PARAGRAPH' || sid === 'SUBHEADING'
    || sid === 'STAT_1_VALUE' || sid === 'STAT_1_LABEL' || sid === 'STAT_1_DESC' || sid === 'STAT_1_TREND' || sid === 'CARD1_TREND'
    || sid === 'STAT_2_VALUE' || sid === 'STAT_2_LABEL' || sid === 'STAT_2_DESC' || sid === 'STAT_2_TREND' || sid === 'CARD2_TREND'
    || sid === 'STAT_3_VALUE' || sid === 'STAT_3_LABEL' || sid === 'STAT_3_DESC' || sid === 'STAT_3_TREND' || sid === 'CARD3_TREND';
}

let _idCounter = 0;
function newId(prefix = 'm3v') {
  return `${prefix}-${Date.now().toString(36)}-${(++_idCounter).toString(36)}`;
}

function filledContent(prev, slotId, fallbackStyle) {
  const raw = prev?.content;
  const text = typeof raw === 'string'
    ? raw
    : (raw?.text ?? M3V_DEFAULTS[slotId.toUpperCase()] ?? '');
  return {
    text: String(text).trim() ? String(text) : (M3V_DEFAULTS[slotId.toUpperCase()] ?? ''),
    fontSize: raw?.fontSize ?? fallbackStyle.fontSize ?? 14,
    fontWeight: raw?.fontWeight ?? fallbackStyle.fontWeight ?? 400,
    color: raw?.color ?? fallbackStyle.color ?? '#0F172A',
    fontFamily: raw?.fontFamily ?? fallbackStyle.fontFamily ?? 'Inter, system-ui, sans-serif',
    align: raw?.align ?? fallbackStyle.align ?? 'left',
    verticalAlign: raw?.verticalAlign ?? fallbackStyle.verticalAlign ?? 'top',
    wrap: raw?.wrap ?? fallbackStyle.wrap ?? 'wrap',
    lineHeight: raw?.lineHeight ?? fallbackStyle.lineHeight ?? 1.2,
    letterSpacing: raw?.letterSpacing ?? fallbackStyle.letterSpacing ?? 'normal',
    clipToSlot: false,
  };
}

function hexLum(hex = '#ffffff') {
  const c = String(hex).replace('#', '');
  if (c.length !== 6) return 1;
  const r = parseInt(c.slice(0, 2), 16) / 255;
  const g = parseInt(c.slice(2, 4), 16) / 255;
  const b = parseInt(c.slice(4, 6), 16) / 255;
  const lin = (v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4));
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

function headingInk(palette = {}) {
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff';
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#0F172A';
}

function metricThreeVerticalChromeSpecs(isCards = false) {
  const g = M3V_GEOM;
  const specs = [];

  // Badge background & icon
  specs.push({
    slotId: 'M3V_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: '#DBEAFE',
    layer: 3,
    kind: 'badge',
  });
  specs.push({
    slotId: 'M3V_BADGE_ICON',
    x: g.badgeX + 10,
    y: g.badgeY + 5,
    w: g.badgeIconSize,
    h: g.badgeIconSize,
    color: '#3B82F6',
    layer: 10,
    kind: 'badgeIcon',
  });

  const rows = [
    { y: g.row1Y, color: M3V_COLORS.row1, id: 1, pct: 98, status: M3V_DEFAULTS.STAT_1_STATUS },
    { y: g.row2Y, color: M3V_COLORS.row2, id: 2, pct: 84, status: M3V_DEFAULTS.STAT_2_STATUS },
    { y: g.row3Y, color: M3V_COLORS.row3, id: 3, pct: 92, status: M3V_DEFAULTS.STAT_3_STATUS },
  ];

  rows.forEach((row, idx) => {
    // Card background in cards variant
    if (isCards) {
      specs.push({
        slotId: `M3V_ROW${row.id}_BG`,
        x: g.rowX,
        y: row.y,
        w: g.rowW,
        h: g.rowH,
        color: row.color,
        layer: 3,
        kind: 'rowCardBg',
        rowId: row.id,
      });
    } else if (idx < 2) {
      // Hairline divider between rows in cardless variant
      specs.push({
        slotId: `M3V_DIVIDER_${row.id}`,
        x: g.rowX,
        y: row.y + g.rowH + 6,
        w: g.rowW,
        h: 1,
        color: M3V_COLORS.divider,
        layer: 3,
        kind: 'rowDivider',
      });
    }

    // Icon background
    specs.push({
      slotId: `M3V_ROW${row.id}_ICON_BG`,
      x: g.rowX + g.iconBgX,
      y: row.y + g.iconBgY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: row.color,
      layer: 5,
      kind: 'iconBg',
    });

    // Icon glyph
    specs.push({
      slotId: `M3V_ROW${row.id}_ICON`,
      x: g.rowX + g.iconBgX + (g.iconBgSize - g.iconSize) / 2,
      y: row.y + g.iconBgY + (g.iconBgSize - g.iconSize) / 2,
      w: g.iconSize,
      h: g.iconSize,
      color: row.color,
      layer: 10,
      kind: `row${row.id}Icon`,
    });

    // Trend pill background
    specs.push({
      slotId: `M3V_ROW${row.id}_TREND_BG`,
      x: g.rowX + g.trendX,
      y: row.y + g.trendY,
      w: g.trendW,
      h: g.trendH,
      color: row.color,
      layer: 5,
      kind: 'trendBg',
    });

    // Progress track background
    specs.push({
      slotId: `M3V_ROW${row.id}_TRACK_BG`,
      x: g.rowX + g.trackX,
      y: row.y + g.trackY,
      w: g.trackW,
      h: g.trackH,
      color: M3V_COLORS.trackBg,
      layer: 4,
      kind: 'trackBg',
    });

    // Progress track fill
    specs.push({
      slotId: `M3V_ROW${row.id}_TRACK_FILL`,
      x: g.rowX + g.trackX,
      y: row.y + g.trackY,
      w: Math.round(g.trackW * (row.pct / 100)),
      h: g.trackH,
      color: row.color,
      layer: 6,
      kind: 'trackFill',
    });

    // Status pill background
    specs.push({
      slotId: `M3V_ROW${row.id}_STATUS_BG`,
      x: g.rowX + g.statusPillX,
      y: row.y + g.statusPillY,
      w: g.statusPillW,
      h: g.statusPillH,
      color: row.color,
      layer: 5,
      kind: 'statusBg',
      statusText: row.status,
    });
  });

  return specs;
}

function metricThreeVerticalOverlay(gx, gy, gw, gh) {
  const g = M3V_GEOM;
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

  const rows = [
    { y: g.row1Y, id: 1 },
    { y: g.row2Y, id: 2 },
    { y: g.row3Y, id: 3 },
  ];

  rows.forEach((r) => {
    overlays[`row${r.id}Value`] = box(g.rowX + g.valX, r.y + g.valY, g.valW, g.valH);
    overlays[`row${r.id}Trend`] = box(g.rowX + g.trendX, r.y + g.trendY, g.trendW, g.trendH);
    overlays[`row${r.id}Label`] = box(g.rowX + g.labelX, r.y + g.labelY, g.labelW, g.labelH);
    overlays[`row${r.id}Desc`] = box(g.rowX + g.descX, r.y + g.descY, g.descW, g.descH);
    overlays[`row${r.id}Status`] = box(g.rowX + g.statusPillX, r.y + g.statusPillY, g.statusPillW, g.statusPillH);
  });

  return overlays;
}

function specToMetricThreeVerticalContent(spec) {
  const { kind, w, h, color } = spec;

  if (kind === 'badge') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
        <rect width="${w}" height="${h}" rx="6" fill="#DBEAFE"/>
      </svg>`,
    };
  }

  if (kind === 'badgeIcon') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14" width="100%" height="100%">
        <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>
        <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>
        <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>
      </svg>`,
    };
  }

  if (kind === 'rowCardBg') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
        <defs>
          <linearGradient id="bg_grad_${spec.rowId}" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="${color}" stop-opacity="0.06"/>
            <stop offset="100%" stop-color="${color}" stop-opacity="0.14"/>
          </linearGradient>
        </defs>
        <rect width="${w}" height="${h}" rx="16" fill="url(#bg_grad_${spec.rowId})" stroke="${color}" stroke-width="1.5" stroke-opacity="0.25"/>
      </svg>`,
    };
  }

  if (kind === 'rowDivider') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
        <line x1="0" y1="0" x2="${w}" y2="0" stroke="${color}" stroke-width="1" stroke-opacity="0.6"/>
      </svg>`,
    };
  }

  if (kind === 'iconBg') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
        <rect width="${w}" height="${h}" rx="16" fill="${color}" fill-opacity="0.14" stroke="${color}" stroke-width="1" stroke-opacity="0.25"/>
      </svg>`,
    };
  }

  if (kind === 'row1Icon') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
      </svg>`,
    };
  }

  if (kind === 'row2Icon') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/>
        <polyline points="17 6 23 6 23 12"/>
      </svg>`,
    };
  }

  if (kind === 'row3Icon') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
        <circle cx="9" cy="7" r="4"/>
        <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
        <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
      </svg>`,
    };
  }

  if (kind === 'trendBg') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
        <rect width="${w}" height="${h}" rx="6" fill="${color}" fill-opacity="0.12" stroke="${color}" stroke-width="0.8" stroke-opacity="0.25"/>
      </svg>`,
    };
  }

  if (kind === 'trackBg') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
        <rect width="${w}" height="${h}" rx="4" fill="${color}"/>
      </svg>`,
    };
  }

  if (kind === 'trackFill') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
        <defs>
          <linearGradient id="tf_grad_${w}" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="${color}" stop-opacity="0.8"/>
            <stop offset="100%" stop-color="${color}" stop-opacity="1"/>
          </linearGradient>
        </defs>
        <rect width="${w}" height="${h}" rx="4" fill="url(#tf_grad_${w})"/>
      </svg>`,
    };
  }

  if (kind === 'statusBg') {
    return {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
        <rect width="${w}" height="${h}" rx="6" fill="${color}" fill-opacity="0.1" stroke="${color}" stroke-width="0.8" stroke-opacity="0.3"/>
      </svg>`,
    };
  }

  return null;
}

function buildLayout(elements, schema, palette = {}, canvas = {}, isCards = false) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / M3V_GEOM.viewW;
  const sy = canvasH / M3V_GEOM.viewH;
  const overlay = metricThreeVerticalOverlay(0, 0, canvasW, canvasH);
  const chromeRe = /^M3V_/i;

  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  );

  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricThreeVerticalTextSlot(el.slotId));
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]));

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId.toUpperCase());
    return {
      id: prev?.id || newId('txt-m3v'),
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
      align: 'left', verticalAlign: 'center', fontSize: 10, fontWeight: 700, color: '#2563EB', clipToSlot: false, lineHeight: 1, letterSpacing: '0.8px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 32, fontWeight: 800, color: headingInk(palette), clipToSlot: false, lineHeight: 1.15,
    }, 'heading'),
    placeText(bodySlot, overlay.body, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: false, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'),
  ];

  const rowColors = [M3V_COLORS.row1, M3V_COLORS.row2, M3V_COLORS.row3];

  for (let i = 1; i <= 3; i++) {
    const vSlot = bySlot.has(`STAT_${i}_VALUE`) ? `STAT_${i}_VALUE` : `STAT_${i}_VALUE`;
    const lSlot = bySlot.has(`STAT_${i}_LABEL`) ? `STAT_${i}_LABEL` : `STAT_${i}_LABEL`;
    const tSlot = bySlot.has(`STAT_${i}_TREND`) ? `STAT_${i}_TREND` : (bySlot.has(`CARD${i}_TREND`) ? `CARD${i}_TREND` : `STAT_${i}_TREND`);
    const dSlot = bySlot.has(`STAT_${i}_DESC`) ? `STAT_${i}_DESC` : `STAT_${i}_DESC`;

    next.push(
      placeText(vSlot, overlay[`row${i}Value`], {
        align: 'left', verticalAlign: 'center', fontSize: 44, fontWeight: 900, color: headingInk(palette), clipToSlot: false, lineHeight: 1,
      }, 'heading'),
      placeText(tSlot, overlay[`row${i}Trend`], {
        align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: rowColors[i - 1], clipToSlot: false, lineHeight: 1,
      }, 'caption'),
      placeText(lSlot, overlay[`row${i}Label`], {
        align: 'left', verticalAlign: 'top', fontSize: 16.5, fontWeight: 700, color: '#1E293B', clipToSlot: false, lineHeight: 1.2,
      }, 'heading'),
      placeText(dSlot, overlay[`row${i}Desc`], {
        align: 'left', verticalAlign: 'top', fontSize: 12.5, fontWeight: 400, color: '#64748B', clipToSlot: false, lineHeight: 1.3,
      }, 'body'),
      placeText(`STAT_${i}_STATUS`, overlay[`row${i}Status`], {
        align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: rowColors[i - 1], clipToSlot: false, lineHeight: 1,
      }, 'caption')
    );
  }

  const chrome = metricThreeVerticalChromeSpecs(isCards).map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToMetricThreeVerticalContent(spec);
    if (!graphic) return null;
    return {
      id: prev?.id || newId('shp-m3v'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement: {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.round(spec.w * sx),
        height: Math.round(spec.h * sy),
        rotation: 0,
        opacity: 1,
      },
      content: graphic,
      slotId: spec.slotId,
    };
  }).filter(Boolean);

  return [...chrome, ...next];
}

function layoutMetricThreeVertical(elements, schema, palette = {}, canvas = {}) {
  return buildLayout(elements, schema, palette, canvas, false);
}

function layoutMetricThreeVerticalCards(elements, schema, palette = {}, canvas = {}) {
  return buildLayout(elements, schema, palette, canvas, true);
}

function metricThreeVerticalPreviewSvg(previewHints = {}, theme = {}, isCards = false) {
  const slots = previewHints?.slots || {};
  const stats = previewHints?.stats || [];

  const badgeText = slots.BADGE?.text || previewHints?.badge || M3V_DEFAULTS.BADGE;
  const headingText = slots.HEADING?.text || previewHints?.heading || M3V_DEFAULTS.HEADING;
  const bodyText = slots.BODY?.text || slots.PARAGRAPH?.text || slots.SUBHEADING?.text || previewHints?.bodyText || previewHints?.subheading || M3V_DEFAULTS.BODY;

  const v1 = slots.STAT_1_VALUE?.text || (stats[0]?.value) || M3V_DEFAULTS.STAT_1_VALUE;
  const l1 = slots.STAT_1_LABEL?.text || (stats[0]?.label) || M3V_DEFAULTS.STAT_1_LABEL;
  const t1 = slots.STAT_1_TREND?.text || slots.CARD1_TREND?.text || M3V_DEFAULTS.STAT_1_TREND;
  const d1 = slots.STAT_1_DESC?.text || M3V_DEFAULTS.STAT_1_DESC;
  const s1 = M3V_DEFAULTS.STAT_1_STATUS;

  const v2 = slots.STAT_2_VALUE?.text || (stats[1]?.value) || M3V_DEFAULTS.STAT_2_VALUE;
  const l2 = slots.STAT_2_LABEL?.text || (stats[1]?.label) || M3V_DEFAULTS.STAT_2_LABEL;
  const t2 = slots.STAT_2_TREND?.text || slots.CARD2_TREND?.text || M3V_DEFAULTS.STAT_2_TREND;
  const d2 = slots.STAT_2_DESC?.text || M3V_DEFAULTS.STAT_2_DESC;
  const s2 = M3V_DEFAULTS.STAT_2_STATUS;

  const v3 = slots.STAT_3_VALUE?.text || (stats[2]?.value) || M3V_DEFAULTS.STAT_3_VALUE;
  const l3 = slots.STAT_3_LABEL?.text || (stats[2]?.label) || M3V_DEFAULTS.STAT_3_LABEL;
  const t3 = slots.STAT_3_TREND?.text || slots.CARD3_TREND?.text || M3V_DEFAULTS.STAT_3_TREND;
  const d3 = slots.STAT_3_DESC?.text || M3V_DEFAULTS.STAT_3_DESC;
  const s3 = M3V_DEFAULTS.STAT_3_STATUS;

  const c1 = M3V_COLORS.row1;
  const c2 = M3V_COLORS.row2;
  const c3 = M3V_COLORS.row3;
  const g = M3V_GEOM;

  const card1Bg = isCards
    ? `<rect x="${g.rowX}" y="${g.row1Y}" width="${g.rowW}" height="${g.rowH}" rx="16" fill="url(#m3vg1)" stroke="${c1}" stroke-width="1.5" stroke-opacity="0.25"/>`
    : `<line x1="${g.rowX}" y1="${g.row1Y + g.rowH + 6}" x2="${g.rowX + g.rowW}" y2="${g.row1Y + g.rowH + 6}" stroke="${M3V_COLORS.divider}" stroke-width="1"/>`;

  const card2Bg = isCards
    ? `<rect x="${g.rowX}" y="${g.row2Y}" width="${g.rowW}" height="${g.rowH}" rx="16" fill="url(#m3vg2)" stroke="${c2}" stroke-width="1.5" stroke-opacity="0.25"/>`
    : `<line x1="${g.rowX}" y1="${g.row2Y + g.rowH + 6}" x2="${g.rowX + g.rowW}" y2="${g.row2Y + g.rowH + 6}" stroke="${M3V_COLORS.divider}" stroke-width="1"/>`;

  const card3Bg = isCards
    ? `<rect x="${g.rowX}" y="${g.row3Y}" width="${g.rowW}" height="${g.rowH}" rx="16" fill="url(#m3vg3)" stroke="${c3}" stroke-width="1.5" stroke-opacity="0.25"/>`
    : '';

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <defs>
      <linearGradient id="m3vg1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c1}" stop-opacity="0.06"/>
        <stop offset="100%" stop-color="${c1}" stop-opacity="0.14"/>
      </linearGradient>
      <linearGradient id="m3vg2" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c2}" stop-opacity="0.06"/>
        <stop offset="100%" stop-color="${c2}" stop-opacity="0.14"/>
      </linearGradient>
      <linearGradient id="m3vg3" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${c3}" stop-opacity="0.06"/>
        <stop offset="100%" stop-color="${c3}" stop-opacity="0.14"/>
      </linearGradient>

      <linearGradient id="m3v_tf1" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c1}" stop-opacity="0.75"/>
        <stop offset="100%" stop-color="${c1}" stop-opacity="1"/>
      </linearGradient>
      <linearGradient id="m3v_tf2" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c2}" stop-opacity="0.75"/>
        <stop offset="100%" stop-color="${c2}" stop-opacity="1"/>
      </linearGradient>
      <linearGradient id="m3v_tf3" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${c3}" stop-opacity="0.75"/>
        <stop offset="100%" stop-color="${c3}" stop-opacity="1"/>
      </linearGradient>
    </defs>

    <!-- Slide Canvas Background -->
    <rect width="1000" height="560" fill="#FFFFFF" rx="12"/>

    <!-- Badge -->
    <rect x="${g.badgeX}" y="${g.badgeY}" width="${g.badgeW}" height="${g.badgeH}" rx="6" fill="#DBEAFE"/>
    <g transform="translate(${g.badgeX + 11}, ${g.badgeY + 5})">
      <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>
      <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>
      <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>
    </g>
    <text x="${g.badgeX + 32}" y="${g.badgeY + 16}" fill="#2563EB" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" letter-spacing="0.8px">${badgeText}</text>

    <!-- Heading -->
    <text x="${g.headingX}" y="94" fill="#0F172A" font-size="30" font-weight="800" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${headingText}</text>

    <!-- Supporting Narrative -->
    <text x="${g.bodyX}" y="122" fill="#64748B" font-size="13" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${bodyText}</text>

    <!-- ================= ROW 1 (Blue) ================= -->
    ${card1Bg}
    <!-- Icon Box -->
    <rect x="${g.rowX + g.iconBgX}" y="${g.row1Y + g.iconBgY}" width="${g.iconBgSize}" height="${g.iconBgSize}" rx="16" fill="${c1}" fill-opacity="0.14" stroke="${c1}" stroke-width="1" stroke-opacity="0.25"/>
    <g transform="translate(${g.rowX + g.iconBgX + 16}, ${g.row1Y + g.iconBgY + 16})">
      <polygon points="14 2 17.5 9.5 25 10.5 19.5 16 21 23.5 14 19.8 7 23.5 8.5 16 3 10.5 10.5 9.5 14 2" fill="none" stroke="${c1}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <!-- Value -->
    <text x="${g.rowX + g.valX}" y="${g.row1Y + 70}" fill="#0F172A" font-size="44" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v1}</text>
    <!-- Trend Chip -->
    <rect x="${g.rowX + g.trendX}" y="${g.row1Y + g.trendY}" width="${g.trendW}" height="${g.trendH}" rx="6" fill="${c1}" fill-opacity="0.12" stroke="${c1}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.rowX + g.trendX + g.trendW / 2}" y="${g.row1Y + g.trendY + 16}" text-anchor="middle" fill="${c1}" font-size="11" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t1}</text>
    <!-- Label -->
    <text x="${g.rowX + g.labelX}" y="${g.row1Y + 76}" fill="#1E293B" font-size="16.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l1}</text>
    <!-- Desc -->
    <text x="${g.rowX + g.descX}" y="${g.row1Y + 98}" fill="#64748B" font-size="12" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d1}</text>
    <!-- Status Pill -->
    <rect x="${g.rowX + g.statusPillX}" y="${g.row1Y + g.statusPillY}" width="${g.statusPillW}" height="${g.statusPillH}" rx="6" fill="${c1}" fill-opacity="0.1" stroke="${c1}" stroke-width="0.8" stroke-opacity="0.3"/>
    <text x="${g.rowX + g.statusPillX + g.statusPillW / 2}" y="${g.row1Y + g.statusPillY + 16}" text-anchor="middle" fill="${c1}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${s1}</text>
    <!-- Progress Track & Fill -->
    <rect x="${g.rowX + g.trackX}" y="${g.row1Y + g.trackY}" width="${g.trackW}" height="${g.trackH}" rx="4" fill="${M3V_COLORS.trackBg}"/>
    <rect x="${g.rowX + g.trackX}" y="${g.row1Y + g.trackY}" width="${Math.round(g.trackW * 0.98)}" height="${g.trackH}" rx="4" fill="url(#m3v_tf1)"/>

    <!-- ================= ROW 2 (Purple) ================= -->
    ${card2Bg}
    <!-- Icon Box -->
    <rect x="${g.rowX + g.iconBgX}" y="${g.row2Y + g.iconBgY}" width="${g.iconBgSize}" height="${g.iconBgSize}" rx="16" fill="${c2}" fill-opacity="0.14" stroke="${c2}" stroke-width="1" stroke-opacity="0.25"/>
    <g transform="translate(${g.rowX + g.iconBgX + 16}, ${g.row2Y + g.iconBgY + 16})">
      <polyline points="24 6 14.5 15.5 9.5 10.5 2 18" fill="none" stroke="${c2}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
      <polyline points="18 6 24 6 24 12" fill="none" stroke="${c2}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <!-- Value -->
    <text x="${g.rowX + g.valX}" y="${g.row2Y + 70}" fill="#0F172A" font-size="44" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v2}</text>
    <!-- Trend Chip -->
    <rect x="${g.rowX + g.trendX}" y="${g.row2Y + g.trendY}" width="${g.trendW}" height="${g.trendH}" rx="6" fill="${c2}" fill-opacity="0.12" stroke="${c2}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.rowX + g.trendX + g.trendW / 2}" y="${g.row2Y + g.trendY + 16}" text-anchor="middle" fill="${c2}" font-size="11" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t2}</text>
    <!-- Label -->
    <text x="${g.rowX + g.labelX}" y="${g.row2Y + 76}" fill="#1E293B" font-size="16.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l2}</text>
    <!-- Desc -->
    <text x="${g.rowX + g.descX}" y="${g.row2Y + 98}" fill="#64748B" font-size="12" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d2}</text>
    <!-- Status Pill -->
    <rect x="${g.rowX + g.statusPillX}" y="${g.row2Y + g.statusPillY}" width="${g.statusPillW}" height="${g.statusPillH}" rx="6" fill="${c2}" fill-opacity="0.1" stroke="${c2}" stroke-width="0.8" stroke-opacity="0.3"/>
    <text x="${g.rowX + g.statusPillX + g.statusPillW / 2}" y="${g.row2Y + g.statusPillY + 16}" text-anchor="middle" fill="${c2}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${s2}</text>
    <!-- Progress Track & Fill -->
    <rect x="${g.rowX + g.trackX}" y="${g.row2Y + g.trackY}" width="${g.trackW}" height="${g.trackH}" rx="4" fill="${M3V_COLORS.trackBg}"/>
    <rect x="${g.rowX + g.trackX}" y="${g.row2Y + g.trackY}" width="${Math.round(g.trackW * 0.84)}" height="${g.trackH}" rx="4" fill="url(#m3v_tf2)"/>

    <!-- ================= ROW 3 (Green) ================= -->
    ${card3Bg}
    <!-- Icon Box -->
    <rect x="${g.rowX + g.iconBgX}" y="${g.row3Y + g.iconBgY}" width="${g.iconBgSize}" height="${g.iconBgSize}" rx="16" fill="${c3}" fill-opacity="0.14" stroke="${c3}" stroke-width="1" stroke-opacity="0.25"/>
    <g transform="translate(${g.rowX + g.iconBgX + 16}, ${g.row3Y + g.iconBgY + 16})">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" fill="none" stroke="${c3}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <circle cx="9" cy="7" r="4" fill="none" stroke="${c3}" stroke-width="2"/>
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" fill="none" stroke="${c3}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M16 3.13a4 4 0 0 1 0 7.75" fill="none" stroke="${c3}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    </g>
    <!-- Value -->
    <text x="${g.rowX + g.valX}" y="${g.row3Y + 70}" fill="#0F172A" font-size="44" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${v3}</text>
    <!-- Trend Chip -->
    <rect x="${g.rowX + g.trendX}" y="${g.row3Y + g.trendY}" width="${g.trendW}" height="${g.trendH}" rx="6" fill="${c3}" fill-opacity="0.12" stroke="${c3}" stroke-width="0.8" stroke-opacity="0.25"/>
    <text x="${g.rowX + g.trendX + g.trendW / 2}" y="${g.row3Y + g.trendY + 16}" text-anchor="middle" fill="${c3}" font-size="11" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${t3}</text>
    <!-- Label -->
    <text x="${g.rowX + g.labelX}" y="${g.row3Y + 76}" fill="#1E293B" font-size="16.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${l3}</text>
    <!-- Desc -->
    <text x="${g.rowX + g.descX}" y="${g.row3Y + 98}" fill="#64748B" font-size="12" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${d3}</text>
    <!-- Status Pill -->
    <rect x="${g.rowX + g.statusPillX}" y="${g.row3Y + g.statusPillY}" width="${g.statusPillW}" height="${g.statusPillH}" rx="6" fill="${c3}" fill-opacity="0.1" stroke="${c3}" stroke-width="0.8" stroke-opacity="0.3"/>
    <text x="${g.rowX + g.statusPillX + g.statusPillW / 2}" y="${g.row3Y + g.statusPillY + 16}" text-anchor="middle" fill="${c3}" font-size="10.5" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">${s3}</text>
    <!-- Progress Track & Fill -->
    <rect x="${g.rowX + g.trackX}" y="${g.row3Y + g.trackY}" width="${g.trackW}" height="${g.trackH}" rx="4" fill="${M3V_COLORS.trackBg}"/>
    <rect x="${g.rowX + g.trackX}" y="${g.row3Y + g.trackY}" width="${Math.round(g.trackW * 0.92)}" height="${g.trackH}" rx="4" fill="url(#m3v_tf3)"/>
  </svg>`;
}

function metricThreeVerticalCardsPreviewSvg(previewHints = {}, theme = {}) {
  return metricThreeVerticalPreviewSvg(previewHints, theme, true);
}

module.exports = {
  isMetricThreeVerticalLayout,
  isMetricThreeVerticalCardsLayout,
  isMetricThreeVerticalTextSlot,
  layoutMetricThreeVertical,
  layoutMetricThreeVerticalCards,
  metricThreeVerticalPreviewSvg,
  metricThreeVerticalCardsPreviewSvg,
};
