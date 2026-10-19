/**
 * Metric two split — Two metrics on left, context panel on right.
 * Dual elevated container card architecture.
 * Layout id: metric_two_split_v1.
 */

var MTS_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Left side - Hero Card Container
  leftCardX: 40,
  leftCardY: 40,
  leftCardW: 510,
  leftCardH: 480,

  // Left Category Badge
  leftBadgeX: 68,
  leftBadgeY: 66,
  leftBadgeW: 130,
  leftBadgeH: 26,
  leftBadgeIconSize: 14,

  // Left Heading
  leftHeadingX: 68,
  leftHeadingY: 102,
  leftHeadingW: 454,
  leftHeadingH: 38,

  // Left Subheading
  leftSubheadingX: 68,
  leftSubheadingY: 144,
  leftSubheadingW: 454,
  leftSubheadingH: 24,

  // Inside Left Card: Two Metric Sub-Cards
  subCardY: 180,
  subCardW: 216,
  subCardH: 316,
  subCard1X: 68,
  subCard2X: 306,

  // Relative to each sub-card
  subIconX: 16,
  subIconY: 16,
  subIconBgSize: 40,
  subIconSize: 20,

  subTrendBadgeX: 120,
  subTrendBadgeY: 18,
  subTrendBadgeW: 80,
  subTrendBadgeH: 28,
  subTrendArrowX: 128,
  subTrendArrowY: 25,
  subTrendX: 144,
  subTrendY: 18,
  subTrendW: 52,
  subTrendH: 28,

  subMetricX: 16,
  subMetricY: 68,
  subMetricW: 184,
  subMetricH: 50,

  subLabelX: 16,
  subLabelY: 122,
  subLabelW: 184,
  subLabelH: 24,

  subBarX: 16,
  subBarY: 154,
  subBarW: 184,
  subBarH: 6,

  subCompareX: 16,
  subCompareY: 168,
  subCompareW: 184,
  subCompareH: 22,

  subDescX: 16,
  subDescY: 196,
  subDescW: 184,
  subDescH: 106,

  // Right side - Context Panel Card Container
  panelX: 570,
  panelY: 40,
  panelW: 390,
  panelH: 480,

  panelIconX: 598,
  panelIconY: 66,
  panelIconSize: 22,
  panelIconBgSize: 44,

  panelHeadingX: 654,
  panelHeadingY: 66,
  panelHeadingW: 278,
  panelHeadingH: 44,

  panelDescX: 598,
  panelDescY: 120,
  panelDescW: 334,
  panelDescH: 48,
  panelDividerY: 180,

  // Context breakdown items
  itemIconX: 598,
  itemIconSize: 20,
  itemIconBgSize: 38,

  item1Y: 198,
  itemHeading1Y: 198,
  itemHeadingW: 284,
  itemHeadingH: 24,
  itemDesc1Y: 226,
  itemDescW: 284,
  itemDescH: 92,

  item2Y: 336,
  itemHeading2Y: 336,
  itemDesc2Y: 364,
}

var MTS_COLORS = {
  primary: '#2563EB',
  card1: '#2563EB',
  card1Bg: '#EFF6FF',
  card1Border: '#DBEAFE',
  card1GradEnd: '#1D4ED8',

  card2: '#7C3AED',
  card2Bg: '#F5F3FF',
  card2Border: '#DDD6FE',
  card2GradEnd: '#6D28D9',

  badge: '#EFF6FF',
  badgeBorder: '#DBEAFE',
  badgeText: '#2563EB',

  trend: '#059669',
  trendBg: '#ECFDF5',
  trendBorder: '#A7F3D0',

  cardBg: '#FFFFFF',
  cardBorder: '#E2E8F0',
  subCardBg: '#FFFFFF',
  subCardBorder: '#E2E8F0',
  panelBg: '#FFFFFF',
  panelBorder: '#E2E8F0',
  trackBg: '#F1F5F9',

  textHero: '#0F172A',
  textSubheading: '#64748B',
  textLabel: '#1E293B',
  textDesc: '#64748B',
  textPanelHeading: '#0F172A',
}

var MTS_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Customer performance',
  SUBHEADING: 'Key indicators that reflect customer satisfaction and business engagement.',

  METRIC1_VALUE: '98%',
  METRIC1_LABEL: 'Customer satisfaction',
  METRIC1_TREND: '+12%',
  METRIC1_COMPARE: 'vs. last quarter',
  METRIC1_DESC: 'Consistent service delivery and positive feedback across all client touchpoints.',

  METRIC2_VALUE: '3.2x',
  METRIC2_LABEL: 'Average ROI',
  METRIC2_TREND: '+24%',
  METRIC2_COMPARE: 'vs. last quarter',
  METRIC2_DESC: 'Efficiency gains and measurable cost reductions delivered across strategic initiatives.',

  PANEL_HEADING: 'Context',
  PANEL_DESC: 'Detailed analysis and trend performance across both core metric categories.',

  ITEM1_HEADING: 'Customer satisfaction',
  ITEM1_DESC: 'Customer satisfaction remains strong, reflecting consistent service delivery and positive feedback across key touchpoints. This highlights continued trust and loyalty.',

  ITEM2_HEADING: 'Average ROI',
  ITEM2_DESC: 'The average ROI shows steady growth, indicating improved operational efficiency and higher value delivery from our strategic technology investments.',
}

function isMetricTwoSplitLayout(layoutId) {
  return /metric_two_split_v1$/i.test(String(layoutId || ''))
}

function isMetricTwoSplitTextSlot(slotId) {
  var sid = String(slotId || '').toUpperCase()
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'TITLE'
    || sid === 'SUBHEADING'
    || sid === 'SUBTITLE'
    || sid === 'METRIC1_VALUE'
    || sid === 'STAT_1_VALUE'
    || sid === 'STAT_VALUE'
    || sid === 'METRIC1_LABEL'
    || sid === 'STAT_1_LABEL'
    || sid === 'STAT_LABEL'
    || sid === 'METRIC1_DESC'
    || sid === 'STAT_1_DESC'
    || sid === 'METRIC1_TREND'
    || sid === 'STAT_1_TREND'
    || sid === 'METRIC1_COMPARE'
    || sid === 'METRIC2_VALUE'
    || sid === 'STAT_2_VALUE'
    || sid === 'METRIC2_LABEL'
    || sid === 'STAT_2_LABEL'
    || sid === 'METRIC2_DESC'
    || sid === 'STAT_2_DESC'
    || sid === 'METRIC2_TREND'
    || sid === 'STAT_2_TREND'
    || sid === 'METRIC2_COMPARE'
    || sid === 'PANEL_HEADING'
    || sid === 'PANEL_DESC'
    || sid === 'ITEM1_HEADING'
    || sid === 'ITEM1_LABEL'
    || sid === 'ITEM1_DESC'
    || sid === 'ITEM1_VALUE'
    || sid === 'ITEM2_HEADING'
    || sid === 'ITEM2_LABEL'
    || sid === 'ITEM2_DESC'
    || sid === 'ITEM2_VALUE'
}

function parseMetricRatio(text, defaultRatio) {
  if (defaultRatio === undefined) defaultRatio = 0.8
  if (!text || typeof text !== 'string') return defaultRatio
  var pct = text.match(/([\d.]+)\s*%/i)
  if (pct) {
    var val = parseFloat(pct[1])
    if (!isNaN(val)) return Math.min(1, Math.max(0.08, val / 100))
  }
  var mult = text.match(/([\d.]+)\s*x/i)
  if (mult) {
    var mval = parseFloat(mult[1])
    if (!isNaN(mval)) return Math.min(1, Math.max(0.12, mval / 4))
  }
  var frac = text.match(/(\d+)\s*\/\s*(\d+)/)
  if (frac) {
    var num = parseFloat(frac[1])
    var den = parseFloat(frac[2])
    if (den > 0) return Math.min(1, Math.max(0.08, num / den))
  }
  return defaultRatio
}

function leftCardSvg() {
  var g = MTS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.leftCardW + ' ' + g.leftCardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
      '<filter id="mtsLeftShadow" x="-5%" y="-5%" width="110%" height="115%">' +
        '<feDropShadow dx="0" dy="10" stdDeviation="18" flood-color="#0F172A" flood-opacity="0.06"/>' +
        '<feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0F172A" flood-opacity="0.04"/>' +
      '</filter>' +
      '<linearGradient id="mtsLeftBg" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="#FFFFFF"/>' +
        '<stop offset="100%" stop-color="#F8FAFC"/>' +
      '</linearGradient>' +
    '</defs>' +
    '<rect x="1" y="1" width="' + (g.leftCardW - 2) + '" height="' + (g.leftCardH - 2) + '" rx="20" ry="20" fill="url(#mtsLeftBg)" stroke="' + MTS_COLORS.cardBorder + '" stroke-width="1.5" filter="url(#mtsLeftShadow)"/>' +
  '</svg>'
}

function subCardSvg() {
  var g = MTS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.subCardW + ' ' + g.subCardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0.5" y="0.5" width="' + (g.subCardW - 1) + '" height="' + (g.subCardH - 1) + '" rx="16" fill="#FFFFFF" stroke="' + MTS_COLORS.subCardBorder + '" stroke-width="1.2"/>' +
  '</svg>'
}

function badgeSvg() {
  var g = MTS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.leftBadgeW + ' ' + g.leftBadgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0.5" y="0.5" width="' + (g.leftBadgeW - 1) + '" height="' + (g.leftBadgeH - 1) + '" rx="13" fill="' + MTS_COLORS.badge + '" stroke="' + MTS_COLORS.badgeBorder + '" stroke-width="1.2"/>' +
  '</svg>'
}

function badgeIconSvg() {
  var size = MTS_GEOM.leftBadgeIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="1" y="5" width="2.5" height="7" rx="0.5" fill="' + MTS_COLORS.badgeText + '"/>' +
    '<rect x="5.5" y="2" width="2.5" height="10" rx="0.5" fill="' + MTS_COLORS.badgeText + '"/>' +
    '<rect x="10" y="6" width="2.5" height="6" rx="0.5" fill="' + MTS_COLORS.badgeText + '"/>' +
  '</svg>'
}

function iconBgSvg(bg, border, size) {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0.5" y="0.5" width="' + (size - 1) + '" height="' + (size - 1) + '" fill="' + bg + '" stroke="' + border + '" stroke-width="1.2" rx="10"/>' +
  '</svg>'
}

function icon1Svg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M10 2L12.5 7L18 7.8L14 11.7L15 17.2L10 14.6L5 17.2L6 11.7L2 7.8L7.5 7L10 2Z" fill="none" stroke="' + MTS_COLORS.card1 + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function icon2Svg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M18 5L10.5 12.5L6.5 8.5L2 13" fill="none" stroke="' + MTS_COLORS.card2 + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<path d="M13 5H18V10" fill="none" stroke="' + MTS_COLORS.card2 + '" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function trendBadgeSvg() {
  var g = MTS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.subTrendBadgeW + ' ' + g.subTrendBadgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0.5" y="0.5" width="' + (g.subTrendBadgeW - 1) + '" height="' + (g.subTrendBadgeH - 1) + '" rx="14" fill="' + MTS_COLORS.trendBg + '" stroke="' + MTS_COLORS.trendBorder + '" stroke-width="1.2"/>' +
  '</svg>'
}

function trendArrowSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14" width="14" height="14">' +
    '<path d="M2.5 11.5L11.5 2.5M11.5 2.5H5.5M11.5 2.5V8.5" fill="none" stroke="' + MTS_COLORS.trend + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function progressBarSvg(ratio, color, gradEnd) {
  var g = MTS_GEOM
  var fillW = Math.max(12, Math.round(g.subBarW * Math.min(1, Math.max(0.05, ratio))))
  var gradId = 'mtsBarGrad-' + color.replace('#', '')
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.subBarW + ' ' + g.subBarH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
      '<linearGradient id="' + gradId + '" x1="0%" y1="0%" x2="100%" y2="0%">' +
        '<stop offset="0%" stop-color="' + color + '" />' +
        '<stop offset="100%" stop-color="' + gradEnd + '" />' +
      '</linearGradient>' +
    '</defs>' +
    '<rect x="0" y="0" width="' + g.subBarW + '" height="' + g.subBarH + '" rx="3" fill="' + MTS_COLORS.trackBg + '"/>' +
    '<rect x="0" y="0" width="' + fillW + '" height="' + g.subBarH + '" rx="3" fill="url(#' + gradId + ')"/>' +
  '</svg>'
}

function panelBgSvg() {
  var g = MTS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.panelW + ' ' + g.panelH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
      '<filter id="mtsPanelShadow" x="-5%" y="-5%" width="110%" height="115%">' +
        '<feDropShadow dx="0" dy="10" stdDeviation="18" flood-color="#0F172A" flood-opacity="0.06"/>' +
        '<feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0F172A" flood-opacity="0.04"/>' +
      '</filter>' +
      '<linearGradient id="mtsPanelBg" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="#FFFFFF"/>' +
        '<stop offset="100%" stop-color="#F8FAFC"/>' +
      '</linearGradient>' +
    '</defs>' +
    '<rect x="1" y="1" width="' + (g.panelW - 2) + '" height="' + (g.panelH - 2) + '" rx="20" ry="20" fill="url(#mtsPanelBg)" stroke="' + MTS_COLORS.panelBorder + '" stroke-width="1.5" filter="url(#mtsPanelShadow)"/>' +
    '<line x1="28" y1="' + g.panelDividerY + '" x2="' + (g.panelW - 28) + '" y2="' + g.panelDividerY + '" stroke="#F1F5F9" stroke-width="1.2"/>' +
  '</svg>'
}

function panelIconSvg() {
  var size = MTS_GEOM.panelIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="3" y="2" width="16" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/>' +
    '<line x1="7" y1="7" x2="15" y2="7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
    '<line x1="7" y1="11" x2="15" y2="11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
    '<line x1="7" y1="15" x2="12" y2="15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
  '</svg>'
}

function item1IconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="3" y="4" width="14" height="13" rx="2" fill="none" stroke="#2563EB" stroke-width="1.6"/>' +
    '<line x1="3" y1="8" x2="17" y2="8" stroke="#2563EB" stroke-width="1.5"/>' +
  '</svg>'
}

function item2IconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M4 14L8 9L11 12L16 6" fill="none" stroke="#7C3AED" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function hexLum(hex) {
  var s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  var r = parseInt(s.slice(0, 2), 16) / 255
  var g = parseInt(s.slice(2, 4), 16) / 255
  var b = parseInt(s.slice(4, 6), 16) / 255
  var lin = function(c) { return (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)) }
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette) {
  palette = palette || {}
  var bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#0F172A'
}

function metricTwoSplitChromeSpecs(metric1Text, metric2Text) {
  if (metric1Text === undefined) metric1Text = '98%'
  if (metric2Text === undefined) metric2Text = '3.2x'
  var g = MTS_GEOM
  var specs = []

  // Left elevated container card
  specs.push({
    slotId: 'MTS_LEFT_CARD',
    x: g.leftCardX,
    y: g.leftCardY,
    w: g.leftCardW,
    h: g.leftCardH,
    color: MTS_COLORS.cardBg,
    layer: 2,
    kind: 'leftCard',
  })

  // Left Badge
  specs.push({
    slotId: 'MTS_BADGE_BG',
    x: g.leftBadgeX,
    y: g.leftBadgeY,
    w: g.leftBadgeW,
    h: g.leftBadgeH,
    color: MTS_COLORS.badge,
    layer: 4,
    kind: 'badge',
  })

  specs.push({
    slotId: 'MTS_BADGE_ICON',
    x: g.leftBadgeX + 10,
    y: g.leftBadgeY + 6,
    w: g.leftBadgeIconSize,
    h: g.leftBadgeIconSize,
    color: MTS_COLORS.badgeText,
    layer: 10,
    kind: 'badgeIcon',
  })

  // Two Metric Sub-Cards inside Left Card
  var subCards = [
    {
      id: 1,
      x: g.subCard1X,
      color: MTS_COLORS.card1,
      bg: MTS_COLORS.card1Bg,
      border: MTS_COLORS.card1Border,
      gradEnd: MTS_COLORS.card1GradEnd,
      ratio: parseMetricRatio(metric1Text, 0.98),
    },
    {
      id: 2,
      x: g.subCard2X,
      color: MTS_COLORS.card2,
      bg: MTS_COLORS.card2Bg,
      border: MTS_COLORS.card2Border,
      gradEnd: MTS_COLORS.card2GradEnd,
      ratio: parseMetricRatio(metric2Text, 0.8),
    },
  ]

  subCards.forEach(function(c) {
    // Sub-card background
    specs.push({
      slotId: 'MTS_SUBCARD' + c.id + '_BG',
      x: c.x,
      y: g.subCardY,
      w: g.subCardW,
      h: g.subCardH,
      color: MTS_COLORS.subCardBg,
      layer: 4,
      kind: 'subCard',
    })

    // Sub-card Icon
    specs.push({
      slotId: 'MTS_METRIC' + c.id + '_ICON_BG',
      x: c.x + g.subIconX,
      y: g.subCardY + g.subIconY,
      w: g.subIconBgSize,
      h: g.subIconBgSize,
      color: c.bg,
      layer: 5,
      kind: 'subIconBg' + c.id,
      meta: { bg: c.bg, border: c.border, size: g.subIconBgSize },
    })

    specs.push({
      slotId: 'MTS_METRIC' + c.id + '_ICON',
      x: c.x + g.subIconX + (g.subIconBgSize - g.subIconSize) / 2,
      y: g.subCardY + g.subIconY + (g.subIconBgSize - g.subIconSize) / 2,
      w: g.subIconSize,
      h: g.subIconSize,
      color: c.color,
      layer: 10,
      kind: 'icon' + c.id,
    })

    // Trend Pill Badge
    specs.push({
      slotId: 'MTS_METRIC' + c.id + '_TREND_BG',
      x: c.x + g.subTrendBadgeX,
      y: g.subCardY + g.subTrendBadgeY,
      w: g.subTrendBadgeW,
      h: g.subTrendBadgeH,
      color: MTS_COLORS.trendBg,
      layer: 6,
      kind: 'trendBadge',
    })

    // Trend Arrow
    specs.push({
      slotId: 'MTS_METRIC' + c.id + '_TREND_ARROW',
      x: c.x + g.subTrendArrowX,
      y: g.subCardY + g.subTrendArrowY,
      w: 14,
      h: 14,
      color: MTS_COLORS.trend,
      layer: 10,
      kind: 'trendArrow',
    })

    // Dynamic Progress Bar
    specs.push({
      slotId: 'MTS_METRIC' + c.id + '_BAR',
      x: c.x + g.subBarX,
      y: g.subCardY + g.subBarY,
      w: g.subBarW,
      h: g.subBarH,
      color: c.color,
      layer: 6,
      kind: 'bar' + c.id,
      meta: { ratio: c.ratio, color: c.color, gradEnd: c.gradEnd },
    })
  })

  // Right side Context Panel Card
  specs.push({
    slotId: 'MTS_PANEL_BG',
    x: g.panelX,
    y: g.panelY,
    w: g.panelW,
    h: g.panelH,
    color: MTS_COLORS.panelBg,
    layer: 2,
    kind: 'panelBg',
  })

  specs.push({
    slotId: 'MTS_PANEL_ICON_BG',
    x: g.panelIconX,
    y: g.panelIconY,
    w: g.panelIconBgSize,
    h: g.panelIconBgSize,
    color: MTS_COLORS.badge,
    layer: 4,
    kind: 'panelIconBg',
    meta: { bg: MTS_COLORS.badge, border: MTS_COLORS.badgeBorder, size: g.panelIconBgSize },
  })

  specs.push({
    slotId: 'MTS_PANEL_ICON',
    x: g.panelIconX + (g.panelIconBgSize - g.panelIconSize) / 2,
    y: g.panelIconY + (g.panelIconBgSize - g.panelIconSize) / 2,
    w: g.panelIconSize,
    h: g.panelIconSize,
    color: MTS_COLORS.primary,
    layer: 10,
    kind: 'panelIcon',
  })

  // Context item icon badges
  specs.push({
    slotId: 'MTS_ITEM1_ICON_BG',
    x: g.itemIconX,
    y: g.item1Y,
    w: g.itemIconBgSize,
    h: g.itemIconBgSize,
    color: MTS_COLORS.card1Bg,
    layer: 4,
    kind: 'item1IconBg',
    meta: { bg: MTS_COLORS.card1Bg, border: MTS_COLORS.card1Border, size: g.itemIconBgSize },
  })
  specs.push({
    slotId: 'MTS_ITEM1_ICON',
    x: g.itemIconX + (g.itemIconBgSize - g.itemIconSize) / 2,
    y: g.item1Y + (g.itemIconBgSize - g.itemIconSize) / 2,
    w: g.itemIconSize,
    h: g.itemIconSize,
    color: MTS_COLORS.card1,
    layer: 10,
    kind: 'item1Icon',
  })

  specs.push({
    slotId: 'MTS_ITEM2_ICON_BG',
    x: g.itemIconX,
    y: g.item2Y,
    w: g.itemIconBgSize,
    h: g.itemIconBgSize,
    color: MTS_COLORS.card2Bg,
    layer: 4,
    kind: 'item2IconBg',
    meta: { bg: MTS_COLORS.card2Bg, border: MTS_COLORS.card2Border, size: g.itemIconBgSize },
  })
  specs.push({
    slotId: 'MTS_ITEM2_ICON',
    x: g.itemIconX + (g.itemIconBgSize - g.itemIconSize) / 2,
    y: g.item2Y + (g.itemIconBgSize - g.itemIconSize) / 2,
    w: g.itemIconSize,
    h: g.itemIconSize,
    color: MTS_COLORS.card2,
    layer: 10,
    kind: 'item2Icon',
  })

  return specs
}

function metricTwoSplitOverlay(gx, gy, gw, gh) {
  var g = MTS_GEOM
  var sx = gw / g.viewW
  var sy = gh / g.viewH
  var box = function(x, y, w, h) {
    return {
      x: Math.round(gx + x * sx),
      y: Math.round(gy + y * sy),
      width: Math.max(12, Math.round(w * sx)),
      height: Math.max(10, Math.round(h * sy)),
    }
  }

  var subXs = [g.subCard1X, g.subCard2X]

  var overlays = {
    badge: box(g.leftBadgeX + g.leftBadgeIconSize + 12, g.leftBadgeY, g.leftBadgeW - g.leftBadgeIconSize - 16, g.leftBadgeH),
    heading: box(g.leftHeadingX, g.leftHeadingY, g.leftHeadingW, g.leftHeadingH),
    subheading: box(g.leftSubheadingX, g.leftSubheadingY, g.leftSubheadingW, g.leftSubheadingH),

    panelHeading: box(g.panelHeadingX, g.panelHeadingY, g.panelHeadingW, g.panelHeadingH),
    panelDesc: box(g.panelDescX, g.panelDescY, g.panelDescW, g.panelDescH),

    item1Heading: box(g.panelIconX + g.itemIconBgSize + 12, g.itemHeading1Y, g.itemHeadingW, g.itemHeadingH),
    item1Desc: box(g.panelIconX + g.itemIconBgSize + 12, g.itemDesc1Y, g.itemDescW, g.itemDescH),
    item2Heading: box(g.panelIconX + g.itemIconBgSize + 12, g.itemHeading2Y, g.itemHeadingW, g.itemHeadingH),
    item2Desc: box(g.panelIconX + g.itemIconBgSize + 12, g.itemDesc2Y, g.itemDescW, g.itemDescH),
  }

  subXs.forEach(function(cardX, i) {
    var num = i + 1
    overlays['metric' + num + 'Trend'] = box(cardX + g.subTrendX, g.subCardY + g.subTrendY, g.subTrendW, g.subTrendH)
    overlays['metric' + num + 'Value'] = box(cardX + g.subMetricX, g.subCardY + g.subMetricY, g.subMetricW, g.subMetricH)
    overlays['metric' + num + 'Label'] = box(cardX + g.subLabelX, g.subCardY + g.subLabelY, g.subLabelW, g.subLabelH)
    overlays['metric' + num + 'Compare'] = box(cardX + g.subCompareX, g.subCardY + g.subCompareY, g.subCompareW, g.subCompareH)
    overlays['metric' + num + 'Desc'] = box(cardX + g.subDescX, g.subCardY + g.subDescY, g.subDescW, g.subDescH)
  })

  return overlays
}

function specToMetricTwoSplitContent(spec) {
  if (spec.kind === 'leftCard') return { svg: leftCardSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'subCard') return { svg: subCardSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'subIconBg1' || spec.kind === 'subIconBg2' || spec.kind === 'panelIconBg' || spec.kind === 'item1IconBg' || spec.kind === 'item2IconBg') {
    return { svg: iconBgSvg(spec.meta && spec.meta.bg, spec.meta && spec.meta.border, spec.meta && spec.meta.size), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'icon1') return { svg: icon1Svg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon2') return { svg: icon2Svg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'trendBadge') return { svg: trendBadgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'trendArrow') return { svg: trendArrowSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'bar1' || spec.kind === 'bar2') {
    return { svg: progressBarSvg(spec.meta && spec.meta.ratio, spec.meta && spec.meta.color, spec.meta && spec.meta.gradEnd), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'panelBg') return { svg: panelBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIcon') return { svg: panelIconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'item1Icon') return { svg: item1IconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'item2Icon') return { svg: item2IconSvg(), colorMode: 'fixed', fill: spec.color }
  return null
}

function plainTextFromContent(content) {
  content = content || {}
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    var joined = content.runs.map(function(r) { return r.text || '' }).join('')
    if (joined.trim()) return joined
  }
  return ''
}

function filledContent(el, slotId, style) {
  var sid = String(slotId || '')
  var existing = plainTextFromContent(el && el.content)
  var text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (MTS_DEFAULTS[sid] || existing)
  return Object.assign({}, (el && el.content) || {}, style, {
    text: text,
    runs: null,
    listType: null,
    letterSpacing: style.letterSpacing !== undefined ? style.letterSpacing : '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  })
}

function newId(prefix) {
  return prefix + '-' + Math.random().toString(36).slice(2, 9)
}

function layoutMetricTwoSplit(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  var canvasW = canvas.width || 1920
  var canvasH = canvas.height || 1080
  var sx = canvasW / MTS_GEOM.viewW
  var sy = canvasH / MTS_GEOM.viewH
  var overlay = metricTwoSplitOverlay(0, 0, canvasW, canvasH)
  var chromeRe = /^MTS_/i

  var prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })

  var filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isMetricTwoSplitTextSlot(el.slotId)
  })
  var bySlot = new Map()
  filtered.forEach(function(el) {
    bySlot.set(String(el.slotId || '').toUpperCase(), el)
  })

  function resolvePrev(slotKey) {
    switch (slotKey) {
      case 'HEADING':
        return bySlot.get('HEADING') || bySlot.get('TITLE')
      case 'SUBHEADING':
        return bySlot.get('SUBHEADING') || bySlot.get('SUBTITLE')
      case 'METRIC1_VALUE':
        return bySlot.get('METRIC1_VALUE') || bySlot.get('STAT_1_VALUE') || bySlot.get('STAT_VALUE')
      case 'METRIC1_LABEL':
        return bySlot.get('METRIC1_LABEL') || bySlot.get('STAT_1_LABEL') || bySlot.get('STAT_LABEL')
      case 'METRIC1_TREND':
        return bySlot.get('METRIC1_TREND') || bySlot.get('STAT_1_TREND')
      case 'METRIC1_COMPARE':
        return bySlot.get('METRIC1_COMPARE') || bySlot.get('STAT_1_COMPARE')
      case 'METRIC1_DESC':
        return bySlot.get('METRIC1_DESC') || bySlot.get('STAT_1_DESC')
      case 'METRIC2_VALUE':
        return bySlot.get('METRIC2_VALUE') || bySlot.get('STAT_2_VALUE')
      case 'METRIC2_LABEL':
        return bySlot.get('METRIC2_LABEL') || bySlot.get('STAT_2_LABEL')
      case 'METRIC2_TREND':
        return bySlot.get('METRIC2_TREND') || bySlot.get('STAT_2_TREND')
      case 'METRIC2_COMPARE':
        return bySlot.get('METRIC2_COMPARE') || bySlot.get('STAT_2_COMPARE')
      case 'METRIC2_DESC':
        return bySlot.get('METRIC2_DESC') || bySlot.get('STAT_2_DESC')
      case 'ITEM1_HEADING':
        return bySlot.get('ITEM1_HEADING') || bySlot.get('ITEM1_LABEL')
      case 'ITEM1_DESC':
        return bySlot.get('ITEM1_DESC') || bySlot.get('ITEM1_VALUE')
      case 'ITEM2_HEADING':
        return bySlot.get('ITEM2_HEADING') || bySlot.get('ITEM2_LABEL')
      case 'ITEM2_DESC':
        return bySlot.get('ITEM2_DESC') || bySlot.get('ITEM2_VALUE')
      default:
        return bySlot.get(slotKey)
    }
  }

  var m1El = resolvePrev('METRIC1_VALUE')
  var m2El = resolvePrev('METRIC2_VALUE')
  var metric1Text = plainTextFromContent(m1El && m1El.content) || MTS_DEFAULTS.METRIC1_VALUE
  var metric2Text = plainTextFromContent(m2El && m2El.content) || MTS_DEFAULTS.METRIC2_VALUE

  function placeText(slotId, box, style, role) {
    var prev = resolvePrev(slotId)
    return {
      id: (prev && prev.id) || newId('txt-mts'),
      type: 'text',
      slotId: slotId,
      role: (prev && prev.role) || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  var next = [
    placeText('BADGE', overlay.badge, {
      align: 'left', verticalAlign: 'center', fontSize: 10, fontWeight: 700, color: MTS_COLORS.badgeText, clipToSlot: false, lineHeight: 1, letterSpacing: '1px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 26, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: MTS_COLORS.textSubheading, clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'subheading'),

    placeText('PANEL_HEADING', overlay.panelHeading, {
      align: 'left', verticalAlign: 'center', fontSize: 20, fontWeight: 800, color: MTS_COLORS.textPanelHeading, clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('PANEL_DESC', overlay.panelDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: MTS_COLORS.textSubheading, clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'body'),

    placeText('ITEM1_HEADING', overlay.item1Heading, {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 700, color: MTS_COLORS.textHero, clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('ITEM1_DESC', overlay.item1Desc, {
      align: 'left', verticalAlign: 'top', fontSize: 12.5, fontWeight: 400, color: MTS_COLORS.textDesc, clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'body'),

    placeText('ITEM2_HEADING', overlay.item2Heading, {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 700, color: MTS_COLORS.textHero, clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('ITEM2_DESC', overlay.item2Desc, {
      align: 'left', verticalAlign: 'top', fontSize: 12.5, fontWeight: 400, color: MTS_COLORS.textDesc, clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'body'),
  ]

  // Dual Metric Sub-Cards
  for (var i = 1; i <= 2; i++) {
    next.push(
      placeText('METRIC' + i + '_TREND', overlay['metric' + i + 'Trend'], {
        align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 700, color: MTS_COLORS.trend, clipToSlot: false, lineHeight: 1,
      }, 'caption'),
      placeText('METRIC' + i + '_VALUE', overlay['metric' + i + 'Value'], {
        align: 'left', verticalAlign: 'center', fontSize: 44, fontWeight: 900, color: MTS_COLORS.textHero, clipToSlot: true, lineHeight: 1,
      }, 'heading'),
      placeText('METRIC' + i + '_LABEL', overlay['metric' + i + 'Label'], {
        align: 'left', verticalAlign: 'center', fontSize: 14.5, fontWeight: 700, color: MTS_COLORS.textLabel, clipToSlot: true, lineHeight: 1.25,
      }, 'caption'),
      placeText('METRIC' + i + '_COMPARE', overlay['metric' + i + 'Compare'], {
        align: 'left', verticalAlign: 'center', fontSize: 11.5, fontWeight: 500, color: MTS_COLORS.textSubheading, clipToSlot: false, lineHeight: 1,
      }, 'caption'),
      placeText('METRIC' + i + '_DESC', overlay['metric' + i + 'Desc'], {
        align: 'left', verticalAlign: 'top', fontSize: 11.5, fontWeight: 400, color: MTS_COLORS.textDesc, clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
      }, 'body')
    )
  }

  var chrome = metricTwoSplitChromeSpecs(metric1Text, metric2Text).map(function(spec) {
    var prev = prevBySlot.get(spec.slotId.toUpperCase())
    var graphic = specToMetricTwoSplitContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-mts'),
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
    }
  }).filter(Boolean)

  return chrome.concat(next)
}

/**
 * Polished SVG Preview for Metric Two Split thumbnail in slide picker.
 * Uses its own compact 560x340 coordinate system.
 */
function metricTwoSplitPreviewSvg(previewHints, theme) {
  previewHints = previewHints || {}
  theme = theme || {}
  var slots = previewHints.slots || {}

  var badgeText = (slots.BADGE && slots.BADGE.text) || MTS_DEFAULTS.BADGE
  var headingText = (slots.HEADING && slots.HEADING.text) || previewHints.heading || MTS_DEFAULTS.HEADING
  var subheadingText = (slots.SUBHEADING && slots.SUBHEADING.text) || previewHints.subheading || MTS_DEFAULTS.SUBHEADING

  var m1Value = (slots.METRIC1_VALUE && slots.METRIC1_VALUE.text) || (slots.STAT_1_VALUE && slots.STAT_1_VALUE.text) || (previewHints.stats && previewHints.stats[0] && previewHints.stats[0].value) || MTS_DEFAULTS.METRIC1_VALUE
  var m1Label = (slots.METRIC1_LABEL && slots.METRIC1_LABEL.text) || (slots.STAT_1_LABEL && slots.STAT_1_LABEL.text) || (previewHints.stats && previewHints.stats[0] && previewHints.stats[0].label) || MTS_DEFAULTS.METRIC1_LABEL
  var m1Trend = (slots.METRIC1_TREND && slots.METRIC1_TREND.text) || MTS_DEFAULTS.METRIC1_TREND

  var m2Value = (slots.METRIC2_VALUE && slots.METRIC2_VALUE.text) || (slots.STAT_2_VALUE && slots.STAT_2_VALUE.text) || (previewHints.stats && previewHints.stats[1] && previewHints.stats[1].value) || MTS_DEFAULTS.METRIC2_VALUE
  var m2Label = (slots.METRIC2_LABEL && slots.METRIC2_LABEL.text) || (slots.STAT_2_LABEL && slots.STAT_2_LABEL.text) || (previewHints.stats && previewHints.stats[1] && previewHints.stats[1].label) || MTS_DEFAULTS.METRIC2_LABEL
  var m2Trend = (slots.METRIC2_TREND && slots.METRIC2_TREND.text) || MTS_DEFAULTS.METRIC2_TREND

  var panelHeading = (slots.PANEL_HEADING && slots.PANEL_HEADING.text) || MTS_DEFAULTS.PANEL_HEADING
  var panelDesc = (slots.PANEL_DESC && slots.PANEL_DESC.text) || MTS_DEFAULTS.PANEL_DESC
  var item1Heading = (slots.ITEM1_HEADING && slots.ITEM1_HEADING.text) || (slots.ITEM1_LABEL && slots.ITEM1_LABEL.text) || m1Label
  var item1Desc = (slots.ITEM1_DESC && slots.ITEM1_DESC.text) || (slots.ITEM1_VALUE && slots.ITEM1_VALUE.text) || MTS_DEFAULTS.ITEM1_DESC
  var item2Heading = (slots.ITEM2_HEADING && slots.ITEM2_HEADING.text) || (slots.ITEM2_LABEL && slots.ITEM2_LABEL.text) || m2Label
  var item2Desc = (slots.ITEM2_DESC && slots.ITEM2_DESC.text) || (slots.ITEM2_VALUE && slots.ITEM2_VALUE.text) || MTS_DEFAULTS.ITEM2_DESC

  var barTrackW = 88
  var bar1W = Math.max(8, Math.round(barTrackW * parseMetricRatio(m1Value, 0.98)))
  var bar2W = Math.max(8, Math.round(barTrackW * parseMetricRatio(m2Value, 0.8)))

  var LCx = 14, LCy = 14, LCw = 300, LCh = 312
  var SC1x = LCx + 12, SC1y = LCy + 82, SCw = 130, SCh = 210
  var SC2x = LCx + 152, SC2y = LCy + 82
  var RPx = 328, RPy = 14, RPw = 218, RPh = 312
  var iconBgSz = 28
  var tbOx = 66, tbOy = 11, tbW = 58, tbH = 22
  var mBY = 60, lBY = 81, bBY = 96, bH = 4, cBY = 106, dBY = 120

  var c = MTS_COLORS
  var d = MTS_DEFAULTS

  var lines = []
  lines.push('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 560 340" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">')
  lines.push('  <defs>')
  lines.push('    <filter id="mtsThS" x="-8%" y="-8%" width="116%" height="120%"><feDropShadow dx="0" dy="4" stdDeviation="7" flood-color="#0F172A" flood-opacity="0.07"/></filter>')
  lines.push('    <linearGradient id="mtsThLB" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#FFFFFF"/><stop offset="100%" stop-color="#F8FAFC"/></linearGradient>')
  lines.push('    <linearGradient id="mtsThB1" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="' + c.card1 + '"/><stop offset="100%" stop-color="' + c.card1GradEnd + '"/></linearGradient>')
  lines.push('    <linearGradient id="mtsThB2" x1="0%" y1="0%" x2="100%" y2="0%"><stop offset="0%" stop-color="' + c.card2 + '"/><stop offset="100%" stop-color="' + c.card2GradEnd + '"/></linearGradient>')
  lines.push('  </defs>')
  lines.push('  <rect width="560" height="340" fill="#F1F5F9"/>')
  // LEFT CARD
  lines.push('  <rect x="' + LCx + '" y="' + LCy + '" width="' + LCw + '" height="' + LCh + '" rx="14" fill="url(#mtsThLB)" stroke="' + c.cardBorder + '" stroke-width="1" filter="url(#mtsThS)"/>')
  lines.push('  <rect x="' + (LCx+16) + '" y="' + (LCy+16) + '" width="98" height="19" rx="9.5" fill="' + c.badge + '" stroke="' + c.badgeBorder + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (LCx+23) + ',' + (LCy+20) + ')"><rect x="0" y="3" width="1.6" height="4.5" rx="0.4" fill="' + c.badgeText + '"/><rect x="3" y="1" width="1.6" height="6.5" rx="0.4" fill="' + c.badgeText + '"/><rect x="6" y="4" width="1.6" height="3.5" rx="0.4" fill="' + c.badgeText + '"/></g>')
  lines.push('  <text x="' + (LCx+33) + '" y="' + (LCy+29) + '" fill="' + c.badgeText + '" font-size="7" font-weight="700" font-family="system-ui,sans-serif" letter-spacing="0.7px">' + badgeText.slice(0,14) + '</text>')
  lines.push('  <text x="' + (LCx+16) + '" y="' + (LCy+54) + '" fill="#0F172A" font-size="13" font-weight="800" font-family="system-ui,sans-serif">' + headingText.slice(0,30) + '</text>')
  lines.push('  <text x="' + (LCx+16) + '" y="' + (LCy+67) + '" fill="#64748B" font-size="7" font-family="system-ui,sans-serif">' + subheadingText.slice(0,50) + '...</text>')
  // SUB-CARD 1
  lines.push('  <!-- SUB-CARD 1 -->')
  lines.push('  <rect x="' + SC1x + '" y="' + SC1y + '" width="' + SCw + '" height="' + SCh + '" rx="10" fill="#FFFFFF" stroke="' + c.subCardBorder + '" stroke-width="0.8"/>')
  lines.push('  <rect x="' + (SC1x+10) + '" y="' + (SC1y+10) + '" width="' + iconBgSz + '" height="' + iconBgSz + '" rx="7" fill="' + c.card1Bg + '" stroke="' + c.card1Border + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (SC1x+17) + ',' + (SC1y+17) + ')"><path d="M7 1L8.8 5L13 5.6L10 8.4L10.8 12.4L7 10.3L3.2 12.4L4 8.4L1 5.6L5.2 5Z" fill="none" stroke="' + c.card1 + '" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></g>')
  lines.push('  <rect x="' + (SC1x+tbOx) + '" y="' + (SC1y+tbOy) + '" width="' + tbW + '" height="' + tbH + '" rx="11" fill="' + c.trendBg + '" stroke="' + c.trendBorder + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (SC1x+tbOx+5) + ',' + (SC1y+tbOy+4) + ')"><path d="M1.5 8L8 1.5M8 1.5H3.5M8 1.5V6" fill="none" stroke="' + c.trend + '" stroke-width="1.5" stroke-linecap="round"/></g>')
  lines.push('  <text x="' + (SC1x+tbOx+17) + '" y="' + (SC1y+tbOy+14) + '" fill="' + c.trend + '" font-size="8" font-weight="700" font-family="system-ui,sans-serif">' + m1Trend + '</text>')
  lines.push('  <text x="' + (SC1x+10) + '" y="' + (SC1y+mBY) + '" fill="#0F172A" font-size="26" font-weight="900" font-family="system-ui,sans-serif">' + m1Value + '</text>')
  lines.push('  <text x="' + (SC1x+10) + '" y="' + (SC1y+lBY) + '" fill="#1E293B" font-size="8" font-weight="700" font-family="system-ui,sans-serif">' + m1Label.slice(0,16) + '</text>')
  lines.push('  <rect x="' + (SC1x+10) + '" y="' + (SC1y+bBY) + '" width="' + barTrackW + '" height="' + bH + '" rx="2" fill="' + c.trackBg + '"/>')
  lines.push('  <rect x="' + (SC1x+10) + '" y="' + (SC1y+bBY) + '" width="' + bar1W + '" height="' + bH + '" rx="2" fill="url(#mtsThB1)"/>')
  lines.push('  <text x="' + (SC1x+10) + '" y="' + (SC1y+cBY) + '" fill="#64748B" font-size="6.5" font-family="system-ui,sans-serif">vs. last quarter</text>')
  lines.push('  <text x="' + (SC1x+10) + '" y="' + (SC1y+dBY) + '" fill="#94A3B8" font-size="6" font-family="system-ui,sans-serif">' + item1Desc.slice(0,22) + '</text>')
  lines.push('  <text x="' + (SC1x+10) + '" y="' + (SC1y+dBY+10) + '" fill="#94A3B8" font-size="6" font-family="system-ui,sans-serif">' + item1Desc.slice(22,44) + '</text>')
  lines.push('  <text x="' + (SC1x+10) + '" y="' + (SC1y+dBY+20) + '" fill="#94A3B8" font-size="6" font-family="system-ui,sans-serif">' + item1Desc.slice(44,66) + '...</text>')
  // SUB-CARD 2
  lines.push('  <!-- SUB-CARD 2 -->')
  lines.push('  <rect x="' + SC2x + '" y="' + SC2y + '" width="' + SCw + '" height="' + SCh + '" rx="10" fill="#FFFFFF" stroke="' + c.subCardBorder + '" stroke-width="0.8"/>')
  lines.push('  <rect x="' + (SC2x+10) + '" y="' + (SC2y+10) + '" width="' + iconBgSz + '" height="' + iconBgSz + '" rx="7" fill="' + c.card2Bg + '" stroke="' + c.card2Border + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (SC2x+17) + ',' + (SC2y+17) + ')"><path d="M13 3L7.5 8.5L4.5 6L1 9.5" fill="none" stroke="' + c.card2 + '" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 3H13V6" fill="none" stroke="' + c.card2 + '" stroke-width="1.3" stroke-linecap="round"/></g>')
  lines.push('  <rect x="' + (SC2x+tbOx) + '" y="' + (SC2y+tbOy) + '" width="' + tbW + '" height="' + tbH + '" rx="11" fill="' + c.trendBg + '" stroke="' + c.trendBorder + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (SC2x+tbOx+5) + ',' + (SC2y+tbOy+4) + ')"><path d="M1.5 8L8 1.5M8 1.5H3.5M8 1.5V6" fill="none" stroke="' + c.trend + '" stroke-width="1.5" stroke-linecap="round"/></g>')
  lines.push('  <text x="' + (SC2x+tbOx+17) + '" y="' + (SC2y+tbOy+14) + '" fill="' + c.trend + '" font-size="8" font-weight="700" font-family="system-ui,sans-serif">' + m2Trend + '</text>')
  lines.push('  <text x="' + (SC2x+10) + '" y="' + (SC2y+mBY) + '" fill="#0F172A" font-size="26" font-weight="900" font-family="system-ui,sans-serif">' + m2Value + '</text>')
  lines.push('  <text x="' + (SC2x+10) + '" y="' + (SC2y+lBY) + '" fill="#1E293B" font-size="8" font-weight="700" font-family="system-ui,sans-serif">' + m2Label.slice(0,16) + '</text>')
  lines.push('  <rect x="' + (SC2x+10) + '" y="' + (SC2y+bBY) + '" width="' + barTrackW + '" height="' + bH + '" rx="2" fill="' + c.trackBg + '"/>')
  lines.push('  <rect x="' + (SC2x+10) + '" y="' + (SC2y+bBY) + '" width="' + bar2W + '" height="' + bH + '" rx="2" fill="url(#mtsThB2)"/>')
  lines.push('  <text x="' + (SC2x+10) + '" y="' + (SC2y+cBY) + '" fill="#64748B" font-size="6.5" font-family="system-ui,sans-serif">vs. last quarter</text>')
  lines.push('  <text x="' + (SC2x+10) + '" y="' + (SC2y+dBY) + '" fill="#94A3B8" font-size="6" font-family="system-ui,sans-serif">' + item2Desc.slice(0,22) + '</text>')
  lines.push('  <text x="' + (SC2x+10) + '" y="' + (SC2y+dBY+10) + '" fill="#94A3B8" font-size="6" font-family="system-ui,sans-serif">' + item2Desc.slice(22,44) + '</text>')
  lines.push('  <text x="' + (SC2x+10) + '" y="' + (SC2y+dBY+20) + '" fill="#94A3B8" font-size="6" font-family="system-ui,sans-serif">' + item2Desc.slice(44,66) + '...</text>')
  // RIGHT PANEL
  lines.push('  <!-- RIGHT PANEL -->')
  lines.push('  <rect x="' + RPx + '" y="' + RPy + '" width="' + RPw + '" height="' + RPh + '" rx="14" fill="#FFFFFF" stroke="' + c.panelBorder + '" stroke-width="1" filter="url(#mtsThS)"/>')
  lines.push('  <rect x="' + (RPx+14) + '" y="' + (RPy+16) + '" width="29" height="29" rx="8" fill="' + c.badge + '" stroke="' + c.badgeBorder + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (RPx+22) + ',' + (RPy+23) + ')"><rect x="1.5" y="1" width="10" height="12" rx="1.5" fill="none" stroke="' + c.primary + '" stroke-width="1.3"/><line x1="3.5" y1="5" x2="9.5" y2="5" stroke="' + c.primary + '" stroke-width="1.1" stroke-linecap="round"/><line x1="3.5" y1="8" x2="9.5" y2="8" stroke="' + c.primary + '" stroke-width="1.1" stroke-linecap="round"/></g>')
  lines.push('  <text x="' + (RPx+49) + '" y="' + (RPy+29) + '" fill="#0F172A" font-size="12.5" font-weight="800" font-family="system-ui,sans-serif">' + panelHeading.slice(0,16) + '</text>')
  lines.push('  <text x="' + (RPx+14) + '" y="' + (RPy+54) + '" fill="#64748B" font-size="7" font-family="system-ui,sans-serif">' + panelDesc.slice(0,32) + '</text>')
  lines.push('  <text x="' + (RPx+14) + '" y="' + (RPy+63) + '" fill="#64748B" font-size="7" font-family="system-ui,sans-serif">' + panelDesc.slice(32,64) + '...</text>')
  lines.push('  <line x1="' + (RPx+14) + '" y1="' + (RPy+76) + '" x2="' + (RPx+RPw-14) + '" y2="' + (RPy+76) + '" stroke="#F1F5F9" stroke-width="1"/>')
  // Item 1
  lines.push('  <rect x="' + (RPx+14) + '" y="' + (RPy+88) + '" width="25" height="25" rx="7" fill="' + c.card1Bg + '" stroke="' + c.card1Border + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (RPx+21) + ',' + (RPy+95) + ')"><rect x="1.5" y="2.5" width="9" height="8" rx="1.2" fill="none" stroke="#2563EB" stroke-width="1.2"/><line x1="1.5" y1="5.5" x2="10.5" y2="5.5" stroke="#2563EB" stroke-width="1"/></g>')
  lines.push('  <text x="' + (RPx+45) + '" y="' + (RPy+99) + '" fill="#0F172A" font-size="8" font-weight="700" font-family="system-ui,sans-serif">' + item1Heading.slice(0,22) + '</text>')
  lines.push('  <text x="' + (RPx+45) + '" y="' + (RPy+109) + '" fill="#64748B" font-size="6.5" font-family="system-ui,sans-serif">' + item1Desc.slice(0,26) + '</text>')
  lines.push('  <text x="' + (RPx+45) + '" y="' + (RPy+118) + '" fill="#64748B" font-size="6.5" font-family="system-ui,sans-serif">' + item1Desc.slice(26,52) + '...</text>')
  lines.push('  <line x1="' + (RPx+14) + '" y1="' + (RPy+130) + '" x2="' + (RPx+RPw-14) + '" y2="' + (RPy+130) + '" stroke="#F8FAFC" stroke-width="0.8"/>')
  // Item 2
  lines.push('  <rect x="' + (RPx+14) + '" y="' + (RPy+142) + '" width="25" height="25" rx="7" fill="' + c.card2Bg + '" stroke="' + c.card2Border + '" stroke-width="0.7"/>')
  lines.push('  <g transform="translate(' + (RPx+21) + ',' + (RPy+149) + ')"><path d="M1.5 9L4 6L6.5 7.5L10 3" fill="none" stroke="#7C3AED" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></g>')
  lines.push('  <text x="' + (RPx+45) + '" y="' + (RPy+153) + '" fill="#0F172A" font-size="8" font-weight="700" font-family="system-ui,sans-serif">' + item2Heading.slice(0,22) + '</text>')
  lines.push('  <text x="' + (RPx+45) + '" y="' + (RPy+163) + '" fill="#64748B" font-size="6.5" font-family="system-ui,sans-serif">' + item2Desc.slice(0,26) + '</text>')
  lines.push('  <text x="' + (RPx+45) + '" y="' + (RPy+172) + '" fill="#64748B" font-size="6.5" font-family="system-ui,sans-serif">' + item2Desc.slice(26,52) + '...</text>')
  // Summary chips
  lines.push('  <rect x="' + (RPx+14) + '" y="' + (RPy+192) + '" width="' + (RPw-28) + '" height="44" rx="8" fill="#F8FAFC" stroke="#E2E8F0" stroke-width="0.7"/>')
  lines.push('  <text x="' + (RPx+22) + '" y="' + (RPy+207) + '" fill="#94A3B8" font-size="6" font-weight="600" font-family="system-ui,sans-serif" letter-spacing="0.5px">SUMMARY</text>')
  lines.push('  <rect x="' + (RPx+22) + '" y="' + (RPy+212) + '" width="62" height="16" rx="5" fill="' + c.card1Bg + '" stroke="' + c.card1Border + '" stroke-width="0.6"/>')
  lines.push('  <text x="' + (RPx+28) + '" y="' + (RPy+223) + '" fill="' + c.card1 + '" font-size="7.5" font-weight="700" font-family="system-ui,sans-serif">' + m1Value + '  ' + m1Trend + '</text>')
  lines.push('  <rect x="' + (RPx+92) + '" y="' + (RPy+212) + '" width="62" height="16" rx="5" fill="' + c.card2Bg + '" stroke="' + c.card2Border + '" stroke-width="0.6"/>')
  lines.push('  <text x="' + (RPx+98) + '" y="' + (RPy+223) + '" fill="' + c.card2 + '" font-size="7.5" font-weight="700" font-family="system-ui,sans-serif">' + m2Value + '  ' + m2Trend + '</text>')
  lines.push('</svg>')
  return lines.join('\n')
}

module.exports = {
  isMetricTwoSplitLayout: isMetricTwoSplitLayout,
  layoutMetricTwoSplit: layoutMetricTwoSplit,
  metricTwoSplitPreviewSvg: metricTwoSplitPreviewSvg,
  MTS_GEOM: MTS_GEOM,
  MTS_COLORS: MTS_COLORS,
  MTS_DEFAULTS: MTS_DEFAULTS,
}