/**
 * Metric single split — Single metric on left, context panel on right.
 * Dual elevated container card architecture.
 * Layout id: metric_single_split_v1.
 */

var MSS_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Left side - Hero Metric Card Container
  leftCardX: 40,
  leftCardY: 40,
  leftCardW: 510,
  leftCardH: 480,
  
  // Left Badge
  leftBadgeX: 72,
  leftBadgeY: 70,
  leftBadgeW: 120,
  leftBadgeH: 26,
  leftBadgeIconSize: 14,
  
  // Left Heading
  leftHeadingX: 72,
  leftHeadingY: 110,
  leftHeadingW: 446,
  leftHeadingH: 44,
  
  // Left Subheading
  leftSubheadingX: 72,
  leftSubheadingY: 160,
  leftSubheadingW: 446,
  leftSubheadingH: 48,
  
  // Left Metric Value
  leftMetricX: 72,
  leftMetricY: 236,
  leftMetricW: 240,
  leftMetricH: 96,
  
  // Dynamic Progress Circle (right of metric inside left card)
  circleX: 340,
  circleY: 220,
  circleDiameter: 140,
  circleStrokeWidth: 14,
  circleIconSize: 40,
  
  // Left Trend Badge Pill
  leftTrendBadgeX: 72,
  leftTrendBadgeY: 366,
  leftTrendBadgeW: 96,
  leftTrendBadgeH: 34,
  leftTrendArrowX: 82,
  leftTrendArrowY: 376,
  leftTrendX: 102,
  leftTrendY: 366,
  leftTrendW: 60,
  leftTrendH: 34,
  
  // Comparison text next to trend pill
  leftCompareX: 180,
  leftCompareY: 366,
  leftCompareW: 180,
  leftCompareH: 34,
  
  // Right side - Context Panel Card Container
  panelX: 570,
  panelY: 40,
  panelW: 390,
  panelH: 480,
  
  panelIconX: 600,
  panelIconY: 66,
  panelIconSize: 22,
  panelIconBgSize: 44,
  
  panelHeadingX: 656,
  panelHeadingY: 66,
  panelHeadingW: 274,
  panelHeadingH: 44,
  
  panelDescX: 600,
  panelDescY: 122,
  panelDescW: 330,
  panelDescH: 66,
  panelDividerY: 202,
  
  // Context items in panel
  item1Y: 222,
  item2Y: 294,
  item3Y: 366,
  itemIconX: 600,
  itemIconSize: 20,
  itemIconBgSize: 36,
  itemLabelX: 650,
  itemLabelW: 280,
  itemLabelH: 18,
  itemValueX: 650,
  itemValueW: 280,
  itemValueH: 40,
}

var MSS_COLORS = {
  primary: '#2563EB',
  circle: '#2563EB',
  circleGradientEnd: '#1D4ED8',
  circleTrack: '#EEF2F6',
  badge: '#EFF6FF',
  badgeBorder: '#DBEAFE',
  badgeText: '#2563EB',
  trend: '#059669',
  trendBg: '#ECFDF5',
  trendBorder: '#A7F3D0',
  panelBg: '#FFFFFF',
  panelBorder: '#E2E8F0',
  cardBg: '#FFFFFF',
  cardBorder: '#E2E8F0',
  textHero: '#0F172A',
  textSubheading: '#64748B',
  textPanelHeading: '#0F172A',
}

var MSS_DEFAULTS = {
  BADGE: 'KEY METRIC',
  HEADING: 'Customer satisfaction',
  SUBHEADING: "Shows how well we're meeting customer expectations and delivering value.",
  METRIC_VALUE: '98%',
  TREND: '+12%',
  COMPARE: 'vs. last quarter',
  
  PANEL_HEADING: 'Context',
  PANEL_DESC: 'This metric reflects customer feedback and support interactions over the last quarter. It highlights the continued improvement in customer experience and satisfaction levels.',
  
  ITEM1_LABEL: 'Time Period',
  ITEM1_VALUE: 'Q2 - Q4 2025',
  
  ITEM2_LABEL: 'Change',
  ITEM2_VALUE: '+12% vs. last quarter',
  
  ITEM3_LABEL: 'Source',
  ITEM3_VALUE: 'Customer feedback & support tickets',
}

function isMetricSingleSplitLayout(layoutId) {
  return /metric_single_split_v1$/i.test(String(layoutId || ''))
}

function isMetricSingleSplitTextSlot(slotId) {
  var sid = String(slotId || '').toUpperCase()
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'TITLE'
    || sid === 'SUBHEADING'
    || sid === 'SUBTITLE'
    || sid === 'METRIC_VALUE'
    || sid === 'STAT_VALUE'
    || sid === 'TREND'
    || sid === 'COMPARE'
    || sid === 'PANEL_HEADING'
    || sid === 'PANEL_DESC'
    || sid === 'ITEM1_LABEL'
    || sid === 'ITEM1_VALUE'
    || sid === 'ITEM2_LABEL'
    || sid === 'ITEM2_VALUE'
    || sid === 'ITEM3_LABEL'
    || sid === 'ITEM3_VALUE'
}

function parseMetricPercent(text) {
  if (!text || typeof text !== 'string') return 0.75
  var match = text.match(/([\d.]+)\s*%/i)
  if (match) {
    var val = parseFloat(match[1])
    if (!isNaN(val)) return Math.min(1, Math.max(0.04, val / 100))
  }
  var fracMatch = text.match(/(\d+)\s*\/\s*(\d+)/)
  if (fracMatch) {
    var num = parseFloat(fracMatch[1])
    var den = parseFloat(fracMatch[2])
    if (den > 0) return Math.min(1, Math.max(0.04, num / den))
  }
  return 0.75
}

function leftCardSvg() {
  var g = MSS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.leftCardW + ' ' + g.leftCardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
    '<filter id="mssLeftShadow" x="-5%" y="-5%" width="110%" height="115%">' +
    '<feDropShadow dx="0" dy="10" stdDeviation="18" flood-color="#0F172A" flood-opacity="0.06"/>' +
    '<feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0F172A" flood-opacity="0.04"/>' +
    '</filter>' +
    '<linearGradient id="mssLeftBg" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" stop-color="#FFFFFF"/>' +
    '<stop offset="100%" stop-color="#F8FAFC"/>' +
    '</linearGradient>' +
    '</defs>' +
    '<rect x="1" y="1" width="' + (g.leftCardW - 2) + '" height="' + (g.leftCardH - 2) + '" rx="20" ry="20" fill="url(#mssLeftBg)" stroke="' + MSS_COLORS.cardBorder + '" stroke-width="1.5" filter="url(#mssLeftShadow)"/>' +
    '</svg>'
}

function badgeSvg() {
  var g = MSS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.leftBadgeW + ' ' + g.leftBadgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0.5" y="0.5" width="' + (g.leftBadgeW - 1) + '" height="' + (g.leftBadgeH - 1) + '" rx="13" fill="' + MSS_COLORS.badge + '" stroke="' + MSS_COLORS.badgeBorder + '" stroke-width="1.2"/>' +
    '</svg>'
}

function badgeIconSvg() {
  var size = MSS_GEOM.leftBadgeIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="1" y="5" width="2.5" height="7" rx="0.5" fill="' + MSS_COLORS.badgeText + '"/>' +
    '<rect x="5.5" y="2" width="2.5" height="10" rx="0.5" fill="' + MSS_COLORS.badgeText + '"/>' +
    '<rect x="10" y="6" width="2.5" height="6" rx="0.5" fill="' + MSS_COLORS.badgeText + '"/>' +
    '</svg>'
}

function circleSvg(metricText) {
  var g = MSS_GEOM
  var r = (g.circleDiameter - g.circleStrokeWidth) / 2
  var cx = g.circleDiameter / 2
  var cy = g.circleDiameter / 2
  var viewBox = g.circleDiameter
  var circumference = 2 * Math.PI * r
  
  var progressPercent = parseMetricPercent(metricText)
  var strokeDashoffset = circumference * (1 - progressPercent)
  
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + viewBox + ' ' + viewBox + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<defs>' +
    '<linearGradient id="mssCircleGradient" x1="0%" y1="0%" x2="100%" y2="100%">' +
    '<stop offset="0%" stop-color="' + MSS_COLORS.circle + '" />' +
    '<stop offset="100%" stop-color="' + MSS_COLORS.circleGradientEnd + '" />' +
    '</linearGradient>' +
    '<filter id="mssGlow" x="-20%" y="-20%" width="140%" height="140%">' +
    '<feDropShadow dx="0" dy="3" stdDeviation="5" flood-color="' + MSS_COLORS.circle + '" flood-opacity="0.22"/>' +
    '</filter>' +
    '</defs>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + (r + g.circleStrokeWidth / 2 + 4) + '" fill="#F8FAFC" stroke="#EEF2F6" stroke-width="1"/>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + MSS_COLORS.circleTrack + '" stroke-width="' + g.circleStrokeWidth + '"/>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="url(#mssCircleGradient)" stroke-width="' + g.circleStrokeWidth + '" stroke-linecap="round" stroke-dasharray="' + circumference + '" stroke-dashoffset="' + strokeDashoffset + '" transform="rotate(-90 ' + cx + ' ' + cy + ')" filter="url(#mssGlow)"/>' +
    '</svg>'
}

function circleIconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M4 22V17M10 22V11M16 22V14M22 22V6" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<path d="M4 17L10 11L16 14L22 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.4"/>' +
    '</svg>'
}

function trendBadgeSvg() {
  var g = MSS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.leftTrendBadgeW + ' ' + g.leftTrendBadgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0.5" y="0.5" width="' + (g.leftTrendBadgeW - 1) + '" height="' + (g.leftTrendBadgeH - 1) + '" rx="17" fill="' + MSS_COLORS.trendBg + '" stroke="' + MSS_COLORS.trendBorder + '" stroke-width="1.2"/>' +
    '</svg>'
}

function trendArrowSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14" width="14" height="14">' +
    '<path d="M2.5 11.5L11.5 2.5M11.5 2.5H5.5M11.5 2.5V8.5" fill="none" stroke="' + MSS_COLORS.trend + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>'
}

function panelBgSvg() {
  var g = MSS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.panelW + ' ' + g.panelH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
    '<filter id="mssPanelShadow" x="-5%" y="-5%" width="110%" height="115%">' +
    '<feDropShadow dx="0" dy="10" stdDeviation="18" flood-color="#0F172A" flood-opacity="0.06"/>' +
    '<feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0F172A" flood-opacity="0.04"/>' +
    '</filter>' +
    '<linearGradient id="mssPanelBg" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" stop-color="#FFFFFF"/>' +
    '<stop offset="100%" stop-color="#F8FAFC"/>' +
    '</linearGradient>' +
    '</defs>' +
    '<rect x="1" y="1" width="' + (g.panelW - 2) + '" height="' + (g.panelH - 2) + '" rx="20" ry="20" fill="url(#mssPanelBg)" stroke="' + MSS_COLORS.panelBorder + '" stroke-width="1.5" filter="url(#mssPanelShadow)"/>' +
    '<line x1="30" y1="' + g.panelDividerY + '" x2="' + (g.panelW - 30) + '" y2="' + g.panelDividerY + '" stroke="#F1F5F9" stroke-width="1.2"/>' +
    '</svg>'
}

function panelIconBgSvg() {
  var size = MSS_GEOM.panelIconBgSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0.5" y="0.5" width="' + (size - 1) + '" height="' + (size - 1) + '" fill="' + MSS_COLORS.badge + '" stroke="' + MSS_COLORS.badgeBorder + '" stroke-width="1.2" rx="10"/>' +
    '</svg>'
}

function panelIconSvg() {
  var size = MSS_GEOM.panelIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="3" y="2" width="16" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/>' +
    '<line x1="7" y1="7" x2="15" y2="7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
    '<line x1="7" y1="11" x2="15" y2="11" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
    '<line x1="7" y1="15" x2="12" y2="15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>' +
    '</svg>'
}

function itemIconBgSvg(bg, border) {
  var size = MSS_GEOM.itemIconBgSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0.5" y="0.5" width="' + (size - 1) + '" height="' + (size - 1) + '" fill="' + bg + '" stroke="' + border + '" stroke-width="1" rx="9"/>' +
    '</svg>'
}

function item1IconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="3" y="4" width="14" height="13" rx="2" fill="none" stroke="#2563EB" stroke-width="1.6"/>' +
    '<line x1="3" y1="8" x2="17" y2="8" stroke="#2563EB" stroke-width="1.5"/>' +
    '<line x1="7" y1="2" x2="7" y2="5" stroke="#2563EB" stroke-width="1.6" stroke-linecap="round"/>' +
    '<line x1="13" y1="2" x2="13" y2="5" stroke="#2563EB" stroke-width="1.6" stroke-linecap="round"/>' +
    '</svg>'
}

function item2IconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M4 14L8 9L11 12L16 6" fill="none" stroke="#059669" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<path d="M12 6H16V10" fill="none" stroke="#059669" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>'
}

function item3IconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M10 2L16 5V9.5C16 13.5 13.5 16.5 10 18C6.5 16.5 4 13.5 4 9.5V5L10 2Z" fill="none" stroke="#7C3AED" stroke-width="1.6" stroke-linejoin="round"/>' +
    '<path d="M7.5 9.5L9.2 11.2L12.5 7.8" fill="none" stroke="#7C3AED" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>'
}

function hexLum(hex) {
  var s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  var r = parseInt(s.slice(0, 2), 16) / 255
  var g = parseInt(s.slice(2, 4), 16) / 255
  var b = parseInt(s.slice(4, 6), 16) / 255
  var lin = function(c) { return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4) }
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette) {
  palette = palette || {}
  var bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#0F172A'
}

function metricSingleSplitChromeSpecs(metricText) {
  metricText = metricText || '98%'
  var g = MSS_GEOM
  var specs = []
  
  // Left elevated container card
  specs.push({
    slotId: 'MSS_LEFT_CARD',
    x: g.leftCardX,
    y: g.leftCardY,
    w: g.leftCardW,
    h: g.leftCardH,
    color: MSS_COLORS.cardBg,
    layer: 2,
    kind: 'leftCard',
  })
  
  // Badge container
  specs.push({
    slotId: 'MSS_BADGE_BG',
    x: g.leftBadgeX,
    y: g.leftBadgeY,
    w: g.leftBadgeW,
    h: g.leftBadgeH,
    color: MSS_COLORS.badge,
    layer: 4,
    kind: 'badge',
  })
  
  // Badge icon
  specs.push({
    slotId: 'MSS_BADGE_ICON',
    x: g.leftBadgeX + 10,
    y: g.leftBadgeY + 6,
    w: g.leftBadgeIconSize,
    h: g.leftBadgeIconSize,
    color: MSS_COLORS.badgeText,
    layer: 10,
    kind: 'badgeIcon',
  })
  
  // Center Progress Circle
  specs.push({
    slotId: 'MSS_CIRCLE',
    x: g.circleX,
    y: g.circleY,
    w: g.circleDiameter,
    h: g.circleDiameter,
    color: MSS_COLORS.primary,
    layer: 5,
    kind: 'circle',
    meta: { metricText: metricText },
  })
  
  // Center circle icon inside ring
  specs.push({
    slotId: 'MSS_CIRCLE_ICON',
    x: g.circleX + (g.circleDiameter - g.circleIconSize) / 2,
    y: g.circleY + (g.circleDiameter - g.circleIconSize) / 2,
    w: g.circleIconSize,
    h: g.circleIconSize,
    color: MSS_COLORS.primary,
    layer: 8,
    kind: 'circleIcon',
  })
  
  // Trend pill badge
  specs.push({
    slotId: 'MSS_TREND_BG',
    x: g.leftTrendBadgeX,
    y: g.leftTrendBadgeY,
    w: g.leftTrendBadgeW,
    h: g.leftTrendBadgeH,
    color: MSS_COLORS.trendBg,
    layer: 6,
    kind: 'trendBadge',
  })
  
  // Trend arrow
  specs.push({
    slotId: 'MSS_TREND_ARROW',
    x: g.leftTrendArrowX,
    y: g.leftTrendArrowY,
    w: 14,
    h: 14,
    color: MSS_COLORS.trend,
    layer: 10,
    kind: 'trendArrow',
  })
  
  // Right side context panel
  specs.push({
    slotId: 'MSS_PANEL_BG',
    x: g.panelX,
    y: g.panelY,
    w: g.panelW,
    h: g.panelH,
    color: MSS_COLORS.panelBg,
    layer: 2,
    kind: 'panelBg',
  })
  
  specs.push({
    slotId: 'MSS_PANEL_ICON_BG',
    x: g.panelIconX,
    y: g.panelIconY,
    w: g.panelIconBgSize,
    h: g.panelIconBgSize,
    color: MSS_COLORS.primary,
    layer: 4,
    kind: 'panelIconBg',
  })
  
  specs.push({
    slotId: 'MSS_PANEL_ICON',
    x: g.panelIconX + (g.panelIconBgSize - g.panelIconSize) / 2,
    y: g.panelIconY + (g.panelIconBgSize - g.panelIconSize) / 2,
    w: g.panelIconSize,
    h: g.panelIconSize,
    color: MSS_COLORS.primary,
    layer: 10,
    kind: 'panelIcon',
  })
  
  // Context items (Time, Change, Source)
  var itemIcons = [
    { y: g.item1Y, id: 1, bg: '#EFF6FF', border: '#DBEAFE' },
    { y: g.item2Y, id: 2, bg: '#ECFDF5', border: '#A7F3D0' },
    { y: g.item3Y, id: 3, bg: '#F5F3FF', border: '#DDD6FE' },
  ]
  
  itemIcons.forEach(function(item) {
    specs.push({
      slotId: 'MSS_ITEM' + item.id + '_ICON_BG',
      x: g.itemIconX,
      y: item.y,
      w: g.itemIconBgSize,
      h: g.itemIconBgSize,
      color: item.bg,
      layer: 4,
      kind: 'item' + item.id + 'IconBg',
      meta: { bg: item.bg, border: item.border },
    })
    
    specs.push({
      slotId: 'MSS_ITEM' + item.id + '_ICON',
      x: g.itemIconX + (g.itemIconBgSize - g.itemIconSize) / 2,
      y: item.y + (g.itemIconBgSize - g.itemIconSize) / 2,
      w: g.itemIconSize,
      h: g.itemIconSize,
      color: MSS_COLORS.primary,
      layer: 10,
      kind: 'item' + item.id + 'Icon',
    })
  })
  
  return specs
}

function metricSingleSplitOverlay(gx, gy, gw, gh) {
  var g = MSS_GEOM
  var sx = gw / g.viewW
  var sy = gh / g.viewH
  function box(x, y, w, h) {
    return {
      x: Math.round(gx + x * sx),
      y: Math.round(gy + y * sy),
      width: Math.max(12, Math.round(w * sx)),
      height: Math.max(10, Math.round(h * sy)),
    }
  }
  
  return {
    badge: box(g.leftBadgeX + g.leftBadgeIconSize + 12, g.leftBadgeY, g.leftBadgeW - g.leftBadgeIconSize - 16, g.leftBadgeH),
    heading: box(g.leftHeadingX, g.leftHeadingY, g.leftHeadingW, g.leftHeadingH),
    subheading: box(g.leftSubheadingX, g.leftSubheadingY, g.leftSubheadingW, g.leftSubheadingH),
    metricValue: box(g.leftMetricX, g.leftMetricY, g.leftMetricW, g.leftMetricH),
    trend: box(g.leftTrendX, g.leftTrendY, g.leftTrendW, g.leftTrendH),
    compare: box(g.leftCompareX, g.leftCompareY, g.leftCompareW, g.leftCompareH),
    panelHeading: box(g.panelHeadingX, g.panelHeadingY, g.panelHeadingW, g.panelHeadingH),
    panelDesc: box(g.panelDescX, g.panelDescY, g.panelDescW, g.panelDescH),
    item1Label: box(g.itemLabelX, g.item1Y, g.itemLabelW, g.itemLabelH),
    item1Value: box(g.itemValueX, g.item1Y + 18, g.itemValueW, g.itemValueH),
    item2Label: box(g.itemLabelX, g.item2Y, g.itemLabelW, g.itemLabelH),
    item2Value: box(g.itemValueX, g.item2Y + 18, g.itemValueW, g.itemValueH),
    item3Label: box(g.itemLabelX, g.item3Y, g.itemLabelW, g.itemLabelH),
    item3Value: box(g.itemValueX, g.item3Y + 18, g.itemValueW, g.itemValueH),
  }
}

function specToMetricSingleSplitContent(spec) {
  if (spec.kind === 'leftCard') return { svg: leftCardSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'circle') return { svg: circleSvg(spec.meta && spec.meta.metricText), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'circleIcon') return { svg: circleIconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'trendBadge') return { svg: trendBadgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'trendArrow') return { svg: trendArrowSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelBg') return { svg: panelBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIconBg') return { svg: panelIconBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIcon') return { svg: panelIconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'item1IconBg') return { svg: itemIconBgSvg('#EFF6FF', '#DBEAFE'), colorMode: 'fixed', fill: '#EFF6FF' }
  if (spec.kind === 'item2IconBg') return { svg: itemIconBgSvg('#ECFDF5', '#A7F3D0'), colorMode: 'fixed', fill: '#ECFDF5' }
  if (spec.kind === 'item3IconBg') return { svg: itemIconBgSvg('#F5F3FF', '#DDD6FE'), colorMode: 'fixed', fill: '#F5F3FF' }
  if (spec.kind === 'item1Icon') return { svg: item1IconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'item2Icon') return { svg: item2IconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'item3Icon') return { svg: item3IconSvg(), colorMode: 'fixed', fill: spec.color }
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
    : (MSS_DEFAULTS[sid] || existing)
  return Object.assign({}, el && el.content || {}, style, {
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

function layoutMetricSingleSplit(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  var canvasW = canvas.width || 1920
  var canvasH = canvas.height || 1080
  var sx = canvasW / MSS_GEOM.viewW
  var sy = canvasH / MSS_GEOM.viewH
  var overlay = metricSingleSplitOverlay(0, 0, canvasW, canvasH)
  var chromeRe = /^MSS_/i
  
  var prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })
  
  var filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isMetricSingleSplitTextSlot(el.slotId)
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
      case 'METRIC_VALUE':
        return bySlot.get('METRIC_VALUE') || bySlot.get('STAT_VALUE') || bySlot.get('STAT_1_VALUE')
      default:
        return bySlot.get(slotKey)
    }
  }

  var metricEl = resolvePrev('METRIC_VALUE')
  var metricText = plainTextFromContent(metricEl && metricEl.content) || MSS_DEFAULTS.METRIC_VALUE

  function placeText(slotId, box, style, role) {
    var prev = resolvePrev(slotId)
    return {
      id: (prev && prev.id) || newId('txt-mss'),
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
      align: 'left', verticalAlign: 'center', fontSize: 10, fontWeight: 700, color: MSS_COLORS.badgeText, clipToSlot: false, lineHeight: 1, letterSpacing: '1px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 32, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: MSS_COLORS.textSubheading, clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'subheading'),
    placeText('METRIC_VALUE', overlay.metricValue, {
      align: 'left', verticalAlign: 'center', fontSize: 78, fontWeight: 900, color: MSS_COLORS.textHero, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('TREND', overlay.trend, {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 700, color: MSS_COLORS.trend, clipToSlot: false, lineHeight: 1,
    }, 'caption'),
    placeText('COMPARE', overlay.compare, {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 500, color: MSS_COLORS.textSubheading, clipToSlot: false, lineHeight: 1,
    }, 'caption'),
    placeText('PANEL_HEADING', overlay.panelHeading, {
      align: 'left', verticalAlign: 'center', fontSize: 20, fontWeight: 800, color: MSS_COLORS.textPanelHeading, clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('PANEL_DESC', overlay.panelDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: MSS_COLORS.textSubheading, clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'body'),
  ]
  
  // Context items
  for (var i = 1; i <= 3; i++) {
    next.push(
      placeText('ITEM' + i + '_LABEL', overlay['item' + i + 'Label'], {
        align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 600, color: '#94A3B8', clipToSlot: true, lineHeight: 1.3, letterSpacing: '0.5px',
      }, 'caption'),
      placeText('ITEM' + i + '_VALUE', overlay['item' + i + 'Value'], {
        align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 700, color: '#0F172A', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap',
      }, 'body')
    )
  }

  var chrome = metricSingleSplitChromeSpecs(metricText).map(function(spec) {
    var prev = prevBySlot.get(spec.slotId.toUpperCase())
    var graphic = specToMetricSingleSplitContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-mss'),
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

module.exports = {
  isMetricSingleSplitLayout: isMetricSingleSplitLayout,
  layoutMetricSingleSplit: layoutMetricSingleSplit,
  MSS_GEOM: MSS_GEOM,
  MSS_DEFAULTS: MSS_DEFAULTS,
}