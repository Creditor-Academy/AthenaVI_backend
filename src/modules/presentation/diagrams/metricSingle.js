/**
 * Metric single — Single large metric with circular progress ring inside an elevated container card.
 * Layout id: metric_single_v1.
 */

var MS_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Elevated Main Container Card
  cardX: 50,
  cardY: 35,
  cardW: 900,
  cardH: 490,
  dividerY: 103, // Relative to card top (global 138)
  pedestalCy: 243, // Relative to card top (global 278)
  
  // Icon at top left (inside card)
  iconX: 86,
  iconY: 62,
  iconSize: 28,
  iconBgSize: 52,
  
  // Heading (top center-left inside card)
  headingX: 154,
  headingY: 58,
  headingW: 610,
  headingH: 40,
  
  // Subheading below heading (inside card)
  subheadingX: 154,
  subheadingY: 100,
  subheadingW: 610,
  subheadingH: 22,
  
  // Trend pill indicator (top right inside card)
  trendBadgeX: 804,
  trendBadgeY: 64,
  trendBadgeW: 110,
  trendBadgeH: 36,
  trendArrowX: 816,
  trendArrowY: 75,
  trendX: 834,
  trendY: 64,
  trendW: 70,
  trendH: 36,
  
  // Center circle with metric (inside card)
  circleX: 390,
  circleY: 168,
  circleDiameter: 220,
  circleStrokeWidth: 18,
  
  // Metric value inside circle (inside card)
  metricX: 390,
  metricY: 244,
  metricW: 220,
  metricH: 68,
  
  // Label below circle (inside card)
  labelX: 250,
  labelY: 418,
  labelW: 500,
  labelH: 34,
}

var MS_COLORS = {
  primary: '#2563EB',
  circle: '#2563EB',
  circleGradientEnd: '#1D4ED8',
  circleTrack: '#EEF2F6',
  trend: '#059669',
  trendBg: '#ECFDF5',
  trendBorder: '#A7F3D0',
  iconBg: '#EFF6FF',
  iconBorder: '#DBEAFE',
  textHero: '#0F172A',
  textLabel: '#334155',
  textSubheading: '#64748B',
  cardBg: '#FFFFFF',
  cardBorder: '#E2E8F0',
}

var MS_DEFAULTS = {
  HEADING: 'Performance Overview',
  SUBHEADING: 'Key customer metric at a glance.',
  METRIC_VALUE: '98%',
  LABEL: 'Customer satisfaction',
  TREND: '+12%',
}

function isMetricSingleLayout(layoutId) {
  return /metric_single_v1$/i.test(String(layoutId || ''))
}

function isMetricSingleTextSlot(slotId) {
  var sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || sid === 'TITLE'
    || sid === 'SUBHEADING'
    || sid === 'SUBTITLE'
    || sid === 'METRIC_VALUE'
    || sid === 'STAT_VALUE'
    || sid === 'LABEL'
    || sid === 'STAT_LABEL'
    || sid === 'TREND'
    || sid === 'BADGE'
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

function containerCardSvg() {
  var g = MS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.cardW + ' ' + g.cardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
    '<filter id="msContainerShadow" x="-5%" y="-5%" width="110%" height="115%">' +
    '<feDropShadow dx="0" dy="12" stdDeviation="20" flood-color="#0F172A" flood-opacity="0.06"/>' +
    '<feDropShadow dx="0" dy="2" stdDeviation="6" flood-color="#0F172A" flood-opacity="0.04"/>' +
    '</filter>' +
    '<linearGradient id="msContainerBg" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" stop-color="#FFFFFF"/>' +
    '<stop offset="100%" stop-color="#F8FAFC"/>' +
    '</linearGradient>' +
    '</defs>' +
    '<rect x="1" y="1" width="' + (g.cardW - 2) + '" height="' + (g.cardH - 2) + '" rx="24" ry="24" fill="url(#msContainerBg)" stroke="' + MS_COLORS.cardBorder + '" stroke-width="1.5" filter="url(#msContainerShadow)"/>' +
    '<line x1="36" y1="' + g.dividerY + '" x2="' + (g.cardW - 36) + '" y2="' + g.dividerY + '" stroke="#F1F5F9" stroke-width="1.2"/>' +
    '<circle cx="' + (g.cardW / 2) + '" cy="' + g.pedestalCy + '" r="128" fill="#F8FAFC" stroke="#EEF2F6" stroke-width="1"/>' +
    '</svg>'
}

function iconBgSvg() {
  var g = MS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.iconBgSize + ' ' + g.iconBgSize + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0.5" y="0.5" width="' + (g.iconBgSize - 1) + '" height="' + (g.iconBgSize - 1) + '" fill="' + MS_COLORS.iconBg + '" stroke="' + MS_COLORS.iconBorder + '" stroke-width="1.2" rx="14"/>' +
    '</svg>'
}

function iconSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M4 22V17M10 22V11M16 22V14M22 22V6" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<path d="M4 17L10 11L16 14L22 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" opacity="0.4"/>' +
    '</svg>'
}

function trendBadgeSvg() {
  var g = MS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.trendBadgeW + ' ' + g.trendBadgeH + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0.5" y="0.5" width="' + (g.trendBadgeW - 1) + '" height="' + (g.trendBadgeH - 1) + '" rx="18" fill="' + MS_COLORS.trendBg + '" stroke="' + MS_COLORS.trendBorder + '" stroke-width="1.2"/>' +
    '</svg>'
}

function trendArrowSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14" width="14" height="14">' +
    '<path d="M2.5 11.5L11.5 2.5M11.5 2.5H5.5M11.5 2.5V8.5" fill="none" stroke="' + MS_COLORS.trend + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>'
}

function circleSvg(metricText) {
  var g = MS_GEOM
  var r = (g.circleDiameter - g.circleStrokeWidth) / 2
  var cx = g.circleDiameter / 2
  var cy = g.circleDiameter / 2
  var viewBox = g.circleDiameter
  var circumference = 2 * Math.PI * r
  
  var progressPercent = parseMetricPercent(metricText)
  var strokeDashoffset = circumference * (1 - progressPercent)
  
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + viewBox + ' ' + viewBox + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<defs>' +
    '<linearGradient id="msCircleGradient" x1="0%" y1="0%" x2="100%" y2="100%">' +
    '<stop offset="0%" stop-color="' + MS_COLORS.circle + '" />' +
    '<stop offset="100%" stop-color="' + MS_COLORS.circleGradientEnd + '" />' +
    '</linearGradient>' +
    '<filter id="msGlow" x="-20%" y="-20%" width="140%" height="140%">' +
    '<feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="' + MS_COLORS.circle + '" flood-opacity="0.22"/>' +
    '</filter>' +
    '</defs>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + (r + g.circleStrokeWidth / 2 + 5) + '" fill="none" stroke="#F1F5F9" stroke-width="4"/>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + MS_COLORS.circleTrack + '" stroke-width="' + g.circleStrokeWidth + '"/>' +
    '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="url(#msCircleGradient)" stroke-width="' + g.circleStrokeWidth + '" stroke-linecap="round" stroke-dasharray="' + circumference + '" stroke-dashoffset="' + strokeDashoffset + '" transform="rotate(-90 ' + cx + ' ' + cy + ')" filter="url(#msGlow)"/>' +
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827'
}

function metricSingleChromeSpecs(metricText) {
  metricText = metricText || '98%'
  var g = MS_GEOM
  var specs = []
  
  // Main elevated container card
  specs.push({
    slotId: 'MS_CONTAINER',
    x: g.cardX,
    y: g.cardY,
    w: g.cardW,
    h: g.cardH,
    color: MS_COLORS.cardBg,
    layer: 2,
    kind: 'containerCard',
  })
  
  // Icon background
  specs.push({
    slotId: 'MS_ICON_BG',
    x: g.iconX,
    y: g.iconY,
    w: g.iconBgSize,
    h: g.iconBgSize,
    color: MS_COLORS.iconBg,
    layer: 4,
    kind: 'iconBg',
  })
  
  // Icon
  specs.push({
    slotId: 'MS_ICON',
    x: g.iconX + (g.iconBgSize - g.iconSize) / 2,
    y: g.iconY + (g.iconBgSize - g.iconSize) / 2,
    w: g.iconSize,
    h: g.iconSize,
    color: MS_COLORS.primary,
    layer: 10,
    kind: 'icon',
  })
  
  // Circle with dynamic progress
  specs.push({
    slotId: 'MS_CIRCLE',
    x: g.circleX,
    y: g.circleY,
    w: g.circleDiameter,
    h: g.circleDiameter,
    color: MS_COLORS.circle,
    layer: 5,
    kind: 'circle',
    meta: { metricText: metricText },
  })
  
  // Trend pill background badge
  specs.push({
    slotId: 'MS_TREND_BG',
    x: g.trendBadgeX,
    y: g.trendBadgeY,
    w: g.trendBadgeW,
    h: g.trendBadgeH,
    color: MS_COLORS.trendBg,
    layer: 8,
    kind: 'trendBadge',
  })
  
  // Trend arrow
  specs.push({
    slotId: 'MS_TREND_ARROW',
    x: g.trendArrowX,
    y: g.trendArrowY,
    w: 14,
    h: 14,
    color: MS_COLORS.trend,
    layer: 10,
    kind: 'trendArrow',
  })
  
  return specs
}

function metricSingleOverlay(gx, gy, gw, gh) {
  var g = MS_GEOM
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
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
    metricValue: box(g.metricX, g.metricY, g.metricW, g.metricH),
    label: box(g.labelX, g.labelY, g.labelW, g.labelH),
    trend: box(g.trendX, g.trendY, g.trendW, g.trendH),
  }
}

function specToMetricSingleContent(spec) {
  if (spec.kind === 'containerCard') return { svg: containerCardSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon') return { svg: iconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'circle') return { svg: circleSvg(spec.meta && spec.meta.metricText), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'trendBadge') return { svg: trendBadgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'trendArrow') return { svg: trendArrowSvg(), colorMode: 'fixed', fill: spec.color }
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
    : (MS_DEFAULTS[sid] || existing)
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

function layoutMetricSingle(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  var canvasW = canvas.width || 1920
  var canvasH = canvas.height || 1080
  var sx = canvasW / MS_GEOM.viewW
  var sy = canvasH / MS_GEOM.viewH
  var overlay = metricSingleOverlay(0, 0, canvasW, canvasH)
  var chromeRe = /^MS_/i
  
  var prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })
  
  var filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isMetricSingleTextSlot(el.slotId)
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
      case 'LABEL':
        return bySlot.get('LABEL') || bySlot.get('STAT_LABEL') || bySlot.get('STAT_1_LABEL')
      case 'TREND':
        return bySlot.get('TREND') || bySlot.get('BADGE') || bySlot.get('STAT_TREND')
      default:
        return bySlot.get(slotKey)
    }
  }

  var metricEl = resolvePrev('METRIC_VALUE')
  var metricText = plainTextFromContent(metricEl && metricEl.content) || MS_DEFAULTS.METRIC_VALUE

  function placeText(slotId, box, style, role) {
    var prev = resolvePrev(slotId)
    return {
      id: (prev && prev.id) || newId('txt-ms'),
      type: 'text',
      slotId: slotId,
      role: (prev && prev.role) || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  var next = [
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'center', fontSize: 28, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.15,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 400, color: MS_COLORS.textSubheading, clipToSlot: true, lineHeight: 1.4,
    }, 'subheading'),
    placeText('METRIC_VALUE', overlay.metricValue, {
      align: 'center', verticalAlign: 'center', fontSize: 64, fontWeight: 900, color: MS_COLORS.textHero, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('LABEL', overlay.label, {
      align: 'center', verticalAlign: 'center', fontSize: 19, fontWeight: 600, color: MS_COLORS.textLabel, clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('TREND', overlay.trend, {
      align: 'left', verticalAlign: 'center', fontSize: 16, fontWeight: 700, color: MS_COLORS.trend, clipToSlot: false, lineHeight: 1,
    }, 'caption'),
  ]

  var chrome = metricSingleChromeSpecs(metricText).map(function(spec) {
    var prev = prevBySlot.get(spec.slotId.toUpperCase())
    var graphic = specToMetricSingleContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-ms'),
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
  isMetricSingleLayout: isMetricSingleLayout,
  layoutMetricSingle: layoutMetricSingle,
  MS_GEOM: MS_GEOM,
  MS_DEFAULTS: MS_DEFAULTS,
}
