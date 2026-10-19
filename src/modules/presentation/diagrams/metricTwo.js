/**
 * Metric two — Dual elevated metric cards with dynamic progress bars, trend badges, and contextual descriptions.
 * Layout id: metric_two_v1.
 */

var MT_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Category Badge at top left
  badgeX: 60,
  badgeY: 36,
  badgeW: 130,
  badgeH: 26,
  badgeIconSize: 14,

  // Section Heading
  headingX: 60,
  headingY: 72,
  headingW: 880,
  headingH: 42,

  // Subheading
  subheadingX: 60,
  subheadingY: 118,
  subheadingW: 880,
  subheadingH: 24,

  // Dual Cards (Symmetrical: 60px left, 420px card1, 40px gap, 420px card2, 60px right = 1000px)
  card1X: 60,
  card2X: 520,
  cardY: 156,
  cardW: 420,
  cardH: 356,

  // Inside each card (relative to cardX, cardY)
  iconX: 28,
  iconY: 26,
  iconBgSize: 48,
  iconSize: 24,

  trendBadgeX: 300,
  trendBadgeY: 26,
  trendBadgeW: 92,
  trendBadgeH: 32,
  trendArrowX: 312,
  trendArrowY: 35,
  trendX: 330,
  trendY: 26,
  trendW: 54,
  trendH: 32,

  metricX: 28,
  metricY: 88,
  metricW: 364,
  metricH: 60,

  labelX: 28,
  labelY: 152,
  labelW: 364,
  labelH: 30,

  barX: 28,
  barY: 192,
  barW: 364,
  barH: 8,

  descX: 28,
  descY: 216,
  descW: 364,
  descH: 76,
}

var MT_COLORS = {
  card1: '#2563EB',          // Sapphire Blue
  card1Bg: '#EFF6FF',
  card1Border: '#DBEAFE',
  card1GradEnd: '#1D4ED8',

  card2: '#7C3AED',          // Violet / Indigo
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
  trackBg: '#F1F5F9',

  textHero: '#0F172A',
  textLabel: '#1E293B',
  textSubheading: '#64748B',
  textDesc: '#64748B',
}

var MT_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Key metrics',
  SUBHEADING: 'A quick snapshot of high-impact performance and measurable business outcomes.',

  METRIC1_VALUE: '98%',
  METRIC1_LABEL: 'Customer satisfaction',
  METRIC1_DESC: 'Reflects positive feedback and support resolutions recorded across all client touchpoints.',
  METRIC1_TREND: '+12%',

  METRIC2_VALUE: '3.2x',
  METRIC2_LABEL: 'Average ROI',
  METRIC2_DESC: 'Efficiency gains and measurable cost reductions delivered across strategic initiatives.',
  METRIC2_TREND: '+24%',
}

function isMetricTwoLayout(layoutId) {
  return /metric_two_v1$/i.test(String(layoutId || ''))
}

function isMetricTwoTextSlot(slotId) {
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
    || sid === 'METRIC2_VALUE'
    || sid === 'STAT_2_VALUE'
    || sid === 'METRIC2_LABEL'
    || sid === 'STAT_2_LABEL'
    || sid === 'METRIC2_DESC'
    || sid === 'STAT_2_DESC'
    || sid === 'METRIC2_TREND'
    || sid === 'STAT_2_TREND'
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

function cardBgSvg() {
  var g = MT_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.cardW + ' ' + g.cardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
      '<filter id="mtCardShadow" x="-5%" y="-5%" width="110%" height="115%">' +
        '<feDropShadow dx="0" dy="10" stdDeviation="16" flood-color="#0F172A" flood-opacity="0.06"/>' +
        '<feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0F172A" flood-opacity="0.04"/>' +
      '</filter>' +
      '<linearGradient id="mtCardGrad" x1="0%" y1="0%" x2="0%" y2="100%">' +
        '<stop offset="0%" stop-color="#FFFFFF"/>' +
        '<stop offset="100%" stop-color="#F8FAFC"/>' +
      '</linearGradient>' +
    '</defs>' +
    '<rect x="1" y="1" width="' + (g.cardW - 2) + '" height="' + (g.cardH - 2) + '" rx="20" ry="20" fill="url(#mtCardGrad)" stroke="' + MT_COLORS.cardBorder + '" stroke-width="1.5" filter="url(#mtCardShadow)"/>' +
  '</svg>'
}

function badgeSvg() {
  var g = MT_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0.5" y="0.5" width="' + (g.badgeW - 1) + '" height="' + (g.badgeH - 1) + '" rx="13" fill="' + MT_COLORS.badge + '" stroke="' + MT_COLORS.badgeBorder + '" stroke-width="1.2"/>' +
  '</svg>'
}

function badgeIconSvg() {
  var size = MT_GEOM.badgeIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="1" y="5" width="2.5" height="7" rx="0.5" fill="' + MT_COLORS.badgeText + '"/>' +
    '<rect x="5.5" y="2" width="2.5" height="10" rx="0.5" fill="' + MT_COLORS.badgeText + '"/>' +
    '<rect x="10" y="6" width="2.5" height="6" rx="0.5" fill="' + MT_COLORS.badgeText + '"/>' +
  '</svg>'
}

function iconBgSvg(bg, border) {
  var size = MT_GEOM.iconBgSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0.5" y="0.5" width="' + (size - 1) + '" height="' + (size - 1) + '" fill="' + bg + '" stroke="' + border + '" stroke-width="1.2" rx="12"/>' +
  '</svg>'
}

function icon1Svg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M12 2L15.09 8.26L22 9.27L17 14.14L18.18 21.02L12 17.77L5.82 21.02L7 14.14L2 9.27L8.91 8.26L12 2Z" fill="none" stroke="' + MT_COLORS.card1 + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function icon2Svg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M23 6L13.5 15.5L8.5 10.5L1 18" fill="none" stroke="' + MT_COLORS.card2 + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<path d="M17 6H23V12" fill="none" stroke="' + MT_COLORS.card2 + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function trendBadgeSvg() {
  var g = MT_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.trendBadgeW + ' ' + g.trendBadgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0.5" y="0.5" width="' + (g.trendBadgeW - 1) + '" height="' + (g.trendBadgeH - 1) + '" rx="16" fill="' + MT_COLORS.trendBg + '" stroke="' + MT_COLORS.trendBorder + '" stroke-width="1.2"/>' +
  '</svg>'
}

function trendArrowSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14" width="14" height="14">' +
    '<path d="M2.5 11.5L11.5 2.5M11.5 2.5H5.5M11.5 2.5V8.5" fill="none" stroke="' + MT_COLORS.trend + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function progressBarSvg(ratio, color, gradEnd) {
  var g = MT_GEOM
  var fillW = Math.max(16, Math.round(g.barW * Math.min(1, Math.max(0.05, ratio))))
  var gradId = 'mtBarGrad-' + color.replace('#', '')
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.barW + ' ' + g.barH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
      '<linearGradient id="' + gradId + '" x1="0%" y1="0%" x2="100%" y2="0%">' +
        '<stop offset="0%" stop-color="' + color + '" />' +
        '<stop offset="100%" stop-color="' + gradEnd + '" />' +
      '</linearGradient>' +
    '</defs>' +
    '<rect x="0" y="0" width="' + g.barW + '" height="' + g.barH + '" rx="4" fill="' + MT_COLORS.trackBg + '"/>' +
    '<rect x="0" y="0" width="' + fillW + '" height="' + g.barH + '" rx="4" fill="url(#' + gradId + ')"/>' +
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

function metricTwoChromeSpecs(metric1Text, metric2Text) {
  if (metric1Text === undefined) metric1Text = '98%'
  if (metric2Text === undefined) metric2Text = '3.2x'
  var g = MT_GEOM
  var specs = []

  // Badge background
  specs.push({
    slotId: 'MT_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: MT_COLORS.badge,
    layer: 3,
    kind: 'badge',
  })

  // Badge icon
  specs.push({
    slotId: 'MT_BADGE_ICON',
    x: g.badgeX + 10,
    y: g.badgeY + 6,
    w: g.badgeIconSize,
    h: g.badgeIconSize,
    color: MT_COLORS.badgeText,
    layer: 10,
    kind: 'badgeIcon',
  })

  // Two Cards
  var cards = [
    {
      id: 1,
      x: g.card1X,
      color: MT_COLORS.card1,
      bg: MT_COLORS.card1Bg,
      border: MT_COLORS.card1Border,
      gradEnd: MT_COLORS.card1GradEnd,
      ratio: parseMetricRatio(metric1Text, 0.98),
    },
    {
      id: 2,
      x: g.card2X,
      color: MT_COLORS.card2,
      bg: MT_COLORS.card2Bg,
      border: MT_COLORS.card2Border,
      gradEnd: MT_COLORS.card2GradEnd,
      ratio: parseMetricRatio(metric2Text, 0.8),
    },
  ]

  cards.forEach(function(c) {
    // Card Container
    specs.push({
      slotId: 'MT_CARD' + c.id + '_BG',
      x: c.x,
      y: g.cardY,
      w: g.cardW,
      h: g.cardH,
      color: MT_COLORS.cardBg,
      layer: 2,
      kind: 'cardBg',
    })

    // Icon Container
    specs.push({
      slotId: 'MT_CARD' + c.id + '_ICON_BG',
      x: c.x + g.iconX,
      y: g.cardY + g.iconY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: c.bg,
      layer: 4,
      kind: 'iconBg' + c.id,
      meta: { bg: c.bg, border: c.border },
    })

    // Icon
    specs.push({
      slotId: 'MT_CARD' + c.id + '_ICON',
      x: c.x + g.iconX + (g.iconBgSize - g.iconSize) / 2,
      y: g.cardY + g.iconY + (g.iconBgSize - g.iconSize) / 2,
      w: g.iconSize,
      h: g.iconSize,
      color: c.color,
      layer: 10,
      kind: 'icon' + c.id,
    })

    // Trend Pill Badge
    specs.push({
      slotId: 'MT_CARD' + c.id + '_TREND_BG',
      x: c.x + g.trendBadgeX,
      y: g.cardY + g.trendBadgeY,
      w: g.trendBadgeW,
      h: g.trendBadgeH,
      color: MT_COLORS.trendBg,
      layer: 5,
      kind: 'trendBadge',
    })

    // Trend Arrow
    specs.push({
      slotId: 'MT_CARD' + c.id + '_TREND_ARROW',
      x: c.x + g.trendArrowX,
      y: g.cardY + g.trendArrowY,
      w: 14,
      h: 14,
      color: MT_COLORS.trend,
      layer: 10,
      kind: 'trendArrow',
    })

    // Dynamic Progress Accent Bar
    specs.push({
      slotId: 'MT_CARD' + c.id + '_BAR',
      x: c.x + g.barX,
      y: g.cardY + g.barY,
      w: g.barW,
      h: g.barH,
      color: c.color,
      layer: 5,
      kind: 'bar' + c.id,
      meta: { ratio: c.ratio, color: c.color, gradEnd: c.gradEnd },
    })
  })

  return specs
}

function metricTwoOverlay(gx, gy, gw, gh) {
  var g = MT_GEOM
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

  var overlays = {
    badge: box(g.badgeX + g.badgeIconSize + 12, g.badgeY, g.badgeW - g.badgeIconSize - 16, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
  }

  var cardXs = [g.card1X, g.card2X]
  cardXs.forEach(function(cardX, i) {
    var num = i + 1
    overlays['metric' + num + 'Trend'] = box(cardX + g.trendX, g.cardY + g.trendY, g.trendW, g.trendH)
    overlays['metric' + num + 'Value'] = box(cardX + g.metricX, g.cardY + g.metricY, g.metricW, g.metricH)
    overlays['metric' + num + 'Label'] = box(cardX + g.labelX, g.cardY + g.labelY, g.labelW, g.labelH)
    overlays['metric' + num + 'Desc'] = box(cardX + g.descX, g.cardY + g.descY, g.descW, g.descH)
  })

  return overlays
}

function specToMetricTwoContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'cardBg') return { svg: cardBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg1') return { svg: iconBgSvg(spec.meta && spec.meta.bg, spec.meta && spec.meta.border), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg2') return { svg: iconBgSvg(spec.meta && spec.meta.bg, spec.meta && spec.meta.border), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon1') return { svg: icon1Svg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon2') return { svg: icon2Svg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'trendBadge') return { svg: trendBadgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'trendArrow') return { svg: trendArrowSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'bar1' || spec.kind === 'bar2') {
    return { svg: progressBarSvg(spec.meta && spec.meta.ratio, spec.meta && spec.meta.color, spec.meta && spec.meta.gradEnd), colorMode: 'fixed', fill: spec.color }
  }
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
    : (MT_DEFAULTS[sid] || existing)
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

function layoutMetricTwo(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  var canvasW = canvas.width || 1920
  var canvasH = canvas.height || 1080
  var sx = canvasW / MT_GEOM.viewW
  var sy = canvasH / MT_GEOM.viewH
  var overlay = metricTwoOverlay(0, 0, canvasW, canvasH)
  var chromeRe = /^MT_/i

  var prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })

  var filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isMetricTwoTextSlot(el.slotId)
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
      case 'METRIC1_DESC':
        return bySlot.get('METRIC1_DESC') || bySlot.get('STAT_1_DESC')
      case 'METRIC1_TREND':
        return bySlot.get('METRIC1_TREND') || bySlot.get('STAT_1_TREND')
      case 'METRIC2_VALUE':
        return bySlot.get('METRIC2_VALUE') || bySlot.get('STAT_2_VALUE')
      case 'METRIC2_LABEL':
        return bySlot.get('METRIC2_LABEL') || bySlot.get('STAT_2_LABEL')
      case 'METRIC2_DESC':
        return bySlot.get('METRIC2_DESC') || bySlot.get('STAT_2_DESC')
      case 'METRIC2_TREND':
        return bySlot.get('METRIC2_TREND') || bySlot.get('STAT_2_TREND')
      default:
        return bySlot.get(slotKey)
    }
  }

  var m1El = resolvePrev('METRIC1_VALUE')
  var m2El = resolvePrev('METRIC2_VALUE')
  var metric1Text = plainTextFromContent(m1El && m1El.content) || MT_DEFAULTS.METRIC1_VALUE
  var metric2Text = plainTextFromContent(m2El && m2El.content) || MT_DEFAULTS.METRIC2_VALUE

  function placeText(slotId, box, style, role) {
    var prev = resolvePrev(slotId)
    return {
      id: (prev && prev.id) || newId('txt-mt'),
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
      align: 'left', verticalAlign: 'center', fontSize: 10, fontWeight: 700, color: MT_COLORS.badgeText, clipToSlot: false, lineHeight: 1, letterSpacing: '1px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 32, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: MT_COLORS.textSubheading, clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'subheading'),
  ]

  // Dual card texts
  for (var i = 1; i <= 2; i++) {
    next.push(
      placeText('METRIC' + i + '_TREND', overlay['metric' + i + 'Trend'], {
        align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 700, color: MT_COLORS.trend, clipToSlot: false, lineHeight: 1,
      }, 'caption'),
      placeText('METRIC' + i + '_VALUE', overlay['metric' + i + 'Value'], {
        align: 'left', verticalAlign: 'center', fontSize: 52, fontWeight: 900, color: MT_COLORS.textHero, clipToSlot: true, lineHeight: 1,
      }, 'heading'),
      placeText('METRIC' + i + '_LABEL', overlay['metric' + i + 'Label'], {
        align: 'left', verticalAlign: 'center', fontSize: 18, fontWeight: 700, color: MT_COLORS.textLabel, clipToSlot: true, lineHeight: 1.25,
      }, 'caption'),
      placeText('METRIC' + i + '_DESC', overlay['metric' + i + 'Desc'], {
        align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: MT_COLORS.textDesc, clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
      }, 'body')
    )
  }

  var chrome = metricTwoChromeSpecs(metric1Text, metric2Text).map(function(spec) {
    var prev = prevBySlot.get(spec.slotId.toUpperCase())
    var graphic = specToMetricTwoContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-mt'),
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
  isMetricTwoLayout: isMetricTwoLayout,
  layoutMetricTwo: layoutMetricTwo,
  MT_GEOM: MT_GEOM,
  MT_COLORS: MT_COLORS,
  MT_DEFAULTS: MT_DEFAULTS,
}
