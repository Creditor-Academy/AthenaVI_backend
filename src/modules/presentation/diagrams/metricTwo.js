/**
 * Metric two — Two side-by-side metric cards with icons and descriptions.
 * Layout id: metric_two_v1.
 */

const MT_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Badge at top left
  badgeX: 50,
  badgeY: 50,
  badgeW: 150,
  badgeH: 26,
  badgeIconSize: 16,
  
  // Heading
  headingX: 50,
  headingY: 100,
  headingW: 700,
  headingH: 65,
  
  // Subheading
  subheadingX: 50,
  subheadingY: 170,
  subheadingW: 700,
  subheadingH: 24,
  
  // Dots decoration (top right)
  dotsX: 910,
  dotsY: 50,
  dotsW: 60,
  dotsH: 16,
  
  // Two cards side by side
  card1X: 50,
  card2X: 525,
  cardY: 230,
  cardW: 450,
  cardH: 220,
  
  // Inside each card
  iconX: 25,
  iconY: 25,
  iconSize: 48,
  iconBgSize: 70,
  
  metricX: 120,
  metricY: 25,
  metricW: 305,
  metricH: 75,
  
  labelX: 120,
  labelY: 110,
  labelW: 305,
  labelH: 32,
  
  underlineX: 120,
  underlineY: 148,
  underlineW: 60,
  underlineH: 4,
  
  descX: 120,
  descY: 165,
  descW: 305,
  descH: 48,
  
  // Decorative circles (bottom left)
  decoX: 0,
  decoY: 440,
  decoW: 200,
  decoH: 120,
}

const MT_COLORS = {
  card1: '#3B82F6',
  card2: '#8B5CF6',
  badge: '#DBEAFE',
  badgeText: '#3B82F6',
  dots: '#3B82F6',
  cardBg: '#F8FAFC',
  deco: '#DBEAFE',
}

const MT_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Key metrics',
  SUBHEADING: 'A quick snapshot of your performance at a glance.',
  
  METRIC1_VALUE: '98%',
  METRIC1_LABEL: 'Customer satisfaction',
  METRIC1_DESC: 'Based on customer feedback and ratings.',
  
  METRIC2_VALUE: '3.2x',
  METRIC2_LABEL: 'Average ROI',
  METRIC2_DESC: 'Generated from key initiatives and campaigns.',
}

function isMetricTwoLayout(layoutId) {
  return /metric_two_v1$/i.test(String(layoutId || ''))
}

function isMetricTwoTextSlot(slotId) {
  var sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'METRIC1_VALUE'
    || sid === 'METRIC1_LABEL'
    || sid === 'METRIC1_DESC'
    || sid === 'METRIC2_VALUE'
    || sid === 'METRIC2_LABEL'
    || sid === 'METRIC2_DESC'
}

function badgeSvg() {
  var g = MT_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.badgeW + '" height="' + g.badgeH + '" fill="' + MT_COLORS.badge + '" rx="8"/>' +
    '</svg>'
}

function badgeIconSvg() {
  var size = MT_GEOM.badgeIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="1" y="5" width="3" height="8" rx="0.5" fill="' + MT_COLORS.badgeText + '"/>' +
    '<rect x="5" y="3" width="3" height="10" rx="0.5" fill="' + MT_COLORS.badgeText + '"/>' +
    '<rect x="9" y="7" width="3" height="6" rx="0.5" fill="' + MT_COLORS.badgeText + '"/>' +
    '</svg>'
}

function dotsSvg() {
  var g = MT_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.dotsW + ' ' + g.dotsH + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="8" cy="8" r="7" fill="' + MT_COLORS.dots + '"/>' +
    '<circle cx="30" cy="8" r="7" fill="' + MT_COLORS.dots + '" opacity="0.5"/>' +
    '<circle cx="52" cy="8" r="7" fill="' + MT_COLORS.dots + '" opacity="0.3"/>' +
    '</svg>'
}

function cardBgSvg() {
  var g = MT_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.cardW + ' ' + g.cardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.cardW + '" height="' + g.cardH + '" fill="' + MT_COLORS.cardBg + '" rx="20"/>' +
    '</svg>'
}

function iconBgSvg(color) {
  var size = MT_GEOM.iconBgSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0" y="0" width="' + size + '" height="' + size + '" fill="' + color + '" fill-opacity="0.12" rx="14"/>' +
    '</svg>'
}

function icon1Svg() {
  var size = MT_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="16" cy="14" r="8" fill="none" stroke="currentColor" stroke-width="2.5"/>' +
    '<circle cx="32" cy="14" r="8" fill="none" stroke="currentColor" stroke-width="2.5"/>' +
    '<path d="M8 32 Q12 28 16 28 Q20 28 24 28 Q28 28 32 28 Q36 28 40 32 L40 40 L8 40 Z" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/>' +
    '</svg>'
}

function icon2Svg() {
  var size = MT_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M8 32 L16 16 L24 24 L40 8" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<polyline points="32,8 40,8 40,16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>'
}

function underlineSvg(color) {
  var g = MT_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.underlineW + ' ' + g.underlineH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.underlineW + '" height="' + g.underlineH + '" fill="' + color + '" rx="2"/>' +
    '</svg>'
}

function decoCirclesSvg() {
  var w = 200
  var h = 120
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + w + ' ' + h + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<circle cx="30" cy="60" r="80" fill="' + MT_COLORS.deco + '" opacity="0.3"/>' +
    '<circle cx="80" cy="90" r="60" fill="' + MT_COLORS.deco + '" opacity="0.5"/>' +
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

function metricTwoChromeSpecs() {
  var g = MT_GEOM
  var specs = []
  
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
  
  specs.push({
    slotId: 'MT_BADGE_ICON',
    x: g.badgeX + 12,
    y: g.badgeY + 5,
    w: g.badgeIconSize,
    h: g.badgeIconSize,
    color: MT_COLORS.badgeText,
    layer: 10,
    kind: 'badgeIcon',
  })
  
  specs.push({
    slotId: 'MT_DOTS',
    x: g.dotsX,
    y: g.dotsY,
    w: g.dotsW,
    h: g.dotsH,
    color: MT_COLORS.dots,
    layer: 10,
    kind: 'dots',
  })
  
  specs.push({
    slotId: 'MT_DECO_CIRCLES',
    x: g.decoX,
    y: g.decoY,
    w: g.decoW,
    h: g.decoH,
    color: MT_COLORS.deco,
    layer: 2,
    kind: 'decoCircles',
  })
  
  var cards = [
    { x: g.card1X, color: MT_COLORS.card1, id: 1 },
    { x: g.card2X, color: MT_COLORS.card2, id: 2 },
  ]
  
  cards.forEach(function(card) {
    specs.push({
      slotId: 'MT_CARD' + card.id + '_BG',
      x: card.x,
      y: g.cardY,
      w: g.cardW,
      h: g.cardH,
      color: MT_COLORS.cardBg,
      layer: 3,
      kind: 'cardBg',
    })
    
    specs.push({
      slotId: 'MT_CARD' + card.id + '_ICON_BG',
      x: card.x + g.iconX,
      y: g.cardY + g.iconY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: card.color,
      layer: 5,
      kind: 'iconBg',
    })
    
    specs.push({
      slotId: 'MT_CARD' + card.id + '_ICON',
      x: card.x + g.iconX + (g.iconBgSize - g.iconSize) / 2,
      y: g.cardY + g.iconY + (g.iconBgSize - g.iconSize) / 2,
      w: g.iconSize,
      h: g.iconSize,
      color: card.color,
      layer: 10,
      kind: 'icon' + card.id,
    })
    
    specs.push({
      slotId: 'MT_CARD' + card.id + '_UNDERLINE',
      x: card.x + g.underlineX,
      y: g.cardY + g.underlineY,
      w: g.underlineW,
      h: g.underlineH,
      color: card.color,
      layer: 10,
      kind: 'underline',
    })
  })
  
  return specs
}

function metricTwoOverlay(gx, gy, gw, gh) {
  var g = MT_GEOM
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
  
  var overlays = {
    badge: box(g.badgeX + g.badgeIconSize + 18, g.badgeY, g.badgeW - g.badgeIconSize - 24, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
  }
  
  var cardXs = [g.card1X, g.card2X]
  cardXs.forEach(function(cardX, i) {
    var num = i + 1
    overlays['metric' + num + 'Value'] = box(cardX + g.metricX, g.cardY + g.metricY, g.metricW, g.metricH)
    overlays['metric' + num + 'Label'] = box(cardX + g.labelX, g.cardY + g.labelY, g.labelW, g.labelH)
    overlays['metric' + num + 'Desc'] = box(cardX + g.descX, g.cardY + g.descY, g.descW, g.descH)
  })
  
  return overlays
}

function specToMetricTwoContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'dots') return { svg: dotsSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'cardBg') return { svg: cardBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon1') return { svg: icon1Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'icon2') return { svg: icon2Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'underline') return { svg: underlineSvg(spec.color), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'decoCircles') return { svg: decoCirclesSvg(), colorMode: 'fixed', fill: spec.color }
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
    bySlot.set(String(el.slotId || ''), el)
  })

  function placeText(slotId, box, style, role) {
    var prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
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
      align: 'center', verticalAlign: 'center', fontSize: 10, fontWeight: 700, color: MT_COLORS.badgeText, clipToSlot: true, lineHeight: 1, letterSpacing: '1.5px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 56, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.4,
    }, 'subheading'),
  ]
  
  var colors = [MT_COLORS.card1, MT_COLORS.card2]
  for (var i = 1; i <= 2; i++) {
    next.push(
      placeText('METRIC' + i + '_VALUE', overlay['metric' + i + 'Value'], {
        align: 'left', verticalAlign: 'center', fontSize: 64, fontWeight: 900, color: colors[i-1], clipToSlot: true, lineHeight: 1,
      }, 'heading'),
      placeText('METRIC' + i + '_LABEL', overlay['metric' + i + 'Label'], {
        align: 'left', verticalAlign: 'center', fontSize: 18, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.3,
      }, 'caption'),
      placeText('METRIC' + i + '_DESC', overlay['metric' + i + 'Desc'], {
        align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
      }, 'body')
    )
  }

  var chrome = metricTwoChromeSpecs().map(function(spec) {
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
  MT_DEFAULTS: MT_DEFAULTS,
}
