/**
 * Metric four cards — 4 vertical metric cards with icons, values, trend indicators, and descriptions.
 * CommonJS backend port for Athena VI Presentation diagram pipeline.
 * Layout id: metric_four_cards_v1.
 */

const M4C_GEOM = {
  viewW: 1000,
  viewH: 560,

  badgeX: 40,
  badgeY: 40,
  badgeW: 130,
  badgeH: 22,
  badgeIconSize: 14,

  headingX: 40,
  headingY: 78,
  headingW: 920,
  headingH: 46,

  subheadingX: 40,
  subheadingY: 130,
  subheadingW: 920,
  subheadingH: 22,

  cardY: 175,
  cardW: 212,
  cardH: 335,
  cardGap: 24,
  card1X: 40,
  card2X: 276,
  card3X: 512,
  card4X: 748,

  cardIconX: 20,
  cardIconY: 20,
  cardIconSize: 32,
  cardIconBgSize: 48,

  cardValueX: 20,
  cardValueY: 90,
  cardValueW: 172,
  cardValueH: 50,

  labelX: 20,
  labelY: 145,
  labelW: 172,
  labelH: 26,

  cardTrendX: 20,
  cardTrendY: 178,
  cardTrendW: 172,
  cardTrendH: 20,

  cardDescX: 20,
  cardDescY: 210,
  cardDescW: 172,
  cardDescH: 70,
}

const M4C_COLORS = {
  card1: '#3B82F6',  // Blue
  card2: '#8B5CF6',  // Purple
  card3: '#10B981',  // Green
  card4: '#F59E0B',  // Amber
}

const M4C_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Key metrics',
  SUBHEADING: 'A quick snapshot of the most important numbers at a glance.',

  CARD1_VALUE: '98%',
  CARD1_LABEL: 'Satisfaction',
  CARD1_TREND: '+12% vs. last quarter',
  CARD1_DESC: 'Consistently high customer happiness and retention across all cohorts.',

  CARD2_VALUE: '3.2x',
  CARD2_LABEL: 'Average ROI',
  CARD2_TREND: '+18% vs. last quarter',
  CARD2_DESC: 'Accelerated payback and measurable operational efficiency gains.',

  CARD3_VALUE: '500+',
  CARD3_LABEL: 'Active teams',
  CARD3_TREND: '+22% vs. last quarter',
  CARD3_DESC: 'Rapid ongoing adoption across global enterprise organizations.',

  CARD4_VALUE: '24h',
  CARD4_LABEL: 'Response time',
  CARD4_TREND: '+35% vs. last quarter',
  CARD4_DESC: 'Round-the-clock priority resolution and dedicated live engineer support.',
}

function isMetricFourCardsLayout(layoutId) {
  return /metric_four_cards_v1$/i.test(String(layoutId || ''))
}

function isMetricFourCardsTextSlot(slotId) {
  var sid = String(slotId || '').toUpperCase()
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
}

function badgeSvg() {
  var g = M4C_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.badgeW + '" height="' + g.badgeH + '" fill="#DBEAFE" rx="6"/>' +
  '</svg>'
}

function badgeIconSvg() {
  var size = M4C_GEOM.badgeIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>' +
    '<rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>' +
    '<rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>' +
  '</svg>'
}

function cardBgSvg(color) {
  var g = M4C_GEOM
  var cleanColor = color.replace('#', '')
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.cardW + ' ' + g.cardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
      '<linearGradient id="m4cGrad_' + cleanColor + '" x1="0%" y1="0%" x2="100%" y2="100%">' +
        '<stop offset="0%" style="stop-color:' + color + ';stop-opacity:0.08" />' +
        '<stop offset="100%" style="stop-color:' + color + ';stop-opacity:0.15" />' +
      '</linearGradient>' +
    '</defs>' +
    '<rect x="0" y="0" width="' + g.cardW + '" height="' + g.cardH + '" fill="url(#m4cGrad_' + cleanColor + ')" stroke="' + color + '" stroke-width="1.5" stroke-opacity="0.2" rx="16"/>' +
  '</svg>'
}

function iconBgSvg(color) {
  var size = M4C_GEOM.cardIconBgSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0" y="0" width="' + size + '" height="' + size + '" fill="' + color + '" fill-opacity="0.15" rx="12"/>' +
  '</svg>'
}

function card1IconSvg() {
  var size = M4C_GEOM.cardIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size / 2) + '" cy="12" r="7" fill="none" stroke="currentColor" stroke-width="2.2"/>' +
    '<path d="M' + (size / 2 - 7) + ' 24 Q' + (size / 2) + ' 20 ' + (size / 2 + 7) + ' 24 L' + (size / 2 + 7) + ' 30 L' + (size / 2 - 7) + ' 30 Z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/>' +
  '</svg>'
}

function card2IconSvg() {
  var size = M4C_GEOM.cardIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="4" y="4" width="24" height="24" rx="3" fill="none" stroke="currentColor" stroke-width="2.2"/>' +
    '<rect x="8" y="13" width="4" height="10" fill="currentColor" rx="0.8"/>' +
    '<rect x="14" y="9" width="4" height="14" fill="currentColor" rx="0.8"/>' +
    '<rect x="20" y="16" width="4" height="7" fill="currentColor" rx="0.8"/>' +
  '</svg>'
}

function card3IconSvg() {
  var size = M4C_GEOM.cardIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="10" cy="10" r="4.5" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<circle cx="22" cy="10" r="4.5" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<circle cx="16" cy="22" r="4.5" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<path d="M12.5 12.5 L14.5 18" stroke="currentColor" stroke-width="2"/>' +
    '<path d="M19.5 12.5 L17.5 18" stroke="currentColor" stroke-width="2"/>' +
  '</svg>'
}

function card4IconSvg() {
  var size = M4C_GEOM.cardIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size / 2) + '" cy="' + (size / 2) + '" r="11" fill="none" stroke="currentColor" stroke-width="2.2"/>' +
    '<polyline points="' + (size / 2) + ',' + (size / 2 - 6) + ' ' + (size / 2) + ',' + (size / 2) + ' ' + (size / 2 + 5) + ',' + (size / 2) + '" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function trendArrowSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 12" width="12" height="12">' +
    '<path d="M2 8 L6 4 L10 8" fill="none" stroke="#10B981" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>' +
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

function metricFourCardsChromeSpecs() {
  var g = M4C_GEOM
  var specs = []

  specs.push({
    slotId: 'M4C_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: '#DBEAFE',
    layer: 3,
    kind: 'badge',
  })

  specs.push({
    slotId: 'M4C_BADGE_ICON',
    x: g.badgeX + 10,
    y: g.badgeY + 4,
    w: g.badgeIconSize,
    h: g.badgeIconSize,
    color: '#3B82F6',
    layer: 10,
    kind: 'badgeIcon',
  })

  var cards = [
    { x: g.card1X, color: M4C_COLORS.card1, id: 1 },
    { x: g.card2X, color: M4C_COLORS.card2, id: 2 },
    { x: g.card3X, color: M4C_COLORS.card3, id: 3 },
    { x: g.card4X, color: M4C_COLORS.card4, id: 4 },
  ]

  cards.forEach(function(card) {
    specs.push({
      slotId: 'M4C_CARD' + card.id + '_BG',
      x: card.x,
      y: g.cardY,
      w: g.cardW,
      h: g.cardH,
      color: card.color,
      layer: 3,
      kind: 'cardBg',
    })

    specs.push({
      slotId: 'M4C_CARD' + card.id + '_ICON_BG',
      x: card.x + g.cardIconX,
      y: g.cardY + g.cardIconY,
      w: g.cardIconBgSize,
      h: g.cardIconBgSize,
      color: card.color,
      layer: 5,
      kind: 'iconBg',
    })

    specs.push({
      slotId: 'M4C_CARD' + card.id + '_ICON',
      x: card.x + g.cardIconX + (g.cardIconBgSize - g.cardIconSize) / 2,
      y: g.cardY + g.cardIconY + (g.cardIconBgSize - g.cardIconSize) / 2,
      w: g.cardIconSize,
      h: g.cardIconSize,
      color: card.color,
      layer: 10,
      kind: 'card' + card.id + 'Icon',
    })

    specs.push({
      slotId: 'M4C_CARD' + card.id + '_ARROW',
      x: card.x + g.cardTrendX,
      y: g.cardY + g.cardTrendY + 3,
      w: 12,
      h: 12,
      color: '#10B981',
      layer: 10,
      kind: 'trendArrow',
    })
  })

  return specs
}

function metricFourCardsOverlay(gx, gy, gw, gh) {
  var g = M4C_GEOM
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
    badge: box(g.badgeX + g.badgeIconSize + 14, g.badgeY, g.badgeW - g.badgeIconSize - 20, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
  }

  var cardXs = [g.card1X, g.card2X, g.card3X, g.card4X]
  cardXs.forEach(function(cardX, i) {
    var num = i + 1
    overlays['card' + num + 'Value'] = box(cardX + g.cardValueX, g.cardY + g.cardValueY, g.cardValueW, g.cardValueH)
    overlays['card' + num + 'Label'] = box(cardX + g.labelX, g.cardY + g.labelY, g.labelW, g.labelH)
    overlays['card' + num + 'Trend'] = box(cardX + g.cardTrendX + 16, g.cardY + g.cardTrendY, g.cardTrendW - 16, g.cardTrendH)
    overlays['card' + num + 'Desc'] = box(cardX + g.cardDescX, g.cardY + g.cardDescY, g.cardDescW, g.cardDescH)
  })

  return overlays
}

function specToMetricFourCardsContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'cardBg') return { svg: cardBgSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'card1Icon') return { svg: card1IconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'card2Icon') return { svg: card2IconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'card3Icon') return { svg: card3IconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'card4Icon') return { svg: card4IconSvg(), colorMode: 'recolor', fill: spec.color }
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
  var sid = String(slotId || '').toUpperCase()
  var existing = plainTextFromContent(el && el.content)
  var defaultKey = sid.replace('STAT_1_', 'CARD1_').replace('STAT_2_', 'CARD2_').replace('STAT_3_', 'CARD3_').replace('STAT_4_', 'CARD4_')
    .replace('METRIC1_', 'CARD1_').replace('METRIC2_', 'CARD2_').replace('METRIC3_', 'CARD3_').replace('METRIC4_', 'CARD4_')
  var text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (M4C_DEFAULTS[defaultKey] || M4C_DEFAULTS[sid] || existing)
  var res = Object.assign({}, el && el.content, style)
  res.text = text
  res.runs = null
  res.listType = null
  res.letterSpacing = style.letterSpacing !== undefined ? style.letterSpacing : '0'
  res.padding = 0
  res.paddingX = 0
  res.stroke = undefined
  res.strokeWidth = 0
  return res
}

function newId(prefix) {
  return prefix + '-' + Math.random().toString(36).slice(2, 9)
}

function layoutMetricFourCards(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  var canvasW = canvas.width || 1920
  var canvasH = canvas.height || 1080
  var sx = canvasW / M4C_GEOM.viewW
  var sy = canvasH / M4C_GEOM.viewH
  var overlay = metricFourCardsOverlay(0, 0, canvasW, canvasH)
  var chromeRe = /^M4C_/i

  var prevBySlot = new Map()
  elements.forEach(function(el) {
    if (chromeRe.test(String(el.slotId || ''))) {
      prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
    }
  })

  var bySlot = new Map()
  elements.forEach(function(el) {
    if (!chromeRe.test(String(el.slotId || '')) && isMetricFourCardsTextSlot(el.slotId)) {
      bySlot.set(String(el.slotId || '').toUpperCase(), el)
    }
  })

  var placeText = function(slotId, box, style, role) {
    var prev = bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-m4c'),
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
      align: 'center', verticalAlign: 'center', fontSize: 9, fontWeight: 700, color: '#2563EB', clipToSlot: true, lineHeight: 1, letterSpacing: '1px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 44, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.4,
    }, 'subheading'),
  ]

  for (var i = 1; i <= 4; i++) {
    var vSlot = bySlot.has('CARD' + i + '_VALUE') ? ('CARD' + i + '_VALUE') : (bySlot.has('STAT_' + i + '_VALUE') ? ('STAT_' + i + '_VALUE') : ('CARD' + i + '_VALUE'))
    var lSlot = bySlot.has('CARD' + i + '_LABEL') ? ('CARD' + i + '_LABEL') : (bySlot.has('STAT_' + i + '_LABEL') ? ('STAT_' + i + '_LABEL') : ('CARD' + i + '_LABEL'))
    var tSlot = bySlot.has('CARD' + i + '_TREND') ? ('CARD' + i + '_TREND') : (bySlot.has('STAT_' + i + '_TREND') ? ('STAT_' + i + '_TREND') : ('CARD' + i + '_TREND'))
    var dSlot = bySlot.has('CARD' + i + '_DESC') ? ('CARD' + i + '_DESC') : (bySlot.has('STAT_' + i + '_DESC') ? ('STAT_' + i + '_DESC') : ('CARD' + i + '_DESC'))

    next.push(
      placeText(vSlot, overlay['card' + i + 'Value'], {
        align: 'left', verticalAlign: 'center', fontSize: 42, fontWeight: 900, color: headingInk(palette), clipToSlot: true, lineHeight: 1,
      }, 'heading'),
      placeText(lSlot, overlay['card' + i + 'Label'], {
        align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.3,
      }, 'caption'),
      placeText(tSlot, overlay['card' + i + 'Trend'], {
        align: 'left', verticalAlign: 'center', fontSize: 11.5, fontWeight: 600, color: '#10B981', clipToSlot: true, lineHeight: 1,
      }, 'caption'),
      placeText(dSlot, overlay['card' + i + 'Desc'], {
        align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap',
      }, 'body')
    )
  }

  var chrome = metricFourCardsChromeSpecs().map(function(spec) {
    var prev = prevBySlot.get(spec.slotId.toUpperCase())
    var graphic = specToMetricFourCardsContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-m4c'),
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

function metricFourCardsPreviewSvg(previewHints, theme) {
  previewHints = previewHints || {}
  theme = theme || {}
  var slots = previewHints.slots || {}
  var stats = previewHints.stats || []

  var badgeText = (slots.BADGE && slots.BADGE.text) || previewHints.badge || M4C_DEFAULTS.BADGE
  var headingText = (slots.HEADING && slots.HEADING.text) || previewHints.heading || M4C_DEFAULTS.HEADING
  var subheadingText = (slots.SUBHEADING && slots.SUBHEADING.text) || previewHints.subheading || M4C_DEFAULTS.SUBHEADING

  var v1 = (slots.CARD1_VALUE && slots.CARD1_VALUE.text) || (slots.STAT_1_VALUE && slots.STAT_1_VALUE.text) || (stats[0] && stats[0].value) || M4C_DEFAULTS.CARD1_VALUE
  var l1 = (slots.CARD1_LABEL && slots.CARD1_LABEL.text) || (slots.STAT_1_LABEL && slots.STAT_1_LABEL.text) || (stats[0] && stats[0].label) || M4C_DEFAULTS.CARD1_LABEL
  var t1 = (slots.CARD1_TREND && slots.CARD1_TREND.text) || M4C_DEFAULTS.CARD1_TREND
  var d1 = (slots.CARD1_DESC && slots.CARD1_DESC.text) || M4C_DEFAULTS.CARD1_DESC

  var v2 = (slots.CARD2_VALUE && slots.CARD2_VALUE.text) || (slots.STAT_2_VALUE && slots.STAT_2_VALUE.text) || (stats[1] && stats[1].value) || M4C_DEFAULTS.CARD2_VALUE
  var l2 = (slots.CARD2_LABEL && slots.CARD2_LABEL.text) || (slots.STAT_2_LABEL && slots.STAT_2_LABEL.text) || (stats[1] && stats[1].label) || M4C_DEFAULTS.CARD2_LABEL
  var t2 = (slots.CARD2_TREND && slots.CARD2_TREND.text) || M4C_DEFAULTS.CARD2_TREND
  var d2 = (slots.CARD2_DESC && slots.CARD2_DESC.text) || M4C_DEFAULTS.CARD2_DESC

  var v3 = (slots.CARD3_VALUE && slots.CARD3_VALUE.text) || (slots.STAT_3_VALUE && slots.STAT_3_VALUE.text) || (stats[2] && stats[2].value) || M4C_DEFAULTS.CARD3_VALUE
  var l3 = (slots.CARD3_LABEL && slots.CARD3_LABEL.text) || (slots.STAT_3_LABEL && slots.STAT_3_LABEL.text) || (stats[2] && stats[2].label) || M4C_DEFAULTS.CARD3_LABEL
  var t3 = (slots.CARD3_TREND && slots.CARD3_TREND.text) || M4C_DEFAULTS.CARD3_TREND
  var d3 = (slots.CARD3_DESC && slots.CARD3_DESC.text) || M4C_DEFAULTS.CARD3_DESC

  var v4 = (slots.CARD4_VALUE && slots.CARD4_VALUE.text) || (slots.STAT_4_VALUE && slots.STAT_4_VALUE.text) || (stats[3] && stats[3].value) || M4C_DEFAULTS.CARD4_VALUE
  var l4 = (slots.CARD4_LABEL && slots.CARD4_LABEL.text) || (slots.STAT_4_LABEL && slots.STAT_4_LABEL.text) || (stats[3] && stats[3].label) || M4C_DEFAULTS.CARD4_LABEL
  var t4 = (slots.CARD4_TREND && slots.CARD4_TREND.text) || M4C_DEFAULTS.CARD4_TREND
  var d4 = (slots.CARD4_DESC && slots.CARD4_DESC.text) || M4C_DEFAULTS.CARD4_DESC

  var c1 = M4C_COLORS.card1
  var c2 = M4C_COLORS.card2
  var c3 = M4C_COLORS.card3
  var c4 = M4C_COLORS.card4

  function splitDesc(desc, fallback1, fallback2) {
    if (!desc) return [fallback1, fallback2]
    var words = String(desc).split(' ')
    if (words.length <= 4) return [desc, '']
    var mid = Math.ceil(words.length / 2)
    return [words.slice(0, mid).join(' '), words.slice(mid).join(' ')]
  }

  var d1Parts = splitDesc(d1, 'Consistently high happiness', 'and cohort retention.')
  var d2Parts = splitDesc(d2, 'Accelerated payback and', 'measurable efficiency gains.')
  var d3Parts = splitDesc(d3, 'Rapid ongoing adoption', 'across global teams.')
  var d4Parts = splitDesc(d4, 'Round-the-clock live support', 'and fast resolution.')

  var lines = []
  lines.push('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">')
  lines.push('  <defs>')
  lines.push('    <linearGradient id="m4cg1" x1="0%" y1="0%" x2="100%" y2="100%">')
  lines.push('      <stop offset="0%" stop-color="' + c1 + '" stop-opacity="0.08"/>')
  lines.push('      <stop offset="100%" stop-color="' + c1 + '" stop-opacity="0.15"/>')
  lines.push('    </linearGradient>')
  lines.push('    <linearGradient id="m4cg2" x1="0%" y1="0%" x2="100%" y2="100%">')
  lines.push('      <stop offset="0%" stop-color="' + c2 + '" stop-opacity="0.08"/>')
  lines.push('      <stop offset="100%" stop-color="' + c2 + '" stop-opacity="0.15"/>')
  lines.push('    </linearGradient>')
  lines.push('    <linearGradient id="m4cg3" x1="0%" y1="0%" x2="100%" y2="100%">')
  lines.push('      <stop offset="0%" stop-color="' + c3 + '" stop-opacity="0.08"/>')
  lines.push('      <stop offset="100%" stop-color="' + c3 + '" stop-opacity="0.15"/>')
  lines.push('    </linearGradient>')
  lines.push('    <linearGradient id="m4cg4" x1="0%" y1="0%" x2="100%" y2="100%">')
  lines.push('      <stop offset="0%" stop-color="' + c4 + '" stop-opacity="0.08"/>')
  lines.push('      <stop offset="100%" stop-color="' + c4 + '" stop-opacity="0.15"/>')
  lines.push('    </linearGradient>')
  lines.push('  </defs>')

  lines.push('  <rect width="1000" height="560" fill="#FFFFFF" rx="12"/>')

  // Badge
  lines.push('  <rect x="' + M4C_GEOM.badgeX + '" y="' + M4C_GEOM.badgeY + '" width="' + M4C_GEOM.badgeW + '" height="' + M4C_GEOM.badgeH + '" rx="6" fill="#DBEAFE"/>')
  lines.push('  <g transform="translate(' + (M4C_GEOM.badgeX + 12) + ', ' + (M4C_GEOM.badgeY + 4) + ')">')
  lines.push('    <rect x="1" y="4" width="3" height="8" rx="1" fill="#3B82F6"/>')
  lines.push('    <rect x="5.5" y="2" width="3" height="10" rx="1" fill="#3B82F6"/>')
  lines.push('    <rect x="10" y="6" width="3" height="6" rx="1" fill="#3B82F6"/>')
  lines.push('  </g>')
  lines.push('  <text x="' + (M4C_GEOM.badgeX + 32) + '" y="' + (M4C_GEOM.badgeY + 15) + '" fill="#2563EB" font-size="10" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif" letter-spacing="0.5px">' + badgeText + '</text>')

  // Heading & Subheading
  lines.push('  <text x="' + M4C_GEOM.headingX + '" y="116" fill="#0F172A" font-size="44" font-weight="800" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + headingText + '</text>')
  lines.push('  <text x="' + M4C_GEOM.subheadingX + '" y="147" fill="#475569" font-size="15" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + subheadingText + '</text>')

  // Card 1 (Blue)
  lines.push('  <rect x="' + M4C_GEOM.card1X + '" y="' + M4C_GEOM.cardY + '" width="' + M4C_GEOM.cardW + '" height="' + M4C_GEOM.cardH + '" rx="16" fill="url(#m4cg1)" stroke="' + c1 + '" stroke-width="1.5" stroke-opacity="0.2"/>')
  lines.push('  <rect x="' + (M4C_GEOM.card1X + 20) + '" y="' + (M4C_GEOM.cardY + 20) + '" width="48" height="48" rx="12" fill="' + c1 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(' + (M4C_GEOM.card1X + 28) + ', ' + (M4C_GEOM.cardY + 28) + ')">')
  lines.push('    <circle cx="16" cy="12" r="7" fill="none" stroke="' + c1 + '" stroke-width="2.2"/>')
  lines.push('    <path d="M9 24 Q16 20 23 24 L23 30 L9 30 Z" fill="none" stroke="' + c1 + '" stroke-width="2.2" stroke-linejoin="round"/>')
  lines.push('  </g>')
  lines.push('  <text x="' + (M4C_GEOM.card1X + 20) + '" y="' + (M4C_GEOM.cardY + 128) + '" fill="#0F172A" font-size="44" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + v1 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card1X + 20) + '" y="' + (M4C_GEOM.cardY + 158) + '" fill="#1E293B" font-size="16" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + l1 + '</text>')
  lines.push('  <path d="M' + (M4C_GEOM.card1X + 21) + ' ' + (M4C_GEOM.cardY + 185) + ' L' + (M4C_GEOM.card1X + 25) + ' ' + (M4C_GEOM.cardY + 179) + ' L' + (M4C_GEOM.card1X + 29) + ' ' + (M4C_GEOM.cardY + 185) + '" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('  <text x="' + (M4C_GEOM.card1X + 34) + '" y="' + (M4C_GEOM.cardY + 186) + '" fill="#10B981" font-size="12" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + t1 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card1X + 20) + '" y="' + (M4C_GEOM.cardY + 224) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d1Parts[0] + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card1X + 20) + '" y="' + (M4C_GEOM.cardY + 242) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d1Parts[1] + '</text>')

  // Card 2 (Purple)
  lines.push('  <rect x="' + M4C_GEOM.card2X + '" y="' + M4C_GEOM.cardY + '" width="' + M4C_GEOM.cardW + '" height="' + M4C_GEOM.cardH + '" rx="16" fill="url(#m4cg2)" stroke="' + c2 + '" stroke-width="1.5" stroke-opacity="0.2"/>')
  lines.push('  <rect x="' + (M4C_GEOM.card2X + 20) + '" y="' + (M4C_GEOM.cardY + 20) + '" width="48" height="48" rx="12" fill="' + c2 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(' + (M4C_GEOM.card2X + 28) + ', ' + (M4C_GEOM.cardY + 28) + ')">')
  lines.push('    <rect x="4" y="4" width="24" height="24" rx="3" fill="none" stroke="' + c2 + '" stroke-width="2.2"/>')
  lines.push('    <rect x="8" y="13" width="4" height="10" fill="' + c2 + '" rx="0.8"/>')
  lines.push('    <rect x="14" y="9" width="4" height="14" fill="' + c2 + '" rx="0.8"/>')
  lines.push('    <rect x="20" y="16" width="4" height="7" fill="' + c2 + '" rx="0.8"/>')
  lines.push('  </g>')
  lines.push('  <text x="' + (M4C_GEOM.card2X + 20) + '" y="' + (M4C_GEOM.cardY + 128) + '" fill="#0F172A" font-size="44" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + v2 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card2X + 20) + '" y="' + (M4C_GEOM.cardY + 158) + '" fill="#1E293B" font-size="16" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + l2 + '</text>')
  lines.push('  <path d="M' + (M4C_GEOM.card2X + 21) + ' ' + (M4C_GEOM.cardY + 185) + ' L' + (M4C_GEOM.card2X + 25) + ' ' + (M4C_GEOM.cardY + 179) + ' L' + (M4C_GEOM.card2X + 29) + ' ' + (M4C_GEOM.cardY + 185) + '" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('  <text x="' + (M4C_GEOM.card2X + 34) + '" y="' + (M4C_GEOM.cardY + 186) + '" fill="#10B981" font-size="12" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + t2 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card2X + 20) + '" y="' + (M4C_GEOM.cardY + 224) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d2Parts[0] + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card2X + 20) + '" y="' + (M4C_GEOM.cardY + 242) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d2Parts[1] + '</text>')

  // Card 3 (Green)
  lines.push('  <rect x="' + M4C_GEOM.card3X + '" y="' + M4C_GEOM.cardY + '" width="' + M4C_GEOM.cardW + '" height="' + M4C_GEOM.cardH + '" rx="16" fill="url(#m4cg3)" stroke="' + c3 + '" stroke-width="1.5" stroke-opacity="0.2"/>')
  lines.push('  <rect x="' + (M4C_GEOM.card3X + 20) + '" y="' + (M4C_GEOM.cardY + 20) + '" width="48" height="48" rx="12" fill="' + c3 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(' + (M4C_GEOM.card3X + 28) + ', ' + (M4C_GEOM.cardY + 28) + ')">')
  lines.push('    <circle cx="10" cy="10" r="4.5" fill="none" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <circle cx="22" cy="10" r="4.5" fill="none" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <circle cx="16" cy="22" r="4.5" fill="none" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <path d="M12.5 12.5 L14.5 18" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <path d="M19.5 12.5 L17.5 18" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('  </g>')
  lines.push('  <text x="' + (M4C_GEOM.card3X + 20) + '" y="' + (M4C_GEOM.cardY + 128) + '" fill="#0F172A" font-size="44" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + v3 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card3X + 20) + '" y="' + (M4C_GEOM.cardY + 158) + '" fill="#1E293B" font-size="16" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + l3 + '</text>')
  lines.push('  <path d="M' + (M4C_GEOM.card3X + 21) + ' ' + (M4C_GEOM.cardY + 185) + ' L' + (M4C_GEOM.card3X + 25) + ' ' + (M4C_GEOM.cardY + 179) + ' L' + (M4C_GEOM.card3X + 29) + ' ' + (M4C_GEOM.cardY + 185) + '" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('  <text x="' + (M4C_GEOM.card3X + 34) + '" y="' + (M4C_GEOM.cardY + 186) + '" fill="#10B981" font-size="12" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + t3 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card3X + 20) + '" y="' + (M4C_GEOM.cardY + 224) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d3Parts[0] + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card3X + 20) + '" y="' + (M4C_GEOM.cardY + 242) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d3Parts[1] + '</text>')

  // Card 4 (Amber)
  lines.push('  <rect x="' + M4C_GEOM.card4X + '" y="' + M4C_GEOM.cardY + '" width="' + M4C_GEOM.cardW + '" height="' + M4C_GEOM.cardH + '" rx="16" fill="url(#m4cg4)" stroke="' + c4 + '" stroke-width="1.5" stroke-opacity="0.2"/>')
  lines.push('  <rect x="' + (M4C_GEOM.card4X + 20) + '" y="' + (M4C_GEOM.cardY + 20) + '" width="48" height="48" rx="12" fill="' + c4 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(' + (M4C_GEOM.card4X + 28) + ', ' + (M4C_GEOM.cardY + 28) + ')">')
  lines.push('    <circle cx="16" cy="16" r="11" fill="none" stroke="' + c4 + '" stroke-width="2.2"/>')
  lines.push('    <polyline points="16,10 16,16 21,16" fill="none" stroke="' + c4 + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('  </g>')
  lines.push('  <text x="' + (M4C_GEOM.card4X + 20) + '" y="' + (M4C_GEOM.cardY + 128) + '" fill="#0F172A" font-size="44" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + v4 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card4X + 20) + '" y="' + (M4C_GEOM.cardY + 158) + '" fill="#1E293B" font-size="16" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + l4 + '</text>')
  lines.push('  <path d="M' + (M4C_GEOM.card4X + 21) + ' ' + (M4C_GEOM.cardY + 185) + ' L' + (M4C_GEOM.card4X + 25) + ' ' + (M4C_GEOM.cardY + 179) + ' L' + (M4C_GEOM.card4X + 29) + ' ' + (M4C_GEOM.cardY + 185) + '" fill="none" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('  <text x="' + (M4C_GEOM.card4X + 34) + '" y="' + (M4C_GEOM.cardY + 186) + '" fill="#10B981" font-size="12" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + t4 + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card4X + 20) + '" y="' + (M4C_GEOM.cardY + 224) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d4Parts[0] + '</text>')
  lines.push('  <text x="' + (M4C_GEOM.card4X + 20) + '" y="' + (M4C_GEOM.cardY + 242) + '" fill="#64748B" font-size="12.5" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + d4Parts[1] + '</text>')

  lines.push('</svg>')
  return lines.join('\n')
}

module.exports = {
  isMetricFourCardsLayout: isMetricFourCardsLayout,
  isMetricFourCardsTextSlot: isMetricFourCardsTextSlot,
  layoutMetricFourCards: layoutMetricFourCards,
  metricFourCardsPreviewSvg: metricFourCardsPreviewSvg,
  M4C_GEOM: M4C_GEOM,
  M4C_DEFAULTS: M4C_DEFAULTS,
  M4C_COLORS: M4C_COLORS,
}
