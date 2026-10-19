/**
 * Chart three context cards — three side-by-side metric cards with icons, charts, and insights.
 * Layout id: chart_three_context_cards_v1.
 */

const CTCC_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Badge at top
  badgeX: 50,
  badgeY: 20,
  badgeW: 200,
  badgeH: 22,
  
  // Heading
  headingX: 50,
  headingY: 50,
  headingW: 900,
  headingH: 50,
  
  // Card dimensions
  cardStartY: 120,
  cardW: 305,
  cardH: 400,
  cardGap: 25,
  
  // Inside each card
  iconSize: 48,
  iconX: 25,
  iconY: 25,
  
  titleX: 85,
  titleY: 30,
  
  // Chart in card
  chartX: 25,
  chartY: 80,
  chartW: 255,
  chartH: 240,
  
  // Insight box at bottom
  insightY: 330,
  insightX: 25,
  insightW: 255,
  insightH: 55,
  insightIconSize: 36,
  insightTextX: 45,
}

const CTCC_COLORS = {
  card1: '#3B82F6',  // Blue
  card2: '#8B5CF6',  // Purple
  card3: '#10B981',  // Green
}

const CTCC_DEFAULTS = {
  BADGE: 'QUARTERLY COMPARISON',
  HEADING: 'Three Metrics Comparison',
  
  CHART_1_TITLE: 'Metric A',
  CHART_1_INSIGHT: 'This metric shows steady growth across all quarters.',
  
  CHART_2_TITLE: 'Metric B',
  CHART_2_INSIGHT: 'This metric reached its highest point in Q3.',
  
  CHART_3_TITLE: 'Metric C',
  CHART_3_INSIGHT: 'This metric showed solid improvement by Q4.',
}

function isChartThreeContextCardsLayout(layoutId) {
  return /chart_three_context_cards_v1$/i.test(String(layoutId || ''))
}

function isChartThreeContextCardsTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'CHART_1_TITLE'
    || sid === 'CHART_1_INSIGHT'
    || sid === 'CHART_2_TITLE'
    || sid === 'CHART_2_INSIGHT'
    || sid === 'CHART_3_TITLE'
    || sid === 'CHART_3_INSIGHT'
}

function badgeSvg() {
  const g = CTCC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.badgeW + '" height="' + g.badgeH + '" fill="#DBEAFE" rx="' + (g.badgeH/2) + '"/>' +
    '</svg>'
}

function cardBackgroundSvg() {
  const g = CTCC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.cardW + ' ' + g.cardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.cardW + '" height="' + g.cardH + '" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2" rx="12"/>' +
    '</svg>'
}

function iconCircleSvg(color) {
  const size = CTCC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + (size/2) + '" fill="' + color + '" opacity="0.1"/>' +
    '</svg>'
}

function barChartIconSvg(color) {
  const size = CTCC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<rect x="-14" y="0" width="6" height="10" fill="' + color + '" rx="1"/>' +
    '<rect x="-5" y="-8" width="6" height="18" fill="' + color + '" rx="1"/>' +
    '<rect x="4" y="-4" width="6" height="14" fill="' + color + '" rx="1"/>' +
    '</g>' +
    '</svg>'
}

function targetIconSvg(color) {
  const size = CTCC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<circle cx="0" cy="0" r="12" fill="none" stroke="' + color + '" stroke-width="2.5"/>' +
    '<circle cx="0" cy="0" r="7" fill="none" stroke="' + color + '" stroke-width="2.5"/>' +
    '<circle cx="0" cy="0" r="2.5" fill="' + color + '"/>' +
    '</g>' +
    '</svg>'
}

function peopleIconSvg(color) {
  const size = CTCC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<circle cx="-6" cy="-4" r="4" fill="' + color + '"/>' +
    '<circle cx="6" cy="-4" r="4" fill="' + color + '"/>' +
    '<circle cx="0" cy="5" r="5" fill="' + color + '"/>' +
    '</g>' +
    '</svg>'
}

function insightBoxSvg(color) {
  const g = CTCC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.insightW + ' ' + g.insightH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.insightW + '" height="' + g.insightH + '" fill="' + color + '" opacity="0.05" rx="8"/>' +
    '</svg>'
}

function insightIconCircleSvg(color) {
  const size = CTCC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + (size/2) + '" fill="' + color + '" opacity="0.15"/>' +
    '</svg>'
}

function trendUpIconSvg(color) {
  const size = CTCC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<line x1="0" y1="6" x2="0" y2="-6" stroke="' + color + '" stroke-width="2" stroke-linecap="round"/>' +
    '<polyline points="-4,-2 0,-6 4,-2" fill="none" stroke="' + color + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</g>' +
    '</svg>'
}

function chartLineIconSvg(color) {
  const size = CTCC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<polyline points="-8,4 -3,-2 3,2 8,-4" fill="none" stroke="' + color + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</g>' +
    '</svg>'
}

function checkIconSvg(color) {
  const size = CTCC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<polyline points="-5,0 -1,5 6,-5" fill="none" stroke="' + color + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</g>' +
    '</svg>'
}

function hexLum(hex) {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = function(c) { return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4) }
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette) {
  palette = palette || {}
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827'
}

function chartThreeContextCardsChromeSpecs() {
  const g = CTCC_GEOM
  const card1X = 15
  const card2X = card1X + g.cardW + g.cardGap
  const card3X = card2X + g.cardW + g.cardGap
  
  const specs = [
    // Badge
    {
      slotId: 'CTCC_BADGE',
      x: g.badgeX,
      y: g.badgeY,
      w: g.badgeW,
      h: g.badgeH,
      color: '#DBEAFE',
      layer: 5,
      kind: 'badge',
    },
  ]
  
  // Card 1
  const card1Specs = [
    { slotId: 'CTCC_CARD_1_BG', x: card1X, y: g.cardStartY, w: g.cardW, h: g.cardH, color: '#FFFFFF', layer: 3, kind: 'cardBg' },
    { slotId: 'CTCC_CARD_1_ICON_CIRCLE', x: card1X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTCC_COLORS.card1, layer: 4, kind: 'iconCircle' },
    { slotId: 'CTCC_CARD_1_ICON', x: card1X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTCC_COLORS.card1, layer: 5, kind: 'barChartIcon' },
    { slotId: 'CTCC_CARD_1_INSIGHT_BG', x: card1X + g.insightX, y: g.cardStartY + g.insightY, w: g.insightW, h: g.insightH, color: CTCC_COLORS.card1, layer: 4, kind: 'insightBox' },
    { slotId: 'CTCC_CARD_1_INSIGHT_ICON_CIRCLE', x: card1X + g.insightX + 8, y: g.cardStartY + g.insightY + 10, w: g.insightIconSize, h: g.insightIconSize, color: CTCC_COLORS.card1, layer: 5, kind: 'insightIconCircle' },
    { slotId: 'CTCC_CARD_1_INSIGHT_ICON', x: card1X + g.insightX + 8, y: g.cardStartY + g.insightY + 10, w: g.insightIconSize, h: g.insightIconSize, color: CTCC_COLORS.card1, layer: 6, kind: 'trendUpIcon' },
  ]
  
  // Card 2
  const card2Specs = [
    { slotId: 'CTCC_CARD_2_BG', x: card2X, y: g.cardStartY, w: g.cardW, h: g.cardH, color: '#FFFFFF', layer: 3, kind: 'cardBg' },
    { slotId: 'CTCC_CARD_2_ICON_CIRCLE', x: card2X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTCC_COLORS.card2, layer: 4, kind: 'iconCircle' },
    { slotId: 'CTCC_CARD_2_ICON', x: card2X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTCC_COLORS.card2, layer: 5, kind: 'targetIcon' },
    { slotId: 'CTCC_CARD_2_INSIGHT_BG', x: card2X + g.insightX, y: g.cardStartY + g.insightY, w: g.insightW, h: g.insightH, color: CTCC_COLORS.card2, layer: 4, kind: 'insightBox' },
    { slotId: 'CTCC_CARD_2_INSIGHT_ICON_CIRCLE', x: card2X + g.insightX + 8, y: g.cardStartY + g.insightY + 10, w: g.insightIconSize, h: g.insightIconSize, color: CTCC_COLORS.card2, layer: 5, kind: 'insightIconCircle' },
    { slotId: 'CTCC_CARD_2_INSIGHT_ICON', x: card2X + g.insightX + 8, y: g.cardStartY + g.insightY + 10, w: g.insightIconSize, h: g.insightIconSize, color: CTCC_COLORS.card2, layer: 6, kind: 'chartLineIcon' },
  ]
  
  // Card 3
  const card3Specs = [
    { slotId: 'CTCC_CARD_3_BG', x: card3X, y: g.cardStartY, w: g.cardW, h: g.cardH, color: '#FFFFFF', layer: 3, kind: 'cardBg' },
    { slotId: 'CTCC_CARD_3_ICON_CIRCLE', x: card3X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTCC_COLORS.card3, layer: 4, kind: 'iconCircle' },
    { slotId: 'CTCC_CARD_3_ICON', x: card3X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTCC_COLORS.card3, layer: 5, kind: 'peopleIcon' },
    { slotId: 'CTCC_CARD_3_INSIGHT_BG', x: card3X + g.insightX, y: g.cardStartY + g.insightY, w: g.insightW, h: g.insightH, color: CTCC_COLORS.card3, layer: 4, kind: 'insightBox' },
    { slotId: 'CTCC_CARD_3_INSIGHT_ICON_CIRCLE', x: card3X + g.insightX + 8, y: g.cardStartY + g.insightY + 10, w: g.insightIconSize, h: g.insightIconSize, color: CTCC_COLORS.card3, layer: 5, kind: 'insightIconCircle' },
    { slotId: 'CTCC_CARD_3_INSIGHT_ICON', x: card3X + g.insightX + 8, y: g.cardStartY + g.insightY + 10, w: g.insightIconSize, h: g.insightIconSize, color: CTCC_COLORS.card3, layer: 6, kind: 'checkIcon' },
  ]
  
  return specs.concat(card1Specs).concat(card2Specs).concat(card3Specs)
}

function chartThreeContextCardsOverlay(gx, gy, gw, gh) {
  const g = CTCC_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  function box(x, y, w, h) {
    return {
      x: Math.round(gx + x * sx),
      y: Math.round(gy + y * sy),
      width: Math.max(12, Math.round(w * sx)),
      height: Math.max(10, Math.round(h * sy)),
    }
  }
  
  const card1X = 15
  const card2X = card1X + g.cardW + g.cardGap
  const card3X = card2X + g.cardW + g.cardGap
  
  return {
    badge: box(g.badgeX, g.badgeY, g.badgeW, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    
    // Card 1
    card1_title: box(card1X + g.titleX, g.cardStartY + g.titleY, 200, 28),
    card1_chart: box(card1X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card1_insight: box(card1X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 12, 200, 32),
    
    // Card 2
    card2_title: box(card2X + g.titleX, g.cardStartY + g.titleY, 200, 28),
    card2_chart: box(card2X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card2_insight: box(card2X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 12, 200, 32),
    
    // Card 3
    card3_title: box(card3X + g.titleX, g.cardStartY + g.titleY, 200, 28),
    card3_chart: box(card3X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card3_insight: box(card3X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 12, 200, 32),
  }
}

function specToChartThreeContextCardsContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'cardBg') return { svg: cardBackgroundSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconCircle') return { svg: iconCircleSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'barChartIcon') return { svg: barChartIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'targetIcon') return { svg: targetIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'peopleIcon') return { svg: peopleIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'insightBox') return { svg: insightBoxSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'insightIconCircle') return { svg: insightIconCircleSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'trendUpIcon') return { svg: trendUpIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'chartLineIcon') return { svg: chartLineIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'checkIcon') return { svg: checkIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  return null
}

function plainTextFromContent(content) {
  content = content || {}
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map(function(r) { return r.text || '' }).join('')
    if (joined.trim()) return joined
  }
  return ''
}

function filledContent(el, slotId, style) {
  const sid = String(slotId || '')
  const existing = plainTextFromContent(el && el.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (CTCC_DEFAULTS[sid] || existing)
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

function layoutChartThreeContextCards(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CTCC_GEOM.viewW
  const sy = canvasH / CTCC_GEOM.viewH
  const overlay = chartThreeContextCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^CTCC_/i
  
  const prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })
  
  const filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isChartThreeContextCardsTextSlot(el.slotId)
  })
  const bySlot = new Map()
  filtered.forEach(function(el) {
    bySlot.set(String(el.slotId || ''), el)
  })

  function placeText(slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-ctcc'),
      type: 'text',
      slotId: slotId,
      role: (prev && prev.role) || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    placeText('BADGE', overlay.badge, {
      align: 'left', verticalAlign: 'middle', fontSize: 10, fontWeight: 600, color: '#3B82F6', clipToSlot: true, lineHeight: 1, textTransform: 'uppercase', letterSpacing: '0.05em',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 32, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    
    // Card 1
    placeText('CHART_1_TITLE', overlay.card1_title, {
      align: 'left', verticalAlign: 'top', fontSize: 18, fontWeight: 700, color: '#111827', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CHART_1_INSIGHT', overlay.card1_insight, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'),
    
    // Card 2
    placeText('CHART_2_TITLE', overlay.card2_title, {
      align: 'left', verticalAlign: 'top', fontSize: 18, fontWeight: 700, color: '#111827', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CHART_2_INSIGHT', overlay.card2_insight, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'),
    
    // Card 3
    placeText('CHART_3_TITLE', overlay.card3_title, {
      align: 'left', verticalAlign: 'top', fontSize: 18, fontWeight: 700, color: '#111827', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CHART_3_INSIGHT', overlay.card3_insight, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'),
  ]

  const chrome = chartThreeContextCardsChromeSpecs().map(function(spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartThreeContextCardsContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-ctcc'),
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
  
  // Find chart elements
  const chart1El = elements.find(function(el) { return el.slotId === 'CHART_1' })
  const chart2El = elements.find(function(el) { return el.slotId === 'CHART_2' })
  const chart3El = elements.find(function(el) { return el.slotId === 'CHART_3' })
  
  const charts = []
  if (chart1El) {
    charts.push(Object.assign({}, chart1El, {
      placement: overlay.card1_chart,
      layer: 8,
    }))
  }
  if (chart2El) {
    charts.push(Object.assign({}, chart2El, {
      placement: overlay.card2_chart,
      layer: 8,
    }))
  }
  if (chart3El) {
    charts.push(Object.assign({}, chart3El, {
      placement: overlay.card3_chart,
      layer: 8,
    }))
  }
  
  return chrome.concat(next).concat(charts)
}

module.exports = {
  isChartThreeContextCardsLayout: isChartThreeContextCardsLayout,
  layoutChartThreeContextCards: layoutChartThreeContextCards,
  CTCC_GEOM: CTCC_GEOM,
  CTCC_DEFAULTS: CTCC_DEFAULTS,
}
