/**
 * Chart three context — three quarterly cards with icons, charts, and insights.
 * Layout id: chart_three_context_v1.
 */

const CTXC_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Badge at top
  badgeX: 50,
  badgeY: 20,
  badgeW: 180,
  badgeH: 22,
  
  // Heading section
  headingX: 50,
  headingY: 50,
  headingW: 900,
  headingH: 50,
  
  subheadingX: 50,
  subheadingY: 105,
  subheadingW: 900,
  subheadingH: 25,
  
  // Card dimensions
  cardStartY: 150,
  cardW: 305,  // Increased from 290 (little bit wider)
  cardH: 380,
  cardGap: 25,  // Reduced gap slightly to compensate
  
  // Inside each card
  iconSize: 52,
  iconX: 35,
  iconY: 30,
  
  quarterX: 100,
  quarterY: 35,
  subtitleX: 100,
  subtitleY: 60,  // Moved down slightly to prevent clipping
  
  descX: 35,
  descY: 95,
  descW: 230,
  descH: 70,
  
  // Chart in card
  chartX: 35,
  chartY: 175,
  chartW: 230,
  chartH: 110,
  
  // Insight box at bottom
  insightX: 35,
  insightY: 300,
  insightW: 230,
  insightH: 65,
  insightIconSize: 40,
  insightTextX: 50,
}

const CTXC_COLORS = {
  card1: '#3B82F6',  // Blue
  card2: '#8B5CF6',  // Purple
  card3: '#10B981',  // Teal/Green
}

const CTXC_DEFAULTS = {
  BADGE: 'QUARTERLY OVERVIEW',
  HEADING: 'Quarterly Breakdown',
  SUBHEADING: 'Tracking progress, performance and key milestones across each quarter.',
  
  CARD_1_QUARTER: 'Q1',
  CARD_1_SUBTITLE: 'FOUNDATION & FOCUS',
  CARD_1_DESC: 'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.',
  CARD_1_INSIGHT_TITLE: 'Strong start',
  CARD_1_INSIGHT_DESC: 'Momentum built across all key areas this quarter.',
  
  CARD_2_QUARTER: 'Q2',
  CARD_2_SUBTITLE: 'GROWTH & EXPANSION',
  CARD_2_DESC: 'Our approach combines research, design, and storytelling so every slide earns attention and every message lands with precision.',
  CARD_2_INSIGHT_TITLE: 'Steady growth',
  CARD_2_INSIGHT_DESC: 'Consistent improvement across all quarters.',
  
  CARD_3_QUARTER: 'Q3',
  CARD_3_SUBTITLE: 'DELIVERY & IMPACT',
  CARD_3_DESC: 'From first draft to final delivery, we keep copy concise, visual, and aligned to your audience and goals.',
  CARD_3_INSIGHT_TITLE: 'High impact',
  CARD_3_INSIGHT_DESC: 'Delivered strong results and higher engagement.',
}

function isChartThreeContextLayout(layoutId) {
  return /chart_three_context_v1$/i.test(String(layoutId || ''))
}

function isChartThreeContextTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'CARD_1_QUARTER'
    || sid === 'CARD_1_SUBTITLE'
    || sid === 'CARD_1_DESC'
    || sid === 'CARD_1_INSIGHT_TITLE'
    || sid === 'CARD_1_INSIGHT_DESC'
    || sid === 'CARD_2_QUARTER'
    || sid === 'CARD_2_SUBTITLE'
    || sid === 'CARD_2_DESC'
    || sid === 'CARD_2_INSIGHT_TITLE'
    || sid === 'CARD_2_INSIGHT_DESC'
    || sid === 'CARD_3_QUARTER'
    || sid === 'CARD_3_SUBTITLE'
    || sid === 'CARD_3_DESC'
    || sid === 'CARD_3_INSIGHT_TITLE'
    || sid === 'CARD_3_INSIGHT_DESC'
}

function badgeSvg() {
  const g = CTXC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.badgeW + '" height="' + g.badgeH + '" fill="#DBEAFE" rx="' + (g.badgeH/2) + '"/>' +
    '</svg>'
}

function cardBackgroundSvg(color) {
  const g = CTXC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.cardW + ' ' + g.cardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.cardW + '" height="' + g.cardH + '" fill="' + color + '" rx="12"/>' +
    '</svg>'
}

function iconCircleSvg(color) {
  const size = CTXC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + (size/2) + '" fill="' + color + '" opacity="0.1"/>' +
    '</svg>'
}

function targetIconSvg(color) {
  const size = CTXC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<circle cx="0" cy="0" r="14" fill="none" stroke="' + color + '" stroke-width="2.5"/>' +
    '<circle cx="0" cy="0" r="8" fill="none" stroke="' + color + '" stroke-width="2.5"/>' +
    '<circle cx="0" cy="0" r="3" fill="' + color + '"/>' +
    '</g>' +
    '</svg>'
}

function bulbIconSvg(color) {
  const size = CTXC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<path d="M -6 8 L -6 12 L 6 12 L 6 8 M -4 12 L -4 14 L 4 14 L 4 12" fill="' + color + '"/>' +
    '<circle cx="0" cy="-2" r="10" fill="none" stroke="' + color + '" stroke-width="2.5"/>' +
    '<line x1="0" y1="-14" x2="0" y2="-16" stroke="' + color + '" stroke-width="2" stroke-linecap="round"/>' +
    '</g>' +
    '</svg>'
}

function groupIconSvg(color) {
  const size = CTXC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<circle cx="-7" cy="-4" r="5" fill="' + color + '"/>' +
    '<circle cx="7" cy="-4" r="5" fill="' + color + '"/>' +
    '<circle cx="0" cy="6" r="6" fill="' + color + '"/>' +
    '</g>' +
    '</svg>'
}

function insightBoxSvg(color) {
  const g = CTXC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.insightW + ' ' + g.insightH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.insightW + '" height="' + g.insightH + '" fill="' + color + '" opacity="0.08" rx="8"/>' +
    '</svg>'
}

function insightIconCircleSvg(color) {
  const size = CTXC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + (size/2) + '" fill="' + color + '" opacity="0.15"/>' +
    '</svg>'
}

function arrowUpIconSvg(color) {
  const size = CTXC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<line x1="0" y1="8" x2="0" y2="-8" stroke="' + color + '" stroke-width="2.5" stroke-linecap="round"/>' +
    '<polyline points="-5,-3 0,-8 5,-3" fill="none" stroke="' + color + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</g>' +
    '</svg>'
}

function chartIconSvg(color) {
  const size = CTXC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<rect x="-8" y="2" width="4" height="6" fill="' + color + '" rx="1"/>' +
    '<rect x="-2" y="-4" width="4" height="12" fill="' + color + '" rx="1"/>' +
    '<rect x="4" y="-2" width="4" height="10" fill="' + color + '" rx="1"/>' +
    '</g>' +
    '</svg>'
}

function checkIconSvg(color) {
  const size = CTXC_GEOM.insightIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<polyline points="-6,0 -2,6 8,-6" fill="none" stroke="' + color + '" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>' +
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

function chartThreeContextChromeSpecs() {
  const g = CTXC_GEOM
  const card1X = 15  // Start even closer to edge for better centering
  const card2X = card1X + g.cardW + g.cardGap
  const card3X = card2X + g.cardW + g.cardGap
  
  const specs = [
    // Badge
    {
      slotId: 'CTXC_BADGE',
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
    { slotId: 'CTXC_CARD_1_BG', x: card1X, y: g.cardStartY, w: g.cardW, h: g.cardH, color: '#EFF6FF', layer: 3, kind: 'cardBg' },
    { slotId: 'CTXC_CARD_1_ICON_CIRCLE', x: card1X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTXC_COLORS.card1, layer: 4, kind: 'iconCircle' },
    { slotId: 'CTXC_CARD_1_ICON', x: card1X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTXC_COLORS.card1, layer: 5, kind: 'targetIcon' },
    { slotId: 'CTXC_CARD_1_INSIGHT_BG', x: card1X + g.insightX, y: g.cardStartY + g.insightY, w: g.insightW, h: g.insightH, color: CTXC_COLORS.card1, layer: 4, kind: 'insightBox' },
    { slotId: 'CTXC_CARD_1_INSIGHT_ICON_CIRCLE', x: card1X + g.insightX + 10, y: g.cardStartY + g.insightY + 12, w: g.insightIconSize, h: g.insightIconSize, color: CTXC_COLORS.card1, layer: 5, kind: 'insightIconCircle' },
    { slotId: 'CTXC_CARD_1_INSIGHT_ICON', x: card1X + g.insightX + 10, y: g.cardStartY + g.insightY + 12, w: g.insightIconSize, h: g.insightIconSize, color: CTXC_COLORS.card1, layer: 6, kind: 'arrowUpIcon' },
  ]
  
  // Card 2
  const card2Specs = [
    { slotId: 'CTXC_CARD_2_BG', x: card2X, y: g.cardStartY, w: g.cardW, h: g.cardH, color: '#F5F3FF', layer: 3, kind: 'cardBg' },
    { slotId: 'CTXC_CARD_2_ICON_CIRCLE', x: card2X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTXC_COLORS.card2, layer: 4, kind: 'iconCircle' },
    { slotId: 'CTXC_CARD_2_ICON', x: card2X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTXC_COLORS.card2, layer: 5, kind: 'bulbIcon' },
    { slotId: 'CTXC_CARD_2_INSIGHT_BG', x: card2X + g.insightX, y: g.cardStartY + g.insightY, w: g.insightW, h: g.insightH, color: CTXC_COLORS.card2, layer: 4, kind: 'insightBox' },
    { slotId: 'CTXC_CARD_2_INSIGHT_ICON_CIRCLE', x: card2X + g.insightX + 10, y: g.cardStartY + g.insightY + 12, w: g.insightIconSize, h: g.insightIconSize, color: CTXC_COLORS.card2, layer: 5, kind: 'insightIconCircle' },
    { slotId: 'CTXC_CARD_2_INSIGHT_ICON', x: card2X + g.insightX + 10, y: g.cardStartY + g.insightY + 12, w: g.insightIconSize, h: g.insightIconSize, color: CTXC_COLORS.card2, layer: 6, kind: 'chartIcon' },
  ]
  
  // Card 3
  const card3Specs = [
    { slotId: 'CTXC_CARD_3_BG', x: card3X, y: g.cardStartY, w: g.cardW, h: g.cardH, color: '#ECFDF5', layer: 3, kind: 'cardBg' },
    { slotId: 'CTXC_CARD_3_ICON_CIRCLE', x: card3X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTXC_COLORS.card3, layer: 4, kind: 'iconCircle' },
    { slotId: 'CTXC_CARD_3_ICON', x: card3X + g.iconX, y: g.cardStartY + g.iconY, w: g.iconSize, h: g.iconSize, color: CTXC_COLORS.card3, layer: 5, kind: 'groupIcon' },
    { slotId: 'CTXC_CARD_3_INSIGHT_BG', x: card3X + g.insightX, y: g.cardStartY + g.insightY, w: g.insightW, h: g.insightH, color: CTXC_COLORS.card3, layer: 4, kind: 'insightBox' },
    { slotId: 'CTXC_CARD_3_INSIGHT_ICON_CIRCLE', x: card3X + g.insightX + 10, y: g.cardStartY + g.insightY + 12, w: g.insightIconSize, h: g.insightIconSize, color: CTXC_COLORS.card3, layer: 5, kind: 'insightIconCircle' },
    { slotId: 'CTXC_CARD_3_INSIGHT_ICON', x: card3X + g.insightX + 10, y: g.cardStartY + g.insightY + 12, w: g.insightIconSize, h: g.insightIconSize, color: CTXC_COLORS.card3, layer: 6, kind: 'checkIcon' },
  ]
  
  return specs.concat(card1Specs).concat(card2Specs).concat(card3Specs)
}

function chartThreeContextOverlay(gx, gy, gw, gh) {
  const g = CTXC_GEOM
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
  
  const card1X = 15  // Match the chrome specs
  const card2X = card1X + g.cardW + g.cardGap
  const card3X = card2X + g.cardW + g.cardGap
  
  return {
    badge: box(g.badgeX, g.badgeY, g.badgeW, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
    
    // Card 1
    card1_quarter: box(card1X + g.quarterX, g.cardStartY + g.quarterY, 180, 24),  // Wider and taller
    card1_subtitle: box(card1X + g.subtitleX, g.cardStartY + g.subtitleY, 180, 20),  // Wider
    card1_desc: box(card1X + g.descX, g.cardStartY + g.descY, g.descW, g.descH),
    card1_chart: box(card1X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card1_insight_title: box(card1X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 15, 170, 18),
    card1_insight_desc: box(card1X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 35, 170, 22),
    
    // Card 2
    card2_quarter: box(card2X + g.quarterX, g.cardStartY + g.quarterY, 180, 24),  // Wider and taller
    card2_subtitle: box(card2X + g.subtitleX, g.cardStartY + g.subtitleY, 180, 20),  // Wider
    card2_desc: box(card2X + g.descX, g.cardStartY + g.descY, g.descW, g.descH),
    card2_chart: box(card2X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card2_insight_title: box(card2X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 15, 170, 18),
    card2_insight_desc: box(card2X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 35, 170, 22),
    
    // Card 3
    card3_quarter: box(card3X + g.quarterX, g.cardStartY + g.quarterY, 180, 24),  // Wider and taller
    card3_subtitle: box(card3X + g.subtitleX, g.cardStartY + g.subtitleY, 180, 20),  // Wider
    card3_desc: box(card3X + g.descX, g.cardStartY + g.descY, g.descW, g.descH),
    card3_chart: box(card3X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card3_insight_title: box(card3X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 15, 170, 18),
    card3_insight_desc: box(card3X + g.insightX + g.insightTextX, g.cardStartY + g.insightY + 35, 170, 22),
  }
}

function specToChartThreeContextContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'cardBg') return { svg: cardBackgroundSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconCircle') return { svg: iconCircleSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'targetIcon') return { svg: targetIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'bulbIcon') return { svg: bulbIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'groupIcon') return { svg: groupIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'insightBox') return { svg: insightBoxSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'insightIconCircle') return { svg: insightIconCircleSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'arrowUpIcon') return { svg: arrowUpIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'chartIcon') return { svg: chartIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
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
    : (CTXC_DEFAULTS[sid] || existing)
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

function layoutChartThreeContext(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CTXC_GEOM.viewW
  const sy = canvasH / CTXC_GEOM.viewH
  const overlay = chartThreeContextOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^CTXC_/i
  
  const prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })
  
  const filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isChartThreeContextTextSlot(el.slotId)
  })
  const bySlot = new Map()
  filtered.forEach(function(el) {
    bySlot.set(String(el.slotId || ''), el)
  })

  function placeText(slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-ctxc'),
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
      align: 'left', verticalAlign: 'top', fontSize: 42, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4,
    }, 'subheading'),
    
    // Card 1
    placeText('CARD_1_QUARTER', overlay.card1_quarter, {
      align: 'left', verticalAlign: 'top', fontSize: 24, fontWeight: 700, color: CTXC_COLORS.card1, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('CARD_1_SUBTITLE', overlay.card1_subtitle, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 700, color: CTXC_COLORS.card1, clipToSlot: true, lineHeight: 1, textTransform: 'uppercase', letterSpacing: '0.05em',
    }, 'caption'),
    placeText('CARD_1_DESC', overlay.card1_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'),
    placeText('CARD_1_INSIGHT_TITLE', overlay.card1_insight_title, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 700, color: CTXC_COLORS.card1, clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CARD_1_INSIGHT_DESC', overlay.card1_insight_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'),
    
    // Card 2
    placeText('CARD_2_QUARTER', overlay.card2_quarter, {
      align: 'left', verticalAlign: 'top', fontSize: 24, fontWeight: 700, color: CTXC_COLORS.card2, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('CARD_2_SUBTITLE', overlay.card2_subtitle, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 700, color: CTXC_COLORS.card2, clipToSlot: true, lineHeight: 1, textTransform: 'uppercase', letterSpacing: '0.05em',
    }, 'caption'),
    placeText('CARD_2_DESC', overlay.card2_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'),
    placeText('CARD_2_INSIGHT_TITLE', overlay.card2_insight_title, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 700, color: CTXC_COLORS.card2, clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CARD_2_INSIGHT_DESC', overlay.card2_insight_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'),
    
    // Card 3
    placeText('CARD_3_QUARTER', overlay.card3_quarter, {
      align: 'left', verticalAlign: 'top', fontSize: 24, fontWeight: 700, color: CTXC_COLORS.card3, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('CARD_3_SUBTITLE', overlay.card3_subtitle, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 700, color: CTXC_COLORS.card3, clipToSlot: true, lineHeight: 1, textTransform: 'uppercase', letterSpacing: '0.05em',
    }, 'caption'),
    placeText('CARD_3_DESC', overlay.card3_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'),
    placeText('CARD_3_INSIGHT_TITLE', overlay.card3_insight_title, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 700, color: CTXC_COLORS.card3, clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CARD_3_INSIGHT_DESC', overlay.card3_insight_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'),
  ]

  const chrome = chartThreeContextChromeSpecs().map(function(spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartThreeContextContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-ctxc'),
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
  isChartThreeContextLayout: isChartThreeContextLayout,
  layoutChartThreeContext: layoutChartThreeContext,
  CTXC_GEOM: CTXC_GEOM,
  CTXC_DEFAULTS: CTXC_DEFAULTS,
}
