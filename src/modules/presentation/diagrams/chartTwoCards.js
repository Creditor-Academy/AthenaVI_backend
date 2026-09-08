/**
 * Chart two cards — side-by-side metric cards with icons, charts, and growth indicators.
 * Layout id: chart_two_cards_v1.
 */

const CTC_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Badge at top
  badgeX: 400,
  badgeY: 25,
  badgeW: 200,
  badgeH: 25,
  
  // Heading section
  headingX: 100,
  headingY: 60,
  headingW: 800,
  headingH: 50,
  
  subheadingX: 100,
  subheadingY: 115,
  subheadingW: 800,
  subheadingH: 30,
  
  // Card dimensions
  cardGap: 30,
  cardStartY: 170,
  cardW: 470,
  cardH: 350,
  
  // Inside each card
  iconSize: 56,
  iconX: 30,
  iconY: 30,
  
  titleX: 100,
  titleY: 35,
  descX: 100,
  descY: 65,
  
  growthX: 400,
  growthY: 35,
  growthW: 60,
  growthH: 30,
  
  // Chart area in card
  chartX: 30,
  chartY: 120,
  chartW: 410,
  chartH: 200,
}

const CTC_DEFAULTS = {
  BADGE: 'PERFORMANCE OVERVIEW',
  HEADING: 'Two Metrics Comparison',
  SUBHEADING: 'A side-by-side look at how the two metrics perform across four key periods.',
  CHART_1_TITLE: 'Metric A',
  CHART_1_DESC: 'This is a sample description for metric A.',
  CHART_1_GROWTH: '+12%',
  CHART_1_CAPTION: 'Performance trend over quarters',
  CHART_2_TITLE: 'Metric B',
  CHART_2_DESC: 'This is a sample description for metric B.',
  CHART_2_GROWTH: '+8%',
  CHART_2_CAPTION: 'Performance trend over quarters',
}

function isChartTwoCardsLayout(layoutId) {
  return /chart_two_cards_v1$/i.test(String(layoutId || ''))
}

function isChartTwoCardsTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'CHART_1_TITLE'
    || sid === 'CHART_1_DESC'
    || sid === 'CHART_1_GROWTH'
    || sid === 'CHART_1_CAPTION'
    || sid === 'CHART_2_TITLE'
    || sid === 'CHART_2_DESC'
    || sid === 'CHART_2_GROWTH'
    || sid === 'CHART_2_CAPTION'
}

function badgeSvg() {
  const g = CTC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.badgeW + '" height="' + g.badgeH + '" fill="#DBEAFE" rx="' + (g.badgeH/2) + '"/>' +
    '</svg>'
}

function cardBackgroundSvg() {
  const g = CTC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.cardW + ' ' + g.cardH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.cardW + '" height="' + g.cardH + '" fill="#F9FAFB" stroke="#E5E7EB" stroke-width="1" rx="16"/>' +
    '</svg>'
}

function iconCircleSvg(color) {
  const size = CTC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + (size/2) + '" fill="' + color + '" opacity="0.15"/>' +
    '</svg>'
}

function chartIconSvg(color) {
  const size = CTC_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<rect x="-12" y="-8" width="5" height="12" fill="' + color + '" rx="1"/>' +
    '<rect x="-4" y="-12" width="5" height="16" fill="' + color + '" rx="1"/>' +
    '<rect x="4" y="-4" width="5" height="8" fill="' + color + '" rx="1"/>' +
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

function chartTwoCardsChromeSpecs() {
  const g = CTC_GEOM
  const card1X = 20
  const card2X = card1X + g.cardW + g.cardGap
  
  return [
    // Badge
    {
      slotId: 'CTC_BADGE',
      x: g.badgeX,
      y: g.badgeY,
      w: g.badgeW,
      h: g.badgeH,
      color: '#DBEAFE',
      layer: 5,
      kind: 'badge',
    },
    // Card 1 background
    {
      slotId: 'CTC_CARD_1_BG',
      x: card1X,
      y: g.cardStartY,
      w: g.cardW,
      h: g.cardH,
      color: '#F9FAFB',
      layer: 3,
      kind: 'cardBg',
    },
    // Card 1 icon circle
    {
      slotId: 'CTC_CARD_1_ICON_CIRCLE',
      x: card1X + g.iconX,
      y: g.cardStartY + g.iconY,
      w: g.iconSize,
      h: g.iconSize,
      color: '#3B82F6',
      layer: 4,
      kind: 'iconCircle',
    },
    // Card 1 icon
    {
      slotId: 'CTC_CARD_1_ICON',
      x: card1X + g.iconX,
      y: g.cardStartY + g.iconY,
      w: g.iconSize,
      h: g.iconSize,
      color: '#3B82F6',
      layer: 5,
      kind: 'chartIcon',
    },
    // Card 2 background
    {
      slotId: 'CTC_CARD_2_BG',
      x: card2X,
      y: g.cardStartY,
      w: g.cardW,
      h: g.cardH,
      color: '#F9FAFB',
      layer: 3,
      kind: 'cardBg',
    },
    // Card 2 icon circle
    {
      slotId: 'CTC_CARD_2_ICON_CIRCLE',
      x: card2X + g.iconX,
      y: g.cardStartY + g.iconY,
      w: g.iconSize,
      h: g.iconSize,
      color: '#8B5CF6',
      layer: 4,
      kind: 'iconCircle',
    },
    // Card 2 icon
    {
      slotId: 'CTC_CARD_2_ICON',
      x: card2X + g.iconX,
      y: g.cardStartY + g.iconY,
      w: g.iconSize,
      h: g.iconSize,
      color: '#8B5CF6',
      layer: 5,
      kind: 'chartIcon',
    },
  ]
}

function chartTwoCardsOverlay(gx, gy, gw, gh) {
  const g = CTC_GEOM
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
  
  const card1X = 20
  const card2X = card1X + g.cardW + g.cardGap
  
  return {
    badge: box(g.badgeX, g.badgeY, g.badgeW, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
    
    // Card 1
    card1_title: box(card1X + g.titleX, g.cardStartY + g.titleY, 250, 25),
    card1_desc: box(card1X + g.descX, g.cardStartY + g.descY, 250, 20),
    card1_growth: box(card1X + g.growthX, g.cardStartY + g.growthY, g.growthW, g.growthH),
    card1_chart: box(card1X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card1_caption: box(card1X + g.chartX, g.cardStartY + g.chartY + g.chartH + 5, g.chartW, 20),
    
    // Card 2
    card2_title: box(card2X + g.titleX, g.cardStartY + g.titleY, 250, 25),
    card2_desc: box(card2X + g.descX, g.cardStartY + g.descY, 250, 20),
    card2_growth: box(card2X + g.growthX, g.cardStartY + g.growthY, g.growthW, g.growthH),
    card2_chart: box(card2X + g.chartX, g.cardStartY + g.chartY, g.chartW, g.chartH),
    card2_caption: box(card2X + g.chartX, g.cardStartY + g.chartY + g.chartH + 5, g.chartW, 20),
  }
}

function specToChartTwoCardsContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'cardBg') return { svg: cardBackgroundSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconCircle') return { svg: iconCircleSvg(spec.color), colorMode: 'fixed', fill: 'none' }
  if (spec.kind === 'chartIcon') return { svg: chartIconSvg(spec.color), colorMode: 'fixed', fill: 'none' }
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
    : (CTC_DEFAULTS[sid] || existing)
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

function layoutChartTwoCards(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CTC_GEOM.viewW
  const sy = canvasH / CTC_GEOM.viewH
  const overlay = chartTwoCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^CTC_/i
  
  const prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })
  
  const filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isChartTwoCardsTextSlot(el.slotId)
  })
  const bySlot = new Map()
  filtered.forEach(function(el) {
    bySlot.set(String(el.slotId || ''), el)
  })

  function placeText(slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-ctc'),
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
      align: 'center', verticalAlign: 'middle', fontSize: 11, fontWeight: 600, color: '#3B82F6', clipToSlot: true, lineHeight: 1, textTransform: 'uppercase', letterSpacing: '0.05em',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'center', verticalAlign: 'top', fontSize: 42, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'center', verticalAlign: 'top', fontSize: 15, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4,
    }, 'subheading'),
    
    // Card 1
    placeText('CHART_1_TITLE', overlay.card1_title, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: '#111827', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CHART_1_DESC', overlay.card1_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3,
    }, 'body'),
    placeText('CHART_1_GROWTH', overlay.card1_growth, {
      align: 'right', verticalAlign: 'middle', fontSize: 16, fontWeight: 600, color: '#10B981', clipToSlot: true, lineHeight: 1,
    }, 'stat'),
    placeText('CHART_1_CAPTION', overlay.card1_caption, {
      align: 'center', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#9CA3AF', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    
    // Card 2
    placeText('CHART_2_TITLE', overlay.card2_title, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: '#111827', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CHART_2_DESC', overlay.card2_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3,
    }, 'body'),
    placeText('CHART_2_GROWTH', overlay.card2_growth, {
      align: 'right', verticalAlign: 'middle', fontSize: 16, fontWeight: 600, color: '#10B981', clipToSlot: true, lineHeight: 1,
    }, 'stat'),
    placeText('CHART_2_CAPTION', overlay.card2_caption, {
      align: 'center', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#9CA3AF', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
  ]

  const chrome = chartTwoCardsChromeSpecs().map(function(spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartTwoCardsContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-ctc'),
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
  
  return chrome.concat(next).concat(charts)
}

module.exports = {
  isChartTwoCardsLayout: isChartTwoCardsLayout,
  layoutChartTwoCards: layoutChartTwoCards,
  CTC_GEOM: CTC_GEOM,
  CTC_DEFAULTS: CTC_DEFAULTS,
}
