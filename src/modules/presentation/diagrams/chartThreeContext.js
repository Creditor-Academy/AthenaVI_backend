/**
 * Chart three context — Custom SVG bars (3 quarters) + context panel.
 * Layout id: chart_three_context_v1.
 */

const CTXC_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Badge at top
  badgeX: 40,
  badgeY: 35,
  badgeW: 170,
  badgeH: 26,
  
  // Heading below badge
  headingX: 40,
  headingY: 75,
  headingW: 500,
  headingH: 50,
  
  // Subheading below heading
  subheadingX: 40,
  subheadingY: 132,
  subheadingW: 500,
  subheadingH: 24,
  
  // Legend (below subheading)
  legendY: 170,
  legendX: 40,
  legendDotSize: 12,
  legendGap: 110,
  
  // Chart area - more space for bars
  chartX: 40,
  chartY: 220,
  chartW: 600,
  chartH: 280,
  
  // Bar dimensions - taller, more prominent
  barWidth: 45,
  barGap: 10,
  groupGap: 55,
  barStartX: 60,
  
  // Quarter labels
  labelY: 515,
  
  // Right side - Context panel (smaller)
  panelX: 710,
  panelY: 35,
  panelW: 260,
  panelH: 490,
  
  // Inside panel - adjusted for smaller width
  panelIconX: 30,
  panelIconY: 30,
  panelIconSize: 32,
  panelHeadingX: 30,
  panelHeadingY: 75,
  contextX: 30,
  contextY: 115,
  contextW: 200,
  contextH: 90,
  
  // Metric breakdowns in panel
  metricStartY: 230,
  metricGap: 70,
  metricDotX: 30,
  metricLabelX: 50,
  metricDescX: 50,
  metricDescY: 26,
}

const CTXC_BAR_DATA = [
  // Q1 - 3 bars
  { quarter: 'Q1', metric: 'A', value: 68, height: 177, color: '#3B82F6' },
  { quarter: 'Q1', metric: 'B', value: 54, height: 140, color: '#8B5CF6' },
  { quarter: 'Q1', metric: 'C', value: 60, height: 156, color: '#10B981' },
  
  // Q2 - 3 bars
  { quarter: 'Q2', metric: 'A', value: 92, height: 239, color: '#3B82F6' },
  { quarter: 'Q2', metric: 'B', value: 88, height: 229, color: '#8B5CF6' },
  { quarter: 'Q2', metric: 'C', value: 82, height: 213, color: '#10B981' },
  
  // Q3 - 3 bars
  { quarter: 'Q3', metric: 'A', value: 76, height: 198, color: '#3B82F6' },
  { quarter: 'Q3', metric: 'B', value: 72, height: 187, color: '#8B5CF6' },
  { quarter: 'Q3', metric: 'C', value: 70, height: 182, color: '#10B981' },
]

const CTXC_COLORS = {
  metricA: '#3B82F6',
  metricB: '#8B5CF6',  
  metricC: '#10B981',
}

const CTXC_DEFAULTS = {
  BADGE: 'QUARTERLY OVERVIEW',
  HEADING: 'Quarterly',
  SUBHEADING: 'Tracking progress, performance and key milestones across each quarter.',
  LEGEND_A: 'Metric A',
  LEGEND_B: 'Metric B',
  LEGEND_C: 'Metric C',
  PANEL_HEADING: 'Context',
  CONTEXT_TEXT: 'Add your analysis, insights, and key findings about the quarterly performance here. This panel provides space for detailed explanations and observations.',
  METRIC_A_LABEL: 'Metric A',
  METRIC_A_DESC: 'Shows steady growth across all quarters, with the highest value in Q4.',
  METRIC_B_LABEL: 'Metric B',
  METRIC_B_DESC: 'Reaches its peak in Q3 and remains strong in Q4.',
  METRIC_C_LABEL: 'Metric C',
  METRIC_C_DESC: 'Consistent improvement throughout, with the highest value in Q4.',
}

function isChartThreeContextLayout(layoutId) {
  return /chart_three_context_v1$/i.test(String(layoutId || ''))
}

function isChartThreeContextTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'LEGEND_A'
    || sid === 'LEGEND_B'
    || sid === 'LEGEND_C'
    || sid === 'PANEL_HEADING'
    || sid === 'CONTEXT_TEXT'
    || sid === 'METRIC_A_LABEL'
    || sid === 'METRIC_A_DESC'
    || sid === 'METRIC_B_LABEL'
    || sid === 'METRIC_B_DESC'
    || sid === 'METRIC_C_LABEL'
    || sid === 'METRIC_C_DESC'
}

function badgeSvg() {
  const g = CTXC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.badgeW + '" height="' + g.badgeH + '" fill="#DBEAFE" rx="8"/>' +
    '</svg>'
}

function panelBgSvg() {
  const g = CTXC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.panelW + ' ' + g.panelH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.panelW + '" height="' + g.panelH + '" fill="#F0F9FF" stroke="#BFDBFE" stroke-width="2" rx="16"/>' +
    '</svg>'
}

function panelIconSvg() {
  const size = CTXC_GEOM.panelIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="5" y="9" width="26" height="22" rx="2" fill="none" stroke="#3B82F6" stroke-width="2.5"/>' +
    '<path d="M9 9 L9 6 C9 4.9 9.9 4 11 4 L25 4 C26.1 4 27 4.9 27 6 L27 9" fill="none" stroke="#3B82F6" stroke-width="2.5"/>' +
    '<line x1="11" y1="16" x2="25" y2="16" stroke="#3B82F6" stroke-width="2.5" stroke-linecap="round"/>' +
    '<line x1="11" y1="22" x2="20" y2="22" stroke="#3B82F6" stroke-width="2.5" stroke-linecap="round"/>' +
    '</svg>'
}

function barSvg(width, height, color) {
  var colorId = color.replace('#','')
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + width + ' ' + height + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
    '<linearGradient id="barGrad_' + colorId + '" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:' + color + ';stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:' + color + ';stop-opacity:0.85" />' +
    '</linearGradient>' +
    '</defs>' +
    '<rect x="0" y="0" width="' + width + '" height="' + height + '" fill="url(#barGrad_' + colorId + ')" rx="6"/>' +
    '</svg>'
}

function legendDotSvg(color) {
  const size = CTXC_GEOM.legendDotSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + (size/2) + '" fill="' + color + '"/>' +
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
  const specs = []
  
  // Badge background
  specs.push({
    slotId: 'CTXC_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: '#DBEAFE',
    layer: 3,
    kind: 'badge',
  })
  
  // Panel background
  specs.push({
    slotId: 'CTXC_PANEL_BG',
    x: g.panelX,
    y: g.panelY,
    w: g.panelW,
    h: g.panelH,
    color: '#EFF6FF',
    layer: 3,
    kind: 'panelBg',
  })
  
  // Panel icon
  specs.push({
    slotId: 'CTXC_PANEL_ICON',
    x: g.panelX + g.panelIconX,
    y: g.panelY + g.panelIconY,
    w: g.panelIconSize,
    h: g.panelIconSize,
    color: '#3B82F6',
    layer: 10,
    kind: 'panelIcon',
  })
  
  // Legend dots (top legend)
  specs.push({
    slotId: 'CTXC_LEGEND_DOT_A',
    x: g.legendX,
    y: g.legendY + 5,
    w: g.legendDotSize,
    h: g.legendDotSize,
    color: CTXC_COLORS.metricA,
    layer: 10,
    kind: 'legendDot',
  })
  specs.push({
    slotId: 'CTXC_LEGEND_DOT_B',
    x: g.legendX + g.legendGap,
    y: g.legendY + 5,
    w: g.legendDotSize,
    h: g.legendDotSize,
    color: CTXC_COLORS.metricB,
    layer: 10,
    kind: 'legendDot',
  })
  specs.push({
    slotId: 'CTXC_LEGEND_DOT_C',
    x: g.legendX + g.legendGap * 2,
    y: g.legendY + 5,
    w: g.legendDotSize,
    h: g.legendDotSize,
    color: CTXC_COLORS.metricC,
    layer: 10,
    kind: 'legendDot',
  })
  
  // Metric breakdown dots in panel
  specs.push({
    slotId: 'CTXC_METRIC_DOT_A',
    x: g.panelX + g.metricDotX,
    y: g.panelY + g.metricStartY + 5,
    w: g.legendDotSize,
    h: g.legendDotSize,
    color: CTXC_COLORS.metricA,
    layer: 10,
    kind: 'legendDot',
  })
  specs.push({
    slotId: 'CTXC_METRIC_DOT_B',
    x: g.panelX + g.metricDotX,
    y: g.panelY + g.metricStartY + g.metricGap + 5,
    w: g.legendDotSize,
    h: g.legendDotSize,
    color: CTXC_COLORS.metricB,
    layer: 10,
    kind: 'legendDot',
  })
  specs.push({
    slotId: 'CTXC_METRIC_DOT_C',
    x: g.panelX + g.metricDotX,
    y: g.panelY + g.metricStartY + g.metricGap * 2 + 5,
    w: g.legendDotSize,
    h: g.legendDotSize,
    color: CTXC_COLORS.metricC,
    layer: 10,
    kind: 'legendDot',
  })
  
  // CUSTOM SVG BARS (9 bars total - 3 per quarter)
  CTXC_BAR_DATA.forEach(function(bar, i) {
    const quarterIndex = Math.floor(i / 3)
    const barInGroup = i % 3
    const groupStartX = g.barStartX + quarterIndex * (3 * g.barWidth + 2 * g.barGap + g.groupGap)
    const x = groupStartX + barInGroup * (g.barWidth + g.barGap)
    const y = g.chartY + g.chartH - bar.height
    
    specs.push({
      slotId: 'CTXC_BAR_' + (i + 1),
      x: x,
      y: y,
      w: g.barWidth,
      h: bar.height,
      color: bar.color,
      layer: 6,
      kind: 'bar',
      barData: bar,
    })
  })
  
  return specs
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
  
  const overlays = {
    badge: box(g.badgeX, g.badgeY, g.badgeW, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
    
    // Top legend labels
    legendA: box(g.legendX + g.legendDotSize + 10, g.legendY, 90, 22),
    legendB: box(g.legendX + g.legendGap + g.legendDotSize + 10, g.legendY, 90, 22),
    legendC: box(g.legendX + g.legendGap * 2 + g.legendDotSize + 10, g.legendY, 90, 22),
    
    // Context panel
    panelHeading: box(g.panelX + g.panelHeadingX, g.panelY + g.panelHeadingY, 200, 32),
    contextText: box(g.panelX + g.contextX, g.panelY + g.contextY, g.contextW, g.contextH),
    
    // Metric breakdowns in panel
    metricALabel: box(g.panelX + g.metricLabelX, g.panelY + g.metricStartY, 180, 22),
    metricADesc: box(g.panelX + g.metricDescX, g.panelY + g.metricStartY + g.metricDescY, 180, 36),
    metricBLabel: box(g.panelX + g.metricLabelX, g.panelY + g.metricStartY + g.metricGap, 180, 22),
    metricBDesc: box(g.panelX + g.metricDescX, g.panelY + g.metricStartY + g.metricGap + g.metricDescY, 180, 36),
    metricCLabel: box(g.panelX + g.metricLabelX, g.panelY + g.metricStartY + g.metricGap * 2, 180, 22),
    metricCDesc: box(g.panelX + g.metricDescX, g.panelY + g.metricStartY + g.metricGap * 2 + g.metricDescY, 180, 36),
  }
  
  return overlays
}

function specToChartThreeContextContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelBg') return { svg: panelBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIcon') return { svg: panelIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'legendDot') return { svg: legendDotSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'bar') return { svg: barSvg(spec.w, spec.h, spec.color), colorMode: 'fixed', fill: spec.color }
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
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: '#2563EB', clipToSlot: true, lineHeight: 1, letterSpacing: '0.8px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 44, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.4,
    }, 'subheading'),
    
    // Top legend labels
    placeText('LEGEND_A', overlay.legendA, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#475569', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('LEGEND_B', overlay.legendB, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#475569', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('LEGEND_C', overlay.legendC, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#475569', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    
    // Context panel
    placeText('PANEL_HEADING', overlay.panelHeading, {
      align: 'left', verticalAlign: 'top', fontSize: 24, fontWeight: 700, color: '#0F172A', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CONTEXT_TEXT', overlay.contextText, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.6, wrap: 'wrap',
    }, 'body'),
    
    // Metric breakdowns in panel
    placeText('METRIC_A_LABEL', overlay.metricALabel, {
      align: 'left', verticalAlign: 'center', fontSize: 16, fontWeight: 700, color: '#0F172A', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('METRIC_A_DESC', overlay.metricADesc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    placeText('METRIC_B_LABEL', overlay.metricBLabel, {
      align: 'left', verticalAlign: 'center', fontSize: 16, fontWeight: 700, color: '#0F172A', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('METRIC_B_DESC', overlay.metricBDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    placeText('METRIC_C_LABEL', overlay.metricCLabel, {
      align: 'left', verticalAlign: 'center', fontSize: 16, fontWeight: 700, color: '#0F172A', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('METRIC_C_DESC', overlay.metricCDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
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
  
  return chrome.concat(next)
}

module.exports = {
  isChartThreeContextLayout: isChartThreeContextLayout,
  layoutChartThreeContext: layoutChartThreeContext,
  CTXC_GEOM: CTXC_GEOM,
  CTXC_DEFAULTS: CTXC_DEFAULTS,
}
