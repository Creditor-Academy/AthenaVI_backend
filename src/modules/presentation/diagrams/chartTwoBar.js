/**
 * Chart two bar — grouped/clustered bar chart with two series comparison.
 * Layout id: chart_two_v1.
 * Backend CommonJS version.
 */

const CTB_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 100,
  headingY: 20,
  headingW: 600,
  headingH: 60,
  // Bar chart area - FULL WIDTH
  chartX: 100,
  chartY: 140,
  chartW: 800,
  chartH: 360,
  groupCount: 6,  // Number of groups (x-axis categories)
  barPadding: 8,  // Space between bars in a group
  groupPadding: 30,  // Space between groups
  // Legend (top-right of chart area)
  legendX: 700,
  legendY: 95,  // Moved up from 110
  legendW: 300,
  legendH: 25,
  legendBoxSize: 14,
  // Accent bar (left edge)
  accentW: 6,
  accentH: 380,
  accentY: 120,
}

const CTB_PALETTE = {
  series1: '#1E40AF',  // Dark blue
  series2: '#8B5CF6',  // Purple
}

const CTB_DEFAULTS = {
  HEADING: 'Revenue vs Forecast',
  LEGEND_1: 'Revenue',
  LEGEND_2: 'Forecast',
}

function isChartTwoBarLayout(layoutId) {
  return /chart_two_v1$/i.test(String(layoutId || ''))
}

function isChartTwoBarTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'LEGEND_1'
    || sid === 'LEGEND_2'
}

function accentBarSvg() {
  const g = CTB_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.accentW} ${g.accentH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.accentW}" height="${g.accentH}" fill="currentColor" rx="2"/>
  </svg>`
}

function gridLinesSvg() {
  const g = CTB_GEOM
  const lines = []
  const steps = 5
  for (let i = 0; i <= steps; i += 1) {
    const y = (g.chartH / steps) * i
    lines.push(`<line x1="0" y1="${y}" x2="${g.chartW}" y2="${y}" stroke="#E5E7EB" stroke-width="1"/>`)
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.chartW} ${g.chartH}" width="100%" height="100%" preserveAspectRatio="none">
    ${lines.join('\n    ')}
  </svg>`
}

function barSvg(spec) {
  const w = spec.w
  const h = spec.h
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="currentColor" rx="2"/>
  </svg>`
}

function legendBoxSvg() {
  const size = CTB_GEOM.legendBoxSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="0" y="0" width="${size}" height="${size}" fill="currentColor" rx="2"/>
  </svg>`
}

function hexLum(hex) {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4))
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette = {}) {
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && palette.colors.bg) || (palette.colors && palette.colors.background) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827'
}

function chartTwoBarChromeSpecs(chartData = {}) {
  const g = CTB_GEOM
  const data = chartData || {}
  
  // Default data: 6 groups, 2 series each
  const defaultSeries1 = [15000, 16000, 20000, 26000, 34000, 40000]
  const defaultSeries2 = [16000, 18000, 15000, 22000, 31000, 45000]
  
  const series1Values = (Array.isArray(data.series1) && data.series1.length > 0) 
    ? data.series1 
    : defaultSeries1
  const series2Values = (Array.isArray(data.series2) && data.series2.length > 0)
    ? data.series2
    : defaultSeries2
  
  const max = Math.max.apply(Math, series1Values.concat(series2Values).concat([50000]))
  const groupW = (g.chartW - g.groupPadding * (g.groupCount + 1)) / g.groupCount
  const barW = (groupW - g.barPadding) / 2
  
  const specs = [
    {
      slotId: 'CTB_ACCENT',
      x: 80,
      y: g.accentY,
      w: g.accentW,
      h: g.accentH,
      color: CTB_PALETTE.series1,
      layer: 5,
      kind: 'accent',
      fill: CTB_PALETTE.series1,
    },
    {
      slotId: 'CTB_GRID',
      x: g.chartX,
      y: g.chartY,
      w: g.chartW,
      h: g.chartH,
      color: '#E5E7EB',
      layer: 2,
      kind: 'grid',
    },
    // Legend boxes
    {
      slotId: 'CTB_LEGEND_BOX_1',
      x: g.legendX,
      y: g.legendY + 5,
      w: g.legendBoxSize,
      h: g.legendBoxSize,
      color: CTB_PALETTE.series1,
      layer: 10,
      kind: 'legendBox',
      fill: CTB_PALETTE.series1,
    },
    {
      slotId: 'CTB_LEGEND_BOX_2',
      x: g.legendX + 140,
      y: g.legendY + 5,
      w: g.legendBoxSize,
      h: g.legendBoxSize,
      color: CTB_PALETTE.series2,
      layer: 10,
      kind: 'legendBox',
      fill: CTB_PALETTE.series2,
    },
  ]
  
  for (let i = 0; i < g.groupCount; i += 1) {
    const groupX = g.chartX + g.groupPadding + i * (groupW + g.groupPadding)
    
    // Series 1 bar (left)
    const bar1H = (series1Values[i] / max) * g.chartH
    const bar1Y = g.chartY + g.chartH - bar1H
    specs.push({
      slotId: `CTB_BAR_${i + 1}_S1`,
      n: i + 1,
      series: 1,
      x: groupX,
      y: bar1Y,
      w: barW,
      h: bar1H,
      color: CTB_PALETTE.series1,
      layer: 6,
      kind: 'bar',
      fill: CTB_PALETTE.series1,
    })
    
    // Series 2 bar (right)
    const bar2H = (series2Values[i] / max) * g.chartH
    const bar2Y = g.chartY + g.chartH - bar2H
    specs.push({
      slotId: `CTB_BAR_${i + 1}_S2`,
      n: i + 1,
      series: 2,
      x: groupX + barW + g.barPadding,
      y: bar2Y,
      w: barW,
      h: bar2H,
      color: CTB_PALETTE.series2,
      layer: 6,
      kind: 'bar',
      fill: CTB_PALETTE.series2,
    })
  }
  
  return specs
}

function chartTwoBarOverlay(gx, gy, gw, gh) {
  const g = CTB_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    legend1: box(g.legendX + g.legendBoxSize + 8, g.legendY, 100, g.legendH),
    legend2: box(g.legendX + 140 + g.legendBoxSize + 8, g.legendY, 100, g.legendH),
  }
}

function specToChartTwoBarContent(spec) {
  if (spec.kind === 'accent') return { svg: accentBarSvg(), colorMode: 'recolorable', fill: spec.fill }
  if (spec.kind === 'grid') return { svg: gridLinesSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'legendBox') return { svg: legendBoxSvg(), colorMode: 'recolorable', fill: spec.fill }
  return { svg: barSvg(spec), colorMode: 'recolorable', fill: spec.fill }
}

function plainTextFromContent(content = {}) {
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map((r) => r.text || '').join('')
    if (joined.trim()) return joined
  }
  return ''
}

function filledContent(el, slotId, style) {
  const sid = String(slotId || '')
  const existing = plainTextFromContent(el && el.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (CTB_DEFAULTS[sid] || existing)
  return Object.assign(
    {},
    (el && el.content) || {},
    style,
    {
      text,
      runs: null,
      listType: null,
      letterSpacing: style.letterSpacing !== undefined ? style.letterSpacing : '0',
      padding: 0,
      paddingX: 0,
      stroke: undefined,
      strokeWidth: 0,
    }
  )
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutChartTwoBar(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CTB_GEOM.viewW
  const sy = canvasH / CTB_GEOM.viewH
  const overlay = chartTwoBarOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^CTB_/i
  const prevBySlot = new Map(
    elements.filter(function (el) { return chromeRe.test(String(el.slotId || '')) }).map(function (el) { return [String(el.slotId || '').toUpperCase(), el] })
  )
  const filtered = elements.filter(function (el) { return !chromeRe.test(String(el.slotId || '')) && isChartTwoBarTextSlot(el.slotId) })
  const bySlot = new Map(filtered.map(function (el) { return [String(el.slotId || ''), el] }))

  const placeText = function (slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-ctb'),
      type: 'text',
      slotId: slotId,
      role: (prev && prev.role) || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 32, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('LEGEND_1', overlay.legend1, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#6B7280', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('LEGEND_2', overlay.legend2, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#6B7280', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
  ]

  // Extract chart data if present
  const chart1El = elements.find(function (el) { return el.slotId === 'CHART_1' })
  const chart2El = elements.find(function (el) { return el.slotId === 'CHART_2' })
  
  const series1 = (chart1El && chart1El.content && chart1El.content.values) || (chart1El && chart1El.content && chart1El.content.data)
  const series2 = (chart2El && chart2El.content && chart2El.content.values) || (chart2El && chart2El.content && chart2El.content.data)
  
  const extractedData = {
    series1: Array.isArray(series1) ? series1 : undefined,
    series2: Array.isArray(series2) ? series2 : undefined,
  }
  
  const chrome = chartTwoBarChromeSpecs(extractedData).map(function (spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartTwoBarContent(spec)
    return {
      id: (prev && prev.id) || newId('shp-ctb'),
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
  })
  
  return chrome.concat(next)
}

module.exports = {
  isChartTwoBarLayout,
  isChartTwoBarTextSlot,
  layoutChartTwoBar,
  CTB_GEOM,
  CTB_PALETTE,
}
