/**
 * Chart two bar SPLIT — grouped/clustered bar chart with side description panel.
 * Layout id: chart_two_split_v1.
 * Backend CommonJS version.
 */

const CTBS_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 100,
  headingY: 20,
  headingW: 400,
  headingH: 60,
  // Bar chart area (left side - narrower)
  chartX: 100,
  chartY: 140,
  chartW: 540,
  chartH: 360,
  groupCount: 6,
  barPadding: 6,
  groupPadding: 20,
  // Legend (above chart)
  legendX: 450,
  legendY: 110,
  legendW: 300,
  legendH: 25,
  legendBoxSize: 14,
  // Side panel (right side)
  panelX: 700,
  panelY: 200,
  panelW: 260,
  panelTitleH: 40,
  panelBodyH: 140,
  // Accent bar (left edge)
  accentW: 6,
  accentH: 380,
  accentY: 120,
}

const CTBS_PALETTE = {
  series1: '#1E40AF',  // Dark blue
  series2: '#8B5CF6',  // Purple
}

const CTBS_DEFAULTS = {
  HEADING: 'Revenue vs Forecast',
  LEGEND_1: 'Revenue',
  LEGEND_2: 'Forecast',
  PANEL_TITLE: 'Sample Text',
  PANEL_BODY: 'This is a sample text. Insert your desired text here.',
}

function isChartTwoBarSplitLayout(layoutId) {
  return /chart_two_split_v1$/i.test(String(layoutId || ''))
}

function isChartTwoBarSplitTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'LEGEND_1'
    || sid === 'LEGEND_2'
    || sid === 'PANEL_TITLE'
    || sid === 'PANEL_BODY'
}

function accentBarSvg() {
  const g = CTBS_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.accentW + ' ' + g.accentH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.accentW + '" height="' + g.accentH + '" fill="currentColor" rx="2"/>' +
    '</svg>'
}

function gridLinesSvg() {
  const g = CTBS_GEOM
  const lines = []
  const steps = 5
  for (let i = 0; i <= steps; i += 1) {
    const y = (g.chartH / steps) * i
    lines.push('<line x1="0" y1="' + y + '" x2="' + g.chartW + '" y2="' + y + '" stroke="#E5E7EB" stroke-width="1"/>')
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.chartW + ' ' + g.chartH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    lines.join('\n    ') +
    '</svg>'
}

function barSvg(spec) {
  const w = spec.w
  const h = spec.h
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + w + ' ' + h + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + w + '" height="' + h + '" fill="currentColor" rx="2"/>' +
    '</svg>'
}

function legendBoxSvg() {
  const size = CTBS_GEOM.legendBoxSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="0" y="0" width="' + size + '" height="' + size + '" fill="currentColor" rx="2"/>' +
    '</svg>'
}

function sidePanelBgSvg() {
  const g = CTBS_GEOM
  const h = g.panelTitleH + g.panelBodyH + 40
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.panelW + ' ' + h + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.panelW + '" height="' + h + '" fill="#F3F4F6" rx="8"/>' +
    '</svg>'
}

function hexLum(hex) {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = function (c) { return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4) }
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette = {}) {
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && palette.colors.bg) || (palette.colors && palette.colors.background) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827'
}

function chartTwoBarSplitChromeSpecs(chartData = {}) {
  const g = CTBS_GEOM
  // Default data: 6 groups, 2 series each
  const series1Values = Array.isArray(chartData.series1) && chartData.series1.length > 0 
    ? chartData.series1 
    : [15000, 16000, 20000, 26000, 34000, 40000]
  const series2Values = Array.isArray(chartData.series2) && chartData.series2.length > 0
    ? chartData.series2
    : [16000, 18000, 15000, 22000, 31000, 45000]
  
  const max = Math.max.apply(Math, series1Values.concat(series2Values).concat([50000]))
  const groupW = (g.chartW - g.groupPadding * (g.groupCount + 1)) / g.groupCount
  const barW = (groupW - g.barPadding) / 2
  
  const specs = [
    {
      slotId: 'CTBS_ACCENT',
      x: 80,
      y: g.accentY,
      w: g.accentW,
      h: g.accentH,
      color: CTBS_PALETTE.series1,
      layer: 5,
      kind: 'accent',
      fill: CTBS_PALETTE.series1,
    },
    {
      slotId: 'CTBS_GRID',
      x: g.chartX,
      y: g.chartY,
      w: g.chartW,
      h: g.chartH,
      color: '#E5E7EB',
      layer: 2,
      kind: 'grid',
    },
    {
      slotId: 'CTBS_PANEL_BG',
      x: g.panelX,
      y: g.panelY,
      w: g.panelW,
      h: g.panelTitleH + g.panelBodyH + 40,
      color: '#F3F4F6',
      layer: 3,
      kind: 'panelBg',
    },
    // Legend boxes
    {
      slotId: 'CTBS_LEGEND_BOX_1',
      x: g.legendX,
      y: g.legendY + 5,
      w: g.legendBoxSize,
      h: g.legendBoxSize,
      color: CTBS_PALETTE.series1,
      layer: 10,
      kind: 'legendBox',
      fill: CTBS_PALETTE.series1,
    },
    {
      slotId: 'CTBS_LEGEND_BOX_2',
      x: g.legendX + 140,
      y: g.legendY + 5,
      w: g.legendBoxSize,
      h: g.legendBoxSize,
      color: CTBS_PALETTE.series2,
      layer: 10,
      kind: 'legendBox',
      fill: CTBS_PALETTE.series2,
    },
  ]
  
  for (let i = 0; i < g.groupCount; i += 1) {
    const groupX = g.chartX + g.groupPadding + i * (groupW + g.groupPadding)
    
    // Series 1 bar (left)
    const bar1H = (series1Values[i] / max) * g.chartH
    const bar1Y = g.chartY + g.chartH - bar1H
    specs.push({
      slotId: 'CTBS_BAR_' + (i + 1) + '_S1',
      n: i + 1,
      series: 1,
      x: groupX,
      y: bar1Y,
      w: barW,
      h: bar1H,
      color: CTBS_PALETTE.series1,
      layer: 6,
      kind: 'bar',
      fill: CTBS_PALETTE.series1,
    })
    
    // Series 2 bar (right)
    const bar2H = (series2Values[i] / max) * g.chartH
    const bar2Y = g.chartY + g.chartH - bar2H
    specs.push({
      slotId: 'CTBS_BAR_' + (i + 1) + '_S2',
      n: i + 1,
      series: 2,
      x: groupX + barW + g.barPadding,
      y: bar2Y,
      w: barW,
      h: bar2H,
      color: CTBS_PALETTE.series2,
      layer: 6,
      kind: 'bar',
      fill: CTBS_PALETTE.series2,
    })
  }
  
  return specs
}

function chartTwoBarSplitOverlay(gx, gy, gw, gh) {
  const g = CTBS_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = function (x, y, w, h) {
    return {
      x: Math.round(gx + x * sx),
      y: Math.round(gy + y * sy),
      width: Math.max(12, Math.round(w * sx)),
      height: Math.max(10, Math.round(h * sy)),
    }
  }
  
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    legend1: box(g.legendX + g.legendBoxSize + 8, g.legendY, 100, g.legendH),
    legend2: box(g.legendX + 140 + g.legendBoxSize + 8, g.legendY, 100, g.legendH),
    panelTitle: box(g.panelX + 20, g.panelY + 20, g.panelW - 40, g.panelTitleH),
    panelBody: box(g.panelX + 20, g.panelY + g.panelTitleH + 30, g.panelW - 40, g.panelBodyH),
  }
}

function specToChartTwoBarSplitContent(spec) {
  if (spec.kind === 'accent') return { svg: accentBarSvg(), colorMode: 'recolorable', fill: spec.fill }
  if (spec.kind === 'grid') return { svg: gridLinesSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'legendBox') return { svg: legendBoxSvg(), colorMode: 'recolorable', fill: spec.fill }
  if (spec.kind === 'panelBg') return { svg: sidePanelBgSvg(), colorMode: 'fixed', fill: spec.color }
  return { svg: barSvg(spec), colorMode: 'recolorable', fill: spec.fill }
}

function plainTextFromContent(content = {}) {
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map(function (r) { return r.text || '' }).join('')
    if (joined.trim()) return joined
  }
  return ''
}

function filledContent(el, slotId, style) {
  const sid = String(slotId || '')
  const existing = plainTextFromContent(el && el.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (CTBS_DEFAULTS[sid] || existing)
  return Object.assign(
    {},
    (el && el.content) || {},
    style,
    {
      text: text,
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
  return prefix + '-' + Math.random().toString(36).slice(2, 9)
}

function layoutChartTwoBarSplit(elements, schema, palette = {}, canvas = {}, chartData = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CTBS_GEOM.viewW
  const sy = canvasH / CTBS_GEOM.viewH
  const overlay = chartTwoBarSplitOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^CTBS_/i
  const prevBySlot = new Map(
    elements.filter(function (el) { return chromeRe.test(String(el.slotId || '')) }).map(function (el) { return [String(el.slotId || '').toUpperCase(), el] })
  )
  const filtered = elements.filter(function (el) { return !chromeRe.test(String(el.slotId || '')) && isChartTwoBarSplitTextSlot(el.slotId) })
  const bySlot = new Map(filtered.map(function (el) { return [String(el.slotId || ''), el] }))

  const placeText = function (slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-ctbs'),
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
    placeText('PANEL_TITLE', overlay.panelTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 18, fontWeight: 600, color: '#6B7280', clipToSlot: true, lineHeight: 1.3,
    }, 'heading'),
    placeText('PANEL_BODY', overlay.panelBody, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
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
  
  const chrome = chartTwoBarSplitChromeSpecs(extractedData).map(function (spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartTwoBarSplitContent(spec)
    return {
      id: (prev && prev.id) || newId('shp-ctbs'),
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
  isChartTwoBarSplitLayout,
  isChartTwoBarSplitTextSlot,
  layoutChartTwoBarSplit,
  CTBS_GEOM,
  CTBS_PALETTE,
}
