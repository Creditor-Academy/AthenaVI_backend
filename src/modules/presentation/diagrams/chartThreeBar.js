/**
 * Chart three bar — 3-series grouped/clustered bar chart with vertical legend.
 * Layout id: chart_three_v1.
 * Backend CommonJS version.
 */

const CT3_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 100,
  headingY: 20,
  headingW: 600,
  headingH: 40,
  subheadingX: 100,
  subheadingY: 70,
  subheadingW: 600,
  subheadingH: 30,
  // Bar chart area
  chartX: 100,
  chartY: 140,
  chartW: 600,
  chartH: 360,
  groupCount: 4,
  barPadding: 6,
  groupPadding: 30,
  // Legend (vertical, right side)
  legendX: 740,
  legendY: 140,
  legendBoxSize: 40,
  legendItemH: 100,
  legendBoxW: 30,
  // Accent bar (left edge)
  accentW: 6,
  accentH: 400,
  accentY: 120,
}

const CT3_PALETTE = {
  series1: '#FF6B35',
  series2: '#FFC107',
  series3: '#4CAF50',
}

const CT3_DEFAULTS = {
  HEADING: 'Insert Your Text Here',
  SUBHEADING: 'This is a sample text',
  LEGEND_1_TITLE: 'Series 1',
  LEGEND_1_DESC: 'This is a sample text. Insert your desired text here.',
  LEGEND_2_TITLE: 'Series 2',
  LEGEND_2_DESC: 'This is a sample text. Insert your desired text here.',
  LEGEND_3_TITLE: 'Series 3',
  LEGEND_3_DESC: 'This is a sample text. Insert your desired text here.',
}

function isChartThreeBarLayout(layoutId) {
  return /chart_three_v1$/i.test(String(layoutId || ''))
}

function isChartThreeBarTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'LEGEND_1_TITLE'
    || sid === 'LEGEND_1_DESC'
    || sid === 'LEGEND_2_TITLE'
    || sid === 'LEGEND_2_DESC'
    || sid === 'LEGEND_3_TITLE'
    || sid === 'LEGEND_3_DESC'
}

function accentBarSvg() {
  const g = CT3_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.accentW + ' ' + g.accentH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.accentW + '" height="' + g.accentH + '" fill="currentColor" rx="2"/>' +
    '</svg>'
}

function gridLinesSvg() {
  const g = CT3_GEOM
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
  const g = CT3_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.legendBoxW + ' ' + g.legendBoxSize + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.legendBoxW + '" height="' + g.legendBoxSize + '" fill="currentColor" rx="4"/>' +
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

function chartThreeBarChromeSpecs(chartData = {}) {
  const g = CT3_GEOM
  const series1Values = Array.isArray(chartData.series1) && chartData.series1.length > 0 
    ? chartData.series1 
    : [4.5, 2.5, 3.5, 4.5]
  const series2Values = Array.isArray(chartData.series2) && chartData.series2.length > 0
    ? chartData.series2
    : [2.5, 4.5, 2.0, 3.0]
  const series3Values = Array.isArray(chartData.series3) && chartData.series3.length > 0
    ? chartData.series3
    : [2.0, 2.0, 3.0, 5.0]
  
  const max = Math.max.apply(Math, series1Values.concat(series2Values).concat(series3Values).concat([5]))
  const groupW = (g.chartW - g.groupPadding * (g.groupCount + 1)) / g.groupCount
  const barW = (groupW - g.barPadding * 2) / 3
  
  const specs = [
    {
      slotId: 'CT3_ACCENT',
      x: 80,
      y: g.accentY,
      w: g.accentW,
      h: g.accentH,
      color: CT3_PALETTE.series1,
      layer: 5,
      kind: 'accent',
      fill: CT3_PALETTE.series1,
    },
    {
      slotId: 'CT3_GRID',
      x: g.chartX,
      y: g.chartY,
      w: g.chartW,
      h: g.chartH,
      color: '#E5E7EB',
      layer: 2,
      kind: 'grid',
    },
    {
      slotId: 'CT3_LEGEND_BOX_1',
      x: g.legendX,
      y: g.legendY + 10,
      w: g.legendBoxW,
      h: g.legendBoxSize,
      color: CT3_PALETTE.series1,
      layer: 10,
      kind: 'legendBox',
      fill: CT3_PALETTE.series1,
    },
    {
      slotId: 'CT3_LEGEND_BOX_2',
      x: g.legendX,
      y: g.legendY + g.legendItemH + 10,
      w: g.legendBoxW,
      h: g.legendBoxSize,
      color: CT3_PALETTE.series2,
      layer: 10,
      kind: 'legendBox',
      fill: CT3_PALETTE.series2,
    },
    {
      slotId: 'CT3_LEGEND_BOX_3',
      x: g.legendX,
      y: g.legendY + g.legendItemH * 2 + 10,
      w: g.legendBoxW,
      h: g.legendBoxSize,
      color: CT3_PALETTE.series3,
      layer: 10,
      kind: 'legendBox',
      fill: CT3_PALETTE.series3,
    },
  ]
  
  const seriesData = [series1Values, series2Values, series3Values]
  const seriesColors = [CT3_PALETTE.series1, CT3_PALETTE.series2, CT3_PALETTE.series3]
  
  for (let i = 0; i < g.groupCount; i += 1) {
    const groupX = g.chartX + g.groupPadding + i * (groupW + g.groupPadding)
    
    for (let s = 0; s < 3; s += 1) {
      const barH = (seriesData[s][i] / max) * g.chartH
      const barY = g.chartY + g.chartH - barH
      const barX = groupX + s * (barW + g.barPadding)
      
      specs.push({
        slotId: 'CT3_BAR_' + (i + 1) + '_S' + (s + 1),
        n: i + 1,
        series: s + 1,
        x: barX,
        y: barY,
        w: barW,
        h: barH,
        color: seriesColors[s],
        layer: 6,
        kind: 'bar',
        fill: seriesColors[s],
      })
    }
  }
  
  return specs
}

function chartThreeBarOverlay(gx, gy, gw, gh) {
  const g = CT3_GEOM
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
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
    legend1Title: box(g.legendX + g.legendBoxW + 10, g.legendY + 10, 200, 24),
    legend1Desc: box(g.legendX + g.legendBoxW + 10, g.legendY + 38, 200, 50),
    legend2Title: box(g.legendX + g.legendBoxW + 10, g.legendY + g.legendItemH + 10, 200, 24),
    legend2Desc: box(g.legendX + g.legendBoxW + 10, g.legendY + g.legendItemH + 38, 200, 50),
    legend3Title: box(g.legendX + g.legendBoxW + 10, g.legendY + g.legendItemH * 2 + 10, 200, 24),
    legend3Desc: box(g.legendX + g.legendBoxW + 10, g.legendY + g.legendItemH * 2 + 38, 200, 50),
  }
}

function specToChartThreeBarContent(spec) {
  if (spec.kind === 'accent') return { svg: accentBarSvg(), colorMode: 'recolorable', fill: spec.fill }
  if (spec.kind === 'grid') return { svg: gridLinesSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'legendBox') return { svg: legendBoxSvg(), colorMode: 'recolorable', fill: spec.fill }
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
    : (CT3_DEFAULTS[sid] || existing)
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

function layoutChartThreeBar(elements, schema, palette = {}, canvas = {}, chartData = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CT3_GEOM.viewW
  const sy = canvasH / CT3_GEOM.viewH
  const overlay = chartThreeBarOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^CT3_/i
  const prevBySlot = new Map(
    elements.filter(function (el) { return chromeRe.test(String(el.slotId || '')) }).map(function (el) { return [String(el.slotId || '').toUpperCase(), el] })
  )
  const filtered = elements.filter(function (el) { return !chromeRe.test(String(el.slotId || '')) && isChartThreeBarTextSlot(el.slotId) })
  const bySlot = new Map(filtered.map(function (el) { return [String(el.slotId || ''), el] }))

  const placeText = function (slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-ct3'),
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
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#9CA3AF', clipToSlot: true, lineHeight: 1.3,
    }, 'subheading'),
    placeText('LEGEND_1_TITLE', overlay.legend1Title, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 600, color: '#374151', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('LEGEND_1_DESC', overlay.legend1Desc, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'caption'),
    placeText('LEGEND_2_TITLE', overlay.legend2Title, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 600, color: '#374151', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('LEGEND_2_DESC', overlay.legend2Desc, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'caption'),
    placeText('LEGEND_3_TITLE', overlay.legend3Title, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 600, color: '#374151', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('LEGEND_3_DESC', overlay.legend3Desc, {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'caption'),
  ]

  const chart1El = elements.find(function (el) { return el.slotId === 'CHART_1' })
  const chart2El = elements.find(function (el) { return el.slotId === 'CHART_2' })
  const chart3El = elements.find(function (el) { return el.slotId === 'CHART_3' })
  
  const series1 = (chart1El && chart1El.content && chart1El.content.values) || (chart1El && chart1El.content && chart1El.content.data)
  const series2 = (chart2El && chart2El.content && chart2El.content.values) || (chart2El && chart2El.content && chart2El.content.data)
  const series3 = (chart3El && chart3El.content && chart3El.content.values) || (chart3El && chart3El.content && chart3El.content.data)
  
  const extractedData = {
    series1: Array.isArray(series1) ? series1 : undefined,
    series2: Array.isArray(series2) ? series2 : undefined,
    series3: Array.isArray(series3) ? series3 : undefined,
  }
  
  const chrome = chartThreeBarChromeSpecs(extractedData).map(function (spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartThreeBarContent(spec)
    return {
      id: (prev && prev.id) || newId('shp-ct3'),
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
  isChartThreeBarLayout,
  isChartThreeBarTextSlot,
  layoutChartThreeBar,
  CT3_GEOM,
  CT3_PALETTE,
}
