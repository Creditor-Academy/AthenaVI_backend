/**
 * Chart two metrics comparison — clean layout with icon containers and bar charts.
 * Layout id: chart_two_cards_split_v1.
 */

const CTMC_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 60,
  headingY: 20,
  headingW: 700,
  headingH: 50,
  subheadingX: 60,
  subheadingY: 75,
  subheadingW: 880,
  subheadingH: 30,
  
  // Metric A section
  metricA_Y: 130,
  
  // Metric B section  
  metricB_Y: 350,
  
  // Icon container (rounded square with light background)
  iconContainerX: 80,
  iconContainerSize: 80,
  
  // Text content area
  textX: 190,
  textW: 420,
  titleH: 35,
  descH: 50,
  labelY: 180,
  
  // Chart area (right side)
  chartX: 640,
  chartW: 300,
  chartH: 140,
}

const CTMC_DEFAULTS = {
  HEADING: 'Two Metrics Comparison',
  SUBHEADING: 'A side-by-side view of how Metric A and Metric B perform across four quarters.',
  METRIC_A_TITLE: 'Metric A',
  METRIC_A_DESC: 'This is a sample description for metric A, giving a brief overview of what this metric represents.',
  METRIC_A_LABEL: '● Performance Trend',
  METRIC_B_TITLE: 'Metric B',
  METRIC_B_DESC: 'This is a sample description for metric B, giving a brief overview of what this metric represents.',
  METRIC_B_LABEL: '● Performance Trend',
}

function isChartTwoMetricsComparisonLayout(layoutId) {
  return /chart_two_cards_split_v1$/i.test(String(layoutId || ''))
}

function isChartTwoMetricsComparisonTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'METRIC_A_TITLE'
    || sid === 'METRIC_A_DESC'
    || sid === 'METRIC_A_LABEL'
    || sid === 'METRIC_B_TITLE'
    || sid === 'METRIC_B_DESC'
    || sid === 'METRIC_B_LABEL'
}

function iconContainerSvg(color) {
  const size = CTMC_GEOM.iconContainerSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + size + '" height="' + size + '" fill="' + color + '" rx="12"/>' +
    '</svg>'
}

function chartIconSvg(color) {
  const size = CTMC_GEOM.iconContainerSize
  const iconColor = color === '#DBEAFE' ? '#3B82F6' : '#8B5CF6'
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<g transform="translate(' + (size/2) + ', ' + (size/2) + ')">' +
    '<path d="M -18 12 L -18 -6 L -10 -6 L -10 12 Z" fill="' + iconColor + '"/>' +
    '<path d="M -6 12 L -6 -12 L 2 -12 L 2 12 Z" fill="' + iconColor + '"/>' +
    '<path d="M 6 12 L 6 0 L 14 0 L 14 12 Z" fill="' + iconColor + '"/>' +
    '<line x1="-20" y1="14" x2="20" y2="14" stroke="' + iconColor + '" stroke-width="2" stroke-linecap="round"/>' +
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

function chartTwoMetricsComparisonChromeSpecs() {
  const g = CTMC_GEOM
  
  return [
    // Metric A icon container (light blue rounded square)
    {
      slotId: 'CTMC_METRIC_A_ICON_BG',
      x: g.iconContainerX,
      y: g.metricA_Y,
      w: g.iconContainerSize,
      h: g.iconContainerSize,
      color: '#DBEAFE',  // Light blue
      layer: 5,
      kind: 'iconContainer',
    },
    // Metric A chart icon
    {
      slotId: 'CTMC_METRIC_A_ICON',
      x: g.iconContainerX,
      y: g.metricA_Y,
      w: g.iconContainerSize,
      h: g.iconContainerSize,
      color: '#DBEAFE',
      layer: 6,
      kind: 'chartIcon',
    },
    // Metric B icon container (light purple rounded square)
    {
      slotId: 'CTMC_METRIC_B_ICON_BG',
      x: g.iconContainerX,
      y: g.metricB_Y,
      w: g.iconContainerSize,
      h: g.iconContainerSize,
      color: '#EDE9FE',  // Light purple
      layer: 5,
      kind: 'iconContainer',
    },
    // Metric B chart icon
    {
      slotId: 'CTMC_METRIC_B_ICON',
      x: g.iconContainerX,
      y: g.metricB_Y,
      w: g.iconContainerSize,
      h: g.iconContainerSize,
      color: '#EDE9FE',
      layer: 6,
      kind: 'chartIcon',
    },
  ]
}

function chartTwoMetricsComparisonOverlay(gx, gy, gw, gh) {
  const g = CTMC_GEOM
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
  
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
    
    // Metric A
    metricA_title: box(g.textX, g.metricA_Y + 10, g.textW, g.titleH),
    metricA_desc: box(g.textX, g.metricA_Y + 50, g.textW, g.descH),
    metricA_label: box(g.textX, g.metricA_Y + 110, 200, 25),
    metricA_chart: box(g.chartX, g.metricA_Y, g.chartW, g.chartH),
    
    // Metric B
    metricB_title: box(g.textX, g.metricB_Y + 10, g.textW, g.titleH),
    metricB_desc: box(g.textX, g.metricB_Y + 50, g.textW, g.descH),
    metricB_label: box(g.textX, g.metricB_Y + 110, 200, 25),
    metricB_chart: box(g.chartX, g.metricB_Y, g.chartW, g.chartH),
  }
}

function specToChartTwoMetricsComparisonContent(spec) {
  if (spec.kind === 'iconContainer') return { svg: iconContainerSvg(spec.color), colorMode: 'fixed', fill: spec.color }
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
    : (CTMC_DEFAULTS[sid] || existing)
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

function layoutChartTwoMetricsComparison(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CTMC_GEOM.viewW
  const sy = canvasH / CTMC_GEOM.viewH
  const overlay = chartTwoMetricsComparisonOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^CTMC_/i
  
  const prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })
  
  const filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isChartTwoMetricsComparisonTextSlot(el.slotId)
  })
  const bySlot = new Map()
  filtered.forEach(function(el) {
    bySlot.set(String(el.slotId || ''), el)
  })

  function placeText(slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-ctmc'),
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
      align: 'left', verticalAlign: 'top', fontSize: 42, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4,
    }, 'subheading'),
    
    // Metric A
    placeText('METRIC_A_TITLE', overlay.metricA_title, {
      align: 'left', verticalAlign: 'top', fontSize: 24, fontWeight: 700, color: '#111827', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('METRIC_A_DESC', overlay.metricA_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'),
    placeText('METRIC_A_LABEL', overlay.metricA_label, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 600, color: '#3B82F6', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    
    // Metric B
    placeText('METRIC_B_TITLE', overlay.metricB_title, {
      align: 'left', verticalAlign: 'top', fontSize: 24, fontWeight: 700, color: '#111827', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('METRIC_B_DESC', overlay.metricB_desc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'),
    placeText('METRIC_B_LABEL', overlay.metricB_label, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 600, color: '#8B5CF6', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
  ]

  const chrome = chartTwoMetricsComparisonChromeSpecs().map(function(spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartTwoMetricsComparisonContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-ctmc'),
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
      placement: overlay.metricA_chart,
      layer: 8,
    }))
  }
  if (chart2El) {
    charts.push(Object.assign({}, chart2El, {
      placement: overlay.metricB_chart,
      layer: 8,
    }))
  }
  
  return chrome.concat(next).concat(charts)
}

module.exports = {
  isChartTwoMetricsComparisonLayout: isChartTwoMetricsComparisonLayout,
  layoutChartTwoMetricsComparison: layoutChartTwoMetricsComparison,
  CTMC_GEOM: CTMC_GEOM,
  CTMC_DEFAULTS: CTMC_DEFAULTS,
}
