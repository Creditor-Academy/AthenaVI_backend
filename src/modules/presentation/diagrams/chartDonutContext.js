/**
 * Chart donut context — Donut chart on left + context panel on right.
 * Layout id: chart_donut_context_v1.
 */

const CDC_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Badge at top left
  badgeX: 50,
  badgeY: 40,
  badgeW: 140,
  badgeH: 22,
  badgeIconSize: 14,
  
  // Donut chart area (left side)
  donutCenterX: 230,
  donutCenterY: 310,
  donutOuterRadius: 150,
  donutInnerRadius: 95,
  
  // Center text in donut
  centerTextY: 305,
  centerLabelY: 330,
  
  // Right side - Context panel (wider and taller)
  panelX: 500,
  panelY: 75,
  panelW: 460,
  panelH: 465,
  
  // Inside panel - better spacing
  panelHeadingX: 35,
  panelHeadingY: 35,
  panelSubheadingX: 35,
  panelSubheadingY: 80,
  panelSubheadingW: 390,
  panelSubheadingH: 65,
  
  // Metric breakdowns in panel (4 metrics) - improved spacing
  metricStartY: 170,
  metricGap: 73,
  metricDotX: 35,
  metricDotSize: 12,
  metricLabelX: 55,
  metricDescX: 55,
  metricDescY: 22,
  metricValueX: 410,
  metricDescH: 42,
}

// Donut segments data (4 segments)
const CDC_SEGMENTS = [
  { id: 'A', value: 32, startAngle: 0, endAngle: 115.2, color: '#3B82F6', label: 'Metric A' },
  { id: 'B', value: 24, startAngle: 115.2, endAngle: 201.6, color: '#8B5CF6', label: 'Metric B' },
  { id: 'C', value: 18, startAngle: 201.6, endAngle: 266.4, color: '#10B981', label: 'Metric C' },
  { id: 'D', value: 26, startAngle: 266.4, endAngle: 360, color: '#64748B', label: 'Metric D' },
]

const CDC_COLORS = {
  metricA: '#3B82F6',  // Blue
  metricB: '#8B5CF6',  // Purple
  metricC: '#10B981',  // Green
  metricD: '#64748B',  // Gray
}

const CDC_DEFAULTS = {
  BADGE: 'MARKET SHARE',
  CENTER_VALUE: '100%',
  CENTER_LABEL: 'Total',
  PANEL_HEADING: 'Market share',
  PANEL_SUBHEADING: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  METRIC_A_LABEL: 'Metric A',
  METRIC_A_VALUE: '32%',
  METRIC_A_DESC: 'Represents the largest share of the market, showing strong performance.',
  METRIC_B_LABEL: 'Metric B',
  METRIC_B_VALUE: '24%',
  METRIC_B_DESC: 'Maintains a steady presence with consistent growth over time.',
  METRIC_C_LABEL: 'Metric C',
  METRIC_C_VALUE: '18%',
  METRIC_C_DESC: 'Shows gradual progress and increasing contribution.',
  METRIC_D_LABEL: 'Metric D',
  METRIC_D_VALUE: '26%',
  METRIC_D_DESC: 'Remains a significant part of the market with stable performance.',
}

function isChartDonutContextLayout(layoutId) {
  return /chart_donut_context(_v1|_right_v1)?$/i.test(String(layoutId || ''))
}

function isChartDonutContextRightLayout(layoutId) {
  return /chart_donut_context_right_v1$/i.test(String(layoutId || ''))
}

function isChartDonutContextTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'CENTER_VALUE'
    || sid === 'CENTER_LABEL'
    || sid === 'PANEL_HEADING'
    || sid === 'PANEL_SUBHEADING'
    || sid === 'METRIC_A_LABEL'
    || sid === 'METRIC_A_VALUE'
    || sid === 'METRIC_A_DESC'
    || sid === 'METRIC_B_LABEL'
    || sid === 'METRIC_B_VALUE'
    || sid === 'METRIC_B_DESC'
    || sid === 'METRIC_C_LABEL'
    || sid === 'METRIC_C_VALUE'
    || sid === 'METRIC_C_DESC'
    || sid === 'METRIC_D_LABEL'
    || sid === 'METRIC_D_VALUE'
    || sid === 'METRIC_D_DESC'
}

function panelBgSvg() {
  const g = CDC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.panelW + ' ' + g.panelH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.panelW + '" height="' + g.panelH + '" fill="#F0F9FF" stroke="#BFDBFE" stroke-width="2" rx="16"/>' +
    '</svg>'
}

function badgeSvg() {
  const g = CDC_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.badgeW + ' ' + g.badgeH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.badgeW + '" height="' + g.badgeH + '" fill="#DBEAFE" rx="6"/>' +
    '</svg>'
}

function badgeIconSvg() {
  const size = CDC_GEOM.badgeIconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<rect x="2" y="2" width="' + (size - 4) + '" height="' + (size - 4) + '" rx="2" fill="none" stroke="#3B82F6" stroke-width="1.5"/>' +
    '<path d="M4 8 L7 11 L12 4" stroke="#3B82F6" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>'
}

function donutSegmentPath(centerX, centerY, innerR, outerR, startAngle, endAngle) {
  function toRad(deg) { return (deg - 90) * Math.PI / 180 }
  const x1 = centerX + outerR * Math.cos(toRad(startAngle))
  const y1 = centerY + outerR * Math.sin(toRad(startAngle))
  const x2 = centerX + outerR * Math.cos(toRad(endAngle))
  const y2 = centerY + outerR * Math.sin(toRad(endAngle))
  const x3 = centerX + innerR * Math.cos(toRad(endAngle))
  const y3 = centerY + innerR * Math.sin(toRad(endAngle))
  const x4 = centerX + innerR * Math.cos(toRad(startAngle))
  const y4 = centerY + innerR * Math.sin(toRad(startAngle))
  
  const largeArc = endAngle - startAngle > 180 ? 1 : 0
  
  return 'M ' + x1 + ' ' + y1 + ' A ' + outerR + ' ' + outerR + ' 0 ' + largeArc + ' 1 ' + x2 + ' ' + y2 + 
         ' L ' + x3 + ' ' + y3 + ' A ' + innerR + ' ' + innerR + ' 0 ' + largeArc + ' 0 ' + x4 + ' ' + y4 + ' Z'
}

function donutSegmentSvg(segment, width, height) {
  const g = CDC_GEOM
  // Adjust coordinates to be relative to the cropped viewBox
  var centerX = g.donutOuterRadius
  var centerY = g.donutOuterRadius
  const path = donutSegmentPath(centerX, centerY, g.donutInnerRadius, g.donutOuterRadius, segment.startAngle, segment.endAngle)
  var viewBoxSize = g.donutOuterRadius * 2
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + viewBoxSize + ' ' + viewBoxSize + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<path d="' + path + '" fill="currentColor"/>' +
    '</svg>'
}

function metricDotSvg(color) {
  const size = CDC_GEOM.metricDotSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size/2) + '" cy="' + (size/2) + '" r="' + (size/2) + '" fill="currentColor"/>' +
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

function chartDonutContextChromeSpecs() {
  const g = CDC_GEOM
  const specs = []
  
  // Badge background
  specs.push({
    slotId: 'CDC_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: '#DBEAFE',
    layer: 3,
    kind: 'badge',
  })
  
  // Badge icon
  specs.push({
    slotId: 'CDC_BADGE_ICON',
    x: g.badgeX + 10,
    y: g.badgeY + 4,
    w: g.badgeIconSize,
    h: g.badgeIconSize,
    color: '#3B82F6',
    layer: 10,
    kind: 'badgeIcon',
  })
  
  // Panel background
  specs.push({
    slotId: 'CDC_PANEL_BG',
    x: g.panelX,
    y: g.panelY,
    w: g.panelW,
    h: g.panelH,
    color: '#F0F9FF',
    layer: 3,
    kind: 'panelBg',
  })
  
  // Donut segments (4 segments) - constrained to donut area only
  CDC_SEGMENTS.forEach(function(segment, i) {
    var donutLeft = g.donutCenterX - g.donutOuterRadius
    var donutTop = g.donutCenterY - g.donutOuterRadius
    var donutSize = g.donutOuterRadius * 2
    
    specs.push({
      slotId: 'CDC_SEGMENT_' + segment.id,
      x: donutLeft,
      y: donutTop,
      w: donutSize,
      h: donutSize,
      color: segment.color,
      layer: 5,
      kind: 'donutSegment',
      segmentData: segment,
    })
  })
  
  // Metric dots in panel (4 metrics)
  CDC_SEGMENTS.forEach(function(segment, i) {
    specs.push({
      slotId: 'CDC_METRIC_DOT_' + segment.id,
      x: g.panelX + g.metricDotX,
      y: g.panelY + g.metricStartY + (i * g.metricGap) + 3,
      w: g.metricDotSize,
      h: g.metricDotSize,
      color: segment.color,
      layer: 10,
      kind: 'metricDot',
    })
  })
  
  return specs
}

// Mirrored version for right-side donut
function chartDonutContextRightChromeSpecs() {
  var specs = chartDonutContextChromeSpecs()
  var g = CDC_GEOM
  
  // Mirror positions horizontally
  return specs.map(function(spec) {
    var mirrored = Object.assign({}, spec)
    
    // Mirror badge
    if (spec.slotId === 'CDC_BADGE_BG' || spec.slotId === 'CDC_BADGE_ICON') {
      mirrored.x = g.viewW - spec.x - spec.w
    }
    
    // Mirror panel
    if (spec.slotId === 'CDC_PANEL_BG') {
      mirrored.x = 40 // Left side instead of right
    }
    
    // Mirror donut
    if (spec.slotId.indexOf('CDC_SEGMENT_') === 0) {
      var donutNewCenterX = 770 // Right side
      var donutLeft = donutNewCenterX - g.donutOuterRadius
      mirrored.x = donutLeft
    }
    
    // Mirror metric dots
    if (spec.slotId.indexOf('CDC_METRIC_DOT_') === 0) {
      mirrored.x = 40 + g.metricDotX
    }
    
    return mirrored
  })
}

function chartDonutContextOverlay(gx, gy, gw, gh) {
  const g = CDC_GEOM
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
    badge: box(g.badgeX + g.badgeIconSize + 14, g.badgeY, g.badgeW - g.badgeIconSize - 20, g.badgeH),
    
    // Center text in donut
    centerValue: box(g.donutCenterX - 60, g.centerTextY - 20, 120, 40),
    centerLabel: box(g.donutCenterX - 60, g.centerLabelY - 10, 120, 24),
    
    // Context panel
    panelHeading: box(g.panelX + g.panelHeadingX, g.panelY + g.panelHeadingY, 340, 36),
    panelSubheading: box(g.panelX + g.panelSubheadingX, g.panelY + g.panelSubheadingY, g.panelSubheadingW, g.panelSubheadingH),
  }
  
  // Metric breakdowns in panel (4 metrics)
  CDC_SEGMENTS.forEach(function(segment, i) {
    const y = g.panelY + g.metricStartY + (i * g.metricGap)
    overlays['metric' + segment.id + 'Label'] = box(g.panelX + g.metricLabelX, y, 240, 20)
    overlays['metric' + segment.id + 'Value'] = box(g.panelX + g.metricValueX, y, 40, 20)
    overlays['metric' + segment.id + 'Desc'] = box(g.panelX + g.metricDescX, y + g.metricDescY, 360, g.metricDescH || 42)
  })
  
  return overlays
}

// Mirrored overlay for right-side donut
function chartDonutContextRightOverlay(gx, gy, gw, gh) {
  var g = CDC_GEOM
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
  
  var donutNewCenterX = 770 // Right side
  var panelNewX = 40 // Left side
  
  var overlays = {
    badge: box(g.viewW - g.badgeX - g.badgeW + g.badgeIconSize + 14, g.badgeY, g.badgeW - g.badgeIconSize - 20, g.badgeH),
    
    // Center text in donut (right side)
    centerValue: box(donutNewCenterX - 60, g.centerTextY - 20, 120, 40),
    centerLabel: box(donutNewCenterX - 60, g.centerLabelY - 10, 120, 24),
    
    // Context panel (left side)
    panelHeading: box(panelNewX + g.panelHeadingX, g.panelY + g.panelHeadingY, 340, 36),
    panelSubheading: box(panelNewX + g.panelSubheadingX, g.panelY + g.panelSubheadingY, g.panelSubheadingW, g.panelSubheadingH),
  }
  
  // Metric breakdowns in panel (left side)
  CDC_SEGMENTS.forEach(function(segment, i) {
    var y = g.panelY + g.metricStartY + (i * g.metricGap)
    overlays['metric' + segment.id + 'Label'] = box(panelNewX + g.metricLabelX, y, 240, 20)
    overlays['metric' + segment.id + 'Value'] = box(panelNewX + g.metricValueX, y, 40, 20)
    overlays['metric' + segment.id + 'Desc'] = box(panelNewX + g.metricDescX, y + g.metricDescY, 360, g.metricDescH || 42)
  })
  
  return overlays
}

function specToChartDonutContextContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelBg') return { svg: panelBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'metricDot') return { svg: metricDotSvg(spec.color), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'donutSegment' && spec.segmentData) {
    return { svg: donutSegmentSvg(spec.segmentData, spec.w, spec.h), colorMode: 'recolor', fill: spec.color }
  }
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
    : (CDC_DEFAULTS[sid] || existing)
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

function layoutChartDonutContext(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / CDC_GEOM.viewW
  const sy = canvasH / CDC_GEOM.viewH
  
  // Detect if this is the mirrored "right" layout
  var layoutId = (schema && (schema.layout_id || schema.id || schema.layoutId)) || ''
  var isRightLayout = isChartDonutContextRightLayout(layoutId)
  
  var overlay = isRightLayout 
    ? chartDonutContextRightOverlay(0, 0, canvasW, canvasH)
    : chartDonutContextOverlay(0, 0, canvasW, canvasH)
    
  const chromeRe = /^CDC_/i
  
  const prevBySlot = new Map()
  elements.filter(function(el) {
    return chromeRe.test(String(el.slotId || ''))
  }).forEach(function(el) {
    prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
  })
  
  const filtered = elements.filter(function(el) {
    return !chromeRe.test(String(el.slotId || '')) && isChartDonutContextTextSlot(el.slotId)
  })
  const bySlot = new Map()
  filtered.forEach(function(el) {
    bySlot.set(String(el.slotId || ''), el)
  })

  function placeText(slotId, box, style, role) {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-cdc'),
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
      align: 'center', verticalAlign: 'center', fontSize: 9, fontWeight: 700, color: '#2563EB', clipToSlot: true, lineHeight: 1, letterSpacing: '1px',
    }, 'caption'),
    
    // Center text in donut
    placeText('CENTER_VALUE', overlay.centerValue, {
      align: 'center', verticalAlign: 'center', fontSize: 48, fontWeight: 900, color: headingInk(palette), clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('CENTER_LABEL', overlay.centerLabel, {
      align: 'center', verticalAlign: 'center', fontSize: 15, fontWeight: 500, color: '#64748B', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    
    // Context panel
    placeText('PANEL_HEADING', overlay.panelHeading, {
      align: 'left', verticalAlign: 'top', fontSize: 36, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('PANEL_SUBHEADING', overlay.panelSubheading, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
  ]
  
  // Metric breakdowns in panel (4 metrics)
  CDC_SEGMENTS.forEach(function(segment) {
    next.push(
      placeText('METRIC_' + segment.id + '_LABEL', overlay['metric' + segment.id + 'Label'], {
        align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 700, color: '#0F172A', clipToSlot: true, lineHeight: 1,
      }, 'caption'),
      placeText('METRIC_' + segment.id + '_VALUE', overlay['metric' + segment.id + 'Value'], {
        align: 'right', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: '#0F172A', clipToSlot: true, lineHeight: 1,
      }, 'caption'),
      placeText('METRIC_' + segment.id + '_DESC', overlay['metric' + segment.id + 'Desc'], {
        align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
      }, 'body')
    )
  })

  const chrome = (isRightLayout ? chartDonutContextRightChromeSpecs() : chartDonutContextChromeSpecs()).map(function(spec) {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToChartDonutContextContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-cdc'),
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
  isChartDonutContextLayout: isChartDonutContextLayout,
  layoutChartDonutContext: layoutChartDonutContext,
  CDC_GEOM: CDC_GEOM,
  CDC_DEFAULTS: CDC_DEFAULTS,
}
