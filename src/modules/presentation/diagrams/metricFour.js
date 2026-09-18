/**
 * Metric four — Four side-by-side metrics with icons and gradient underlines.
 * CommonJS backend port for Athena VI Presentation diagram pipeline.
 * Layout id: metric_four_v1.
 */

const MFOUR_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Title decoration (top left)
  decoX: 40,
  decoY: 60,
  decoW: 50,
  decoH: 6,

  // Heading
  headingX: 40,
  headingY: 80,
  headingW: 600,
  headingH: 55,

  // Four metrics in a row
  metric1X: 40,
  metric2X: 280,
  metric3X: 520,
  metric4X: 760,
  metricY: 180,
  metricW: 200,
  metricH: 250,

  // Inside each metric column
  iconX: 70,
  iconY: 0,
  iconSize: 40,
  iconBgSize: 60,

  valueX: 0,
  valueY: 85,
  valueW: 200,
  valueH: 70,

  labelX: 0,
  labelY: 165,
  labelW: 200,
  labelH: 30,

  underlineX: 55,
  underlineY: 210,
  underlineW: 90,
  underlineH: 5,

  // Vertical dividers between columns
  divider1X: 260,
  divider2X: 500,
  divider3X: 740,
  dividerY: 200,
  dividerW: 1,
  dividerH: 200,

  // Decorative circles (bottom left)
  decoCirclesX: 0,
  decoCirclesY: 440,
  decoCirclesW: 200,
  decoCirclesH: 120,
}

const MFOUR_COLORS = {
  metric1: '#3B82F6',  // Blue
  metric2: '#8B5CF6',  // Purple
  metric3: '#10B981',  // Green
  metric4: '#F59E0B',  // Amber
  deco: '#3B82F6',
  divider: '#E2E8F0',
  decoCircles: '#DBEAFE',
}

const MFOUR_DEFAULTS = {
  HEADING: 'Key metrics',

  METRIC1_VALUE: '98%',
  METRIC1_LABEL: 'Satisfaction',
  STAT_1_VALUE: '98%',
  STAT_1_LABEL: 'Satisfaction',

  METRIC2_VALUE: '3.2x',
  METRIC2_LABEL: 'ROI',
  STAT_2_VALUE: '3.2x',
  STAT_2_LABEL: 'ROI',

  METRIC3_VALUE: '500+',
  METRIC3_LABEL: 'Teams',
  STAT_3_VALUE: '500+',
  STAT_3_LABEL: 'Teams',

  METRIC4_VALUE: '24h',
  METRIC4_LABEL: 'Response',
  STAT_4_VALUE: '24h',
  STAT_4_LABEL: 'Response',
}

function isMetricFourLayout(layoutId) {
  return /metric_four_v1$/i.test(String(layoutId || ''))
}

function isMetricFourTextSlot(slotId) {
  var sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || sid === 'METRIC1_VALUE' || sid === 'STAT_1_VALUE'
    || sid === 'METRIC1_LABEL' || sid === 'STAT_1_LABEL'
    || sid === 'METRIC2_VALUE' || sid === 'STAT_2_VALUE'
    || sid === 'METRIC2_LABEL' || sid === 'STAT_2_LABEL'
    || sid === 'METRIC3_VALUE' || sid === 'STAT_3_VALUE'
    || sid === 'METRIC3_LABEL' || sid === 'STAT_3_LABEL'
    || sid === 'METRIC4_VALUE' || sid === 'STAT_4_VALUE'
    || sid === 'METRIC4_LABEL' || sid === 'STAT_4_LABEL'
}

function decoSvg() {
  var g = MFOUR_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.decoW + ' ' + g.decoH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.decoW + '" height="' + g.decoH + '" fill="' + MFOUR_COLORS.deco + '" rx="3"/>' +
  '</svg>'
}

function iconBgSvg(color) {
  var size = MFOUR_GEOM.iconBgSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="' + (size / 2) + '" cy="' + (size / 2) + '" r="' + (size / 2) + '" fill="' + color + '" fill-opacity="0.15"/>' +
  '</svg>'
}

function icon1Svg() {
  var size = MFOUR_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="13" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2.5"/>' +
    '<circle cx="27" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2.5"/>' +
    '<path d="M7 27 Q10 24 13 24 Q16 24 20 24 Q24 24 27 24 Q30 24 33 27 L33 34 L7 34 Z" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/>' +
  '</svg>'
}

function icon2Svg() {
  var size = MFOUR_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<path d="M7 28 L14 14 L21 21 L33 9" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<polyline points="26,9 33,9 33,16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function icon3Svg() {
  var size = MFOUR_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="10" cy="10" r="5" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<circle cx="24" cy="10" r="5" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<circle cx="30" cy="24" r="5" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<circle cx="17" cy="27" r="5" fill="none" stroke="currentColor" stroke-width="2"/>' +
    '<path d="M13 13 L15 22" stroke="currentColor" stroke-width="2"/>' +
    '<path d="M21 13 L19 22" stroke="currentColor" stroke-width="2"/>' +
    '<path d="M25 19 L22 23" stroke="currentColor" stroke-width="2"/>' +
  '</svg>'
}

function icon4Svg() {
  var size = MFOUR_GEOM.iconSize
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">' +
    '<circle cx="20" cy="20" r="13" fill="none" stroke="currentColor" stroke-width="2.5"/>' +
    '<polyline points="20,12 20,20 26,20" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
  '</svg>'
}

function underlineSvg(color) {
  var g = MFOUR_GEOM
  var cClean = color.replace('#', '')
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.underlineW + ' ' + g.underlineH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<defs>' +
      '<linearGradient id="m4UnderlineGrad_' + cClean + '" x1="0%" y1="0%" x2="100%" y2="0%">' +
        '<stop offset="0%" style="stop-color:' + color + ';stop-opacity:0.25" />' +
        '<stop offset="50%" style="stop-color:' + color + ';stop-opacity:1" />' +
        '<stop offset="100%" style="stop-color:' + color + ';stop-opacity:0.25" />' +
      '</linearGradient>' +
    '</defs>' +
    '<rect x="0" y="0" width="' + g.underlineW + '" height="' + g.underlineH + '" fill="url(#m4UnderlineGrad_' + cClean + ')" rx="2.5"/>' +
  '</svg>'
}

function dividerSvg() {
  var g = MFOUR_GEOM
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + g.dividerW + ' ' + g.dividerH + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<rect x="0" y="0" width="' + g.dividerW + '" height="' + g.dividerH + '" fill="' + MFOUR_COLORS.divider + '"/>' +
  '</svg>'
}

function decoCirclesSvg() {
  var w = 200
  var h = 120
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + w + ' ' + h + '" width="100%" height="100%" preserveAspectRatio="none">' +
    '<circle cx="30" cy="60" r="80" fill="' + MFOUR_COLORS.decoCircles + '" opacity="0.25"/>' +
    '<circle cx="80" cy="90" r="60" fill="' + MFOUR_COLORS.decoCircles + '" opacity="0.4"/>' +
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

function metricFourChromeSpecs() {
  var g = MFOUR_GEOM
  var specs = []

  specs.push({
    slotId: 'MFOUR_DECO',
    x: g.decoX,
    y: g.decoY,
    w: g.decoW,
    h: g.decoH,
    color: MFOUR_COLORS.deco,
    layer: 10,
    kind: 'deco',
  })

  var metrics = [
    { x: g.metric1X, color: MFOUR_COLORS.metric1, id: 1 },
    { x: g.metric2X, color: MFOUR_COLORS.metric2, id: 2 },
    { x: g.metric3X, color: MFOUR_COLORS.metric3, id: 3 },
    { x: g.metric4X, color: MFOUR_COLORS.metric4, id: 4 },
  ]

  metrics.forEach(function(metric) {
    specs.push({
      slotId: 'MFOUR_METRIC' + metric.id + '_ICON_BG',
      x: metric.x + g.iconX,
      y: g.metricY + g.iconY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: metric.color,
      layer: 5,
      kind: 'iconBg',
    })

    specs.push({
      slotId: 'MFOUR_METRIC' + metric.id + '_ICON',
      x: metric.x + g.iconX + (g.iconBgSize - g.iconSize) / 2,
      y: g.metricY + g.iconY + (g.iconBgSize - g.iconSize) / 2,
      w: g.iconSize,
      h: g.iconSize,
      color: metric.color,
      layer: 10,
      kind: 'icon' + metric.id,
    })

    specs.push({
      slotId: 'MFOUR_METRIC' + metric.id + '_UNDERLINE',
      x: metric.x + g.underlineX,
      y: g.metricY + g.underlineY,
      w: g.underlineW,
      h: g.underlineH,
      color: metric.color,
      layer: 10,
      kind: 'underline',
    })
  })

  specs.push({
    slotId: 'MFOUR_DIVIDER1',
    x: g.divider1X,
    y: g.dividerY,
    w: g.dividerW,
    h: g.dividerH,
    color: MFOUR_COLORS.divider,
    layer: 3,
    kind: 'divider',
  })

  specs.push({
    slotId: 'MFOUR_DIVIDER2',
    x: g.divider2X,
    y: g.dividerY,
    w: g.dividerW,
    h: g.dividerH,
    color: MFOUR_COLORS.divider,
    layer: 3,
    kind: 'divider',
  })

  specs.push({
    slotId: 'MFOUR_DIVIDER3',
    x: g.divider3X,
    y: g.dividerY,
    w: g.dividerW,
    h: g.dividerH,
    color: MFOUR_COLORS.divider,
    layer: 3,
    kind: 'divider',
  })

  specs.push({
    slotId: 'MFOUR_DECO_CIRCLES',
    x: g.decoCirclesX,
    y: g.decoCirclesY,
    w: g.decoCirclesW,
    h: g.decoCirclesH,
    color: MFOUR_COLORS.decoCircles,
    layer: 2,
    kind: 'decoCircles',
  })

  return specs
}

function metricFourOverlay(gx, gy, gw, gh) {
  var g = MFOUR_GEOM
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
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
  }

  var metricXs = [g.metric1X, g.metric2X, g.metric3X, g.metric4X]
  metricXs.forEach(function(metricX, i) {
    var num = i + 1
    overlays['metric' + num + 'Value'] = box(metricX + g.valueX, g.metricY + g.valueY, g.valueW, g.valueH)
    overlays['metric' + num + 'Label'] = box(metricX + g.labelX, g.metricY + g.labelY, g.labelW, g.labelH)
  })

  return overlays
}

function specToMetricFourContent(spec) {
  if (spec.kind === 'deco') return { svg: decoSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon1') return { svg: icon1Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'icon2') return { svg: icon2Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'icon3') return { svg: icon3Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'icon4') return { svg: icon4Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'underline') return { svg: underlineSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'divider') return { svg: dividerSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'decoCircles') return { svg: decoCirclesSvg(), colorMode: 'fixed', fill: spec.color }
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
  var defaultKey = sid.indexOf('STAT_') === 0
    ? sid.replace('STAT_1_', 'METRIC1_').replace('STAT_2_', 'METRIC2_').replace('STAT_3_', 'METRIC3_').replace('STAT_4_', 'METRIC4_')
    : sid
  var text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (MFOUR_DEFAULTS[defaultKey] || MFOUR_DEFAULTS[sid] || existing)
  
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

function layoutMetricFour(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements
  palette = palette || {}
  canvas = canvas || {}
  var canvasW = canvas.width || 1920
  var canvasH = canvas.height || 1080
  var sx = canvasW / MFOUR_GEOM.viewW
  var sy = canvasH / MFOUR_GEOM.viewH
  var overlay = metricFourOverlay(0, 0, canvasW, canvasH)
  var chromeRe = /^MFOUR_/i

  var prevBySlot = new Map()
  elements.forEach(function(el) {
    if (chromeRe.test(String(el.slotId || ''))) {
      prevBySlot.set(String(el.slotId || '').toUpperCase(), el)
    }
  })

  var bySlot = new Map()
  elements.forEach(function(el) {
    if (!chromeRe.test(String(el.slotId || '')) && isMetricFourTextSlot(el.slotId)) {
      bySlot.set(String(el.slotId || '').toUpperCase(), el)
    }
  })

  var placeText = function(slotId, box, style, role) {
    var prev = bySlot.get(slotId.toUpperCase())
    return {
      id: (prev && prev.id) || newId('txt-m4'),
      type: 'text',
      slotId: slotId,
      role: (prev && prev.role) || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  var next = [
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 52, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
  ]

  for (var i = 1; i <= 4; i++) {
    var valSlot = bySlot.has('METRIC' + i + '_VALUE') ? ('METRIC' + i + '_VALUE') : ('STAT_' + i + '_VALUE')
    var lblSlot = bySlot.has('METRIC' + i + '_LABEL') ? ('METRIC' + i + '_LABEL') : ('STAT_' + i + '_LABEL')
    next.push(
      placeText(valSlot, overlay['metric' + i + 'Value'], {
        align: 'center', verticalAlign: 'center', fontSize: 60, fontWeight: 900, color: '#1E293B', clipToSlot: true, lineHeight: 1,
      }, 'heading'),
      placeText(lblSlot, overlay['metric' + i + 'Label'], {
        align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 600, color: '#64748B', clipToSlot: true, lineHeight: 1.3,
      }, 'caption')
    )
  }

  var chrome = metricFourChromeSpecs().map(function(spec) {
    var prev = prevBySlot.get(spec.slotId.toUpperCase())
    var graphic = specToMetricFourContent(spec)
    if (!graphic) return null
    return {
      id: (prev && prev.id) || newId('shp-m4'),
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

function metricFourPreviewSvg(previewHints, theme) {
  previewHints = previewHints || {}
  theme = theme || {}
  var slots = previewHints.slots || {}
  var stats = previewHints.stats || []

  var headingText = (slots.HEADING && slots.HEADING.text) || previewHints.heading || MFOUR_DEFAULTS.HEADING
  var m1v = (slots.METRIC1_VALUE && slots.METRIC1_VALUE.text) || (slots.STAT_1_VALUE && slots.STAT_1_VALUE.text) || (stats[0] && stats[0].value) || MFOUR_DEFAULTS.METRIC1_VALUE
  var m1l = (slots.METRIC1_LABEL && slots.METRIC1_LABEL.text) || (slots.STAT_1_LABEL && slots.STAT_1_LABEL.text) || (stats[0] && stats[0].label) || MFOUR_DEFAULTS.METRIC1_LABEL
  var m2v = (slots.METRIC2_VALUE && slots.METRIC2_VALUE.text) || (slots.STAT_2_VALUE && slots.STAT_2_VALUE.text) || (stats[1] && stats[1].value) || MFOUR_DEFAULTS.METRIC2_VALUE
  var m2l = (slots.METRIC2_LABEL && slots.METRIC2_LABEL.text) || (slots.STAT_2_LABEL && slots.STAT_2_LABEL.text) || (stats[1] && stats[1].label) || MFOUR_DEFAULTS.METRIC2_LABEL
  var m3v = (slots.METRIC3_VALUE && slots.METRIC3_VALUE.text) || (slots.STAT_3_VALUE && slots.STAT_3_VALUE.text) || (stats[2] && stats[2].value) || MFOUR_DEFAULTS.METRIC3_VALUE
  var m3l = (slots.METRIC3_LABEL && slots.METRIC3_LABEL.text) || (slots.STAT_3_LABEL && slots.STAT_3_LABEL.text) || (stats[2] && stats[2].label) || MFOUR_DEFAULTS.METRIC3_LABEL
  var m4v = (slots.METRIC4_VALUE && slots.METRIC4_VALUE.text) || (slots.STAT_4_VALUE && slots.STAT_4_VALUE.text) || (stats[3] && stats[3].value) || MFOUR_DEFAULTS.METRIC4_VALUE
  var m4l = (slots.METRIC4_LABEL && slots.METRIC4_LABEL.text) || (slots.STAT_4_LABEL && slots.STAT_4_LABEL.text) || (stats[3] && stats[3].label) || MFOUR_DEFAULTS.METRIC4_LABEL

  var c1 = MFOUR_COLORS.metric1
  var c2 = MFOUR_COLORS.metric2
  var c3 = MFOUR_COLORS.metric3
  var c4 = MFOUR_COLORS.metric4

  var lines = []
  lines.push('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">')
  lines.push('  <defs>')
  lines.push('    <linearGradient id="m4u1" x1="0%" y1="0%" x2="100%" y2="0%">')
  lines.push('      <stop offset="0%" stop-color="' + c1 + '" stop-opacity="0.25"/>')
  lines.push('      <stop offset="50%" stop-color="' + c1 + '" stop-opacity="1"/>')
  lines.push('      <stop offset="100%" stop-color="' + c1 + '" stop-opacity="0.25"/>')
  lines.push('    </linearGradient>')
  lines.push('    <linearGradient id="m4u2" x1="0%" y1="0%" x2="100%" y2="0%">')
  lines.push('      <stop offset="0%" stop-color="' + c2 + '" stop-opacity="0.25"/>')
  lines.push('      <stop offset="50%" stop-color="' + c2 + '" stop-opacity="1"/>')
  lines.push('      <stop offset="100%" stop-color="' + c2 + '" stop-opacity="0.25"/>')
  lines.push('    </linearGradient>')
  lines.push('    <linearGradient id="m4u3" x1="0%" y1="0%" x2="100%" y2="0%">')
  lines.push('      <stop offset="0%" stop-color="' + c3 + '" stop-opacity="0.25"/>')
  lines.push('      <stop offset="50%" stop-color="' + c3 + '" stop-opacity="1"/>')
  lines.push('      <stop offset="100%" stop-color="' + c3 + '" stop-opacity="0.25"/>')
  lines.push('    </linearGradient>')
  lines.push('    <linearGradient id="m4u4" x1="0%" y1="0%" x2="100%" y2="0%">')
  lines.push('      <stop offset="0%" stop-color="' + c4 + '" stop-opacity="0.25"/>')
  lines.push('      <stop offset="50%" stop-color="' + c4 + '" stop-opacity="1"/>')
  lines.push('      <stop offset="100%" stop-color="' + c4 + '" stop-opacity="0.25"/>')
  lines.push('    </linearGradient>')
  lines.push('  </defs>')

  lines.push('  <rect width="1000" height="560" fill="#FFFFFF" rx="12"/>')
  lines.push('  <circle cx="30" cy="500" r="80" fill="' + MFOUR_COLORS.decoCircles + '" opacity="0.25"/>')
  lines.push('  <circle cx="80" cy="530" r="60" fill="' + MFOUR_COLORS.decoCircles + '" opacity="0.4"/>')
  lines.push('  <rect x="' + MFOUR_GEOM.decoX + '" y="' + MFOUR_GEOM.decoY + '" width="' + MFOUR_GEOM.decoW + '" height="' + MFOUR_GEOM.decoH + '" rx="3" fill="' + MFOUR_COLORS.deco + '"/>')
  lines.push('  <text x="' + MFOUR_GEOM.headingX + '" y="124" fill="#0F172A" font-size="52" font-weight="800" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + headingText + '</text>')

  lines.push('  <rect x="' + MFOUR_GEOM.divider1X + '" y="' + MFOUR_GEOM.dividerY + '" width="1" height="' + MFOUR_GEOM.dividerH + '" fill="' + MFOUR_COLORS.divider + '"/>')
  lines.push('  <rect x="' + MFOUR_GEOM.divider2X + '" y="' + MFOUR_GEOM.dividerY + '" width="1" height="' + MFOUR_GEOM.dividerH + '" fill="' + MFOUR_COLORS.divider + '"/>')
  lines.push('  <rect x="' + MFOUR_GEOM.divider3X + '" y="' + MFOUR_GEOM.dividerY + '" width="1" height="' + MFOUR_GEOM.dividerH + '" fill="' + MFOUR_COLORS.divider + '"/>')

  // Col 1
  lines.push('  <circle cx="140" cy="210" r="30" fill="' + c1 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(120, 190)">')
  lines.push('    <circle cx="13" cy="12" r="6" fill="none" stroke="' + c1 + '" stroke-width="2.5"/>')
  lines.push('    <circle cx="27" cy="12" r="6" fill="none" stroke="' + c1 + '" stroke-width="2.5"/>')
  lines.push('    <path d="M7 27 Q10 24 13 24 Q16 24 20 24 Q24 24 27 24 Q30 24 33 27 L33 34 L7 34 Z" fill="none" stroke="' + c1 + '" stroke-width="2.5" stroke-linejoin="round"/>')
  lines.push('  </g>')
  lines.push('  <text x="140" y="325" text-anchor="middle" fill="#1E293B" font-size="60" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m1v + '</text>')
  lines.push('  <text x="140" y="372" text-anchor="middle" fill="#64748B" font-size="16" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m1l + '</text>')
  lines.push('  <rect x="95" y="396" width="90" height="5" rx="2.5" fill="url(#m4u1)"/>')

  // Col 2
  lines.push('  <circle cx="380" cy="210" r="30" fill="' + c2 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(360, 190)">')
  lines.push('    <path d="M7 28 L14 14 L21 21 L33 9" fill="none" stroke="' + c2 + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('    <polyline points="26,9 33,9 33,16" fill="none" stroke="' + c2 + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('  </g>')
  lines.push('  <text x="380" y="325" text-anchor="middle" fill="#1E293B" font-size="60" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m2v + '</text>')
  lines.push('  <text x="380" y="372" text-anchor="middle" fill="#64748B" font-size="16" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m2l + '</text>')
  lines.push('  <rect x="335" y="396" width="90" height="5" rx="2.5" fill="url(#m4u2)"/>')

  // Col 3
  lines.push('  <circle cx="620" cy="210" r="30" fill="' + c3 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(600, 190)">')
  lines.push('    <circle cx="10" cy="10" r="5" fill="none" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <circle cx="24" cy="10" r="5" fill="none" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <circle cx="30" cy="24" r="5" fill="none" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <circle cx="17" cy="27" r="5" fill="none" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <path d="M13 13 L15 22" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <path d="M21 13 L19 22" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('    <path d="M25 19 L22 23" stroke="' + c3 + '" stroke-width="2"/>')
  lines.push('  </g>')
  lines.push('  <text x="620" y="325" text-anchor="middle" fill="#1E293B" font-size="60" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m3v + '</text>')
  lines.push('  <text x="620" y="372" text-anchor="middle" fill="#64748B" font-size="16" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m3l + '</text>')
  lines.push('  <rect x="575" y="396" width="90" height="5" rx="2.5" fill="url(#m4u3)"/>')

  // Col 4
  lines.push('  <circle cx="860" cy="210" r="30" fill="' + c4 + '" fill-opacity="0.15"/>')
  lines.push('  <g transform="translate(840, 190)">')
  lines.push('    <circle cx="20" cy="20" r="13" fill="none" stroke="' + c4 + '" stroke-width="2.5"/>')
  lines.push('    <polyline points="20,12 20,20 26,20" fill="none" stroke="' + c4 + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>')
  lines.push('  </g>')
  lines.push('  <text x="860" y="325" text-anchor="middle" fill="#1E293B" font-size="60" font-weight="900" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m4v + '</text>')
  lines.push('  <text x="860" y="372" text-anchor="middle" fill="#64748B" font-size="16" font-weight="600" font-family="system-ui, -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif">' + m4l + '</text>')
  lines.push('  <rect x="815" y="396" width="90" height="5" rx="2.5" fill="url(#m4u4)"/>')

  lines.push('</svg>')
  return lines.join('\n')
}

module.exports = {
  isMetricFourLayout: isMetricFourLayout,
  isMetricFourTextSlot: isMetricFourTextSlot,
  layoutMetricFour: layoutMetricFour,
  metricFourPreviewSvg: metricFourPreviewSvg,
  MFOUR_GEOM: MFOUR_GEOM,
  MFOUR_DEFAULTS: MFOUR_DEFAULTS,
  MFOUR_COLORS: MFOUR_COLORS,
}
