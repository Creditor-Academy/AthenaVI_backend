/**
 * Metric three — Three side-by-side metrics with icons and underlines.
 * Layout id: metric_three_v1.
 */

const MTH_GEOM = {
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
  
  // Three metrics in a row
  metric1X: 60,
  metric2X: 360,
  metric3X: 660,
  metricY: 180,
  metricW: 280,
  metricH: 250,
  
  // Inside each metric card
  iconX: 115,
  iconY: 0,
  iconSize: 40,
  iconBgSize: 60,
  
  valueX: 0,
  valueY: 85,
  valueW: 280,
  valueH: 80,
  
  labelX: 0,
  labelY: 175,
  labelW: 280,
  labelH: 32,
  
  underlineX: 90,
  underlineY: 220,
  underlineW: 100,
  underlineH: 5,
  
  // Vertical dividers between cards
  divider1X: 340,
  divider2X: 640,
  dividerY: 200,
  dividerW: 1,
  dividerH: 200,
  
  // Decorative circles (bottom left)
  decoCirclesX: 0,
  decoCirclesY: 440,
  decoCirclesW: 200,
  decoCirclesH: 120,
}

const MTH_COLORS = {
  metric1: '#3B82F6',  // Blue
  metric2: '#8B5CF6',  // Purple
  metric3: '#10B981',  // Green
  deco: '#3B82F6',
  divider: '#E2E8F0',
  decoCircles: '#DBEAFE',
}

const MTH_DEFAULTS = {
  HEADING: 'Key metrics',
  
  METRIC1_VALUE: '98%',
  METRIC1_LABEL: 'Customer satisfaction',
  
  METRIC2_VALUE: '3.2x',
  METRIC2_LABEL: 'Average ROI',
  
  METRIC3_VALUE: '500+',
  METRIC3_LABEL: 'Active teams',
}

const isMetricThreeLayout = (layoutId) => {
  return /metric_three_v1$/i.test(String(layoutId || ''))
}

const isMetricThreeTextSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'METRIC1_VALUE'
    || sid === 'METRIC1_LABEL'
    || sid === 'METRIC2_VALUE'
    || sid === 'METRIC2_LABEL'
    || sid === 'METRIC3_VALUE'
    || sid === 'METRIC3_LABEL'
}

const decoSvg = () => {
  const g = MTH_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.decoW} ${g.decoH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.decoW}" height="${g.decoH}" fill="${MTH_COLORS.deco}" rx="3"/>
  </svg>`
}

const iconBgSvg = (color) => {
  const size = MTH_GEOM.iconBgSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size/2}" cy="${size/2}" r="${size/2}" fill="${color}" fill-opacity="0.15"/>
  </svg>`
}

const icon1Svg = () => {
  const size = MTH_GEOM.iconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="13" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2.5"/>
    <circle cx="27" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2.5"/>
    <path d="M7 27 Q10 24 13 24 Q16 24 20 24 Q24 24 27 24 Q30 24 33 27 L33 34 L7 34 Z" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/>
  </svg>`
}

const icon2Svg = () => {
  const size = MTH_GEOM.iconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <path d="M7 28 L14 14 L21 21 L33 9" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="26,9 33,9 33,16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`
}

const icon3Svg = () => {
  const size = MTH_GEOM.iconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="10" cy="10" r="5" fill="none" stroke="currentColor" stroke-width="2"/>
    <circle cx="24" cy="10" r="5" fill="none" stroke="currentColor" stroke-width="2"/>
    <circle cx="30" cy="24" r="5" fill="none" stroke="currentColor" stroke-width="2"/>
    <circle cx="17" cy="27" r="5" fill="none" stroke="currentColor" stroke-width="2"/>
    <path d="M13 13 L15 22" stroke="currentColor" stroke-width="2"/>
    <path d="M21 13 L19 22" stroke="currentColor" stroke-width="2"/>
    <path d="M25 19 L22 23" stroke="currentColor" stroke-width="2"/>
  </svg>`
}

const underlineSvg = (color) => {
  const g = MTH_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.underlineW} ${g.underlineH}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="underlineGrad_${color.replace('#','')}" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" style="stop-color:${color};stop-opacity:0.3" />
        <stop offset="50%" style="stop-color:${color};stop-opacity:1" />
        <stop offset="100%" style="stop-color:${color};stop-opacity:0.3" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${g.underlineW}" height="${g.underlineH}" fill="url(#underlineGrad_${color.replace('#','')})" rx="2.5"/>
  </svg>`
}

const dividerSvg = () => {
  const g = MTH_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.dividerW} ${g.dividerH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.dividerW}" height="${g.dividerH}" fill="${MTH_COLORS.divider}"/>
  </svg>`
}

const decoCirclesSvg = () => {
  const w = 200
  const h = 120
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <circle cx="30" cy="60" r="80" fill="${MTH_COLORS.decoCircles}" opacity="0.25"/>
    <circle cx="80" cy="90" r="60" fill="${MTH_COLORS.decoCircles}" opacity="0.4"/>
  </svg>`
}

const hexLum = (hex) => {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4))
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

const headingInk = (palette = {}) => {
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827'
}

const metricThreeChromeSpecs = () => {
  const g = MTH_GEOM
  const specs = []
  
  // Title decoration
  specs.push({
    slotId: 'MTH_DECO',
    x: g.decoX,
    y: g.decoY,
    w: g.decoW,
    h: g.decoH,
    color: MTH_COLORS.deco,
    layer: 10,
    kind: 'deco',
  })
  
  // Three metrics
  const metrics = [
    { x: g.metric1X, color: MTH_COLORS.metric1, id: 1 },
    { x: g.metric2X, color: MTH_COLORS.metric2, id: 2 },
    { x: g.metric3X, color: MTH_COLORS.metric3, id: 3 },
  ]
  
  metrics.forEach(metric => {
    // Icon background
    specs.push({
      slotId: `MTH_METRIC${metric.id}_ICON_BG`,
      x: metric.x + g.iconX,
      y: g.metricY + g.iconY,
      w: g.iconBgSize,
      h: g.iconBgSize,
      color: metric.color,
      layer: 5,
      kind: 'iconBg',
    })
    
    // Icon
    specs.push({
      slotId: `MTH_METRIC${metric.id}_ICON`,
      x: metric.x + g.iconX + (g.iconBgSize - g.iconSize) / 2,
      y: g.metricY + g.iconY + (g.iconBgSize - g.iconSize) / 2,
      w: g.iconSize,
      h: g.iconSize,
      color: metric.color,
      layer: 10,
      kind: `icon${metric.id}`,
    })
    
    // Underline
    specs.push({
      slotId: `MTH_METRIC${metric.id}_UNDERLINE`,
      x: metric.x + g.underlineX,
      y: g.metricY + g.underlineY,
      w: g.underlineW,
      h: g.underlineH,
      color: metric.color,
      layer: 10,
      kind: 'underline',
    })
  })
  
  // Dividers
  specs.push({
    slotId: 'MTH_DIVIDER1',
    x: g.divider1X,
    y: g.dividerY,
    w: g.dividerW,
    h: g.dividerH,
    color: MTH_COLORS.divider,
    layer: 3,
    kind: 'divider',
  })
  
  specs.push({
    slotId: 'MTH_DIVIDER2',
    x: g.divider2X,
    y: g.dividerY,
    w: g.dividerW,
    h: g.dividerH,
    color: MTH_COLORS.divider,
    layer: 3,
    kind: 'divider',
  })
  
  // Decorative circles
  specs.push({
    slotId: 'MTH_DECO_CIRCLES',
    x: g.decoCirclesX,
    y: g.decoCirclesY,
    w: g.decoCirclesW,
    h: g.decoCirclesH,
    color: MTH_COLORS.decoCircles,
    layer: 2,
    kind: 'decoCircles',
  })
  
  return specs
}

const metricThreeOverlay = (gx, gy, gw, gh) => {
  const g = MTH_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const overlays = {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
  }
  
  // Metric text overlays
  const metricXs = [g.metric1X, g.metric2X, g.metric3X]
  metricXs.forEach((metricX, i) => {
    const num = i + 1
    overlays[`metric${num}Value`] = box(metricX + g.valueX, g.metricY + g.valueY, g.valueW, g.valueH)
    overlays[`metric${num}Label`] = box(metricX + g.labelX, g.metricY + g.labelY, g.labelW, g.labelH)
  })
  
  return overlays
}

const specToMetricThreeContent = (spec) => {
  if (spec.kind === 'deco') return { svg: decoSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon1') return { svg: icon1Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'icon2') return { svg: icon2Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'icon3') return { svg: icon3Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'underline') return { svg: underlineSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'divider') return { svg: dividerSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'decoCircles') return { svg: decoCirclesSvg(), colorMode: 'fixed', fill: spec.color }
  return null
}

const plainTextFromContent = (content = {}) => {
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map((r) => r.text || '').join('')
    if (joined.trim()) return joined
  }
  return ''
}

const filledContent = (el, slotId, style) => {
  const sid = String(slotId || '')
  const existing = plainTextFromContent(el?.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (MTH_DEFAULTS[sid] || existing)
  return {
    ...(el?.content || {}),
    ...style,
    text,
    runs: null,
    listType: null,
    letterSpacing: style.letterSpacing !== undefined ? style.letterSpacing : '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  }
}

const newId = (prefix) => {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

const layoutMetricThree = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / MTH_GEOM.viewW
  const sy = canvasH / MTH_GEOM.viewH
  const overlay = metricThreeOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^MTH_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricThreeTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-mth'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 52, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
  ]
  
  // Metric text elements
  const colors = [MTH_COLORS.metric1, MTH_COLORS.metric2, MTH_COLORS.metric3]
  for (let i = 1; i <= 3; i++) {
    next.push(
      placeText(`METRIC${i}_VALUE`, overlay[`metric${i}Value`], {
        align: 'center', verticalAlign: 'center', fontSize: 68, fontWeight: 900, color: colors[i-1], clipToSlot: true, lineHeight: 1,
      }, 'heading'),
      placeText(`METRIC${i}_LABEL`, overlay[`metric${i}Label`], {
        align: 'center', verticalAlign: 'center', fontSize: 17, fontWeight: 600, color: '#64748B', clipToSlot: true, lineHeight: 1.3,
      }, 'caption')
    )
  }

  const chrome = metricThreeChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToMetricThreeContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-mth'),
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
  
  return [...chrome, ...next]
}


module.exports = {
  isMetricThreeLayout: isMetricThreeLayout,
  layoutMetricThree: layoutMetricThree,
  MTH_GEOM: MTH_GEOM,
  MTH_DEFAULTS: MTH_DEFAULTS,
};