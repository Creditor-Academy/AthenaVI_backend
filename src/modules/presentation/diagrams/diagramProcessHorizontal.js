/**
 * Timeline process horizontal — two parallel dashed lines with circles, icons, 
 * vertical connectors, and chevron boxes. Based on infographic style.
 * Layout id: timeline_process_horizontal_v1.
 */

const TPH_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 40,
  headingY: 16,
  headingW: 920,
  headingH: 40,
  n: 6,
  padX: 80,  // Increased padding to prevent text cutoff
  topLineY: 270,  // Shifted up from 310
  botLineY: 370,  // Shifted up from 410
  circleR: 30,
  circleYHigh: 100,  // Shifted up from 140
  circleYLow: 160,   // Shifted up from 200
  chevronW: 90,
  chevronH: 46,
  textW: 140,
  titleH: 24,
  descH: 50,  // Increased for better text fit
  dotR: 5,
}

const TPH_PALETTE = ['#5B21B6', '#BE185D', '#DC2626', '#059669', '#EA580C', '#CA8A04']

const LOREM = 'Lorem ipsum dolor sit amet.'

const TPH_DEFAULTS = {
  HEADING: 'Horizontal Timeline Infographic',
  ...Array.from({ length: 6 }, (_, i) => {
    const n = i + 1
    const years = ['1980', '1985', '2000', '2005', '2010', '2015']
    const titles = ['Add Your Text Here', 'Add Your Text Here', 'Add Your Text Here', 'Add Your Text Here', 'Add Your Text Here', 'Add Your Text Here']
    return {
      [`step_${n}_year`]: years[i],
      [`step_${n}_title`]: titles[i],
      [`step_${n}_desc`]: LOREM,
    }
  }).reduce((acc, obj) => ({ ...acc, ...obj }), {}),
}

function isTimelineProcessHorizontalLayout(layoutId) {
  return /timeline_process_horizontal_v1$/i.test(String(layoutId || ''))
}

function isTimelineProcessHorizontalTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^step_\d+_(year|title|desc)$/i.test(sid)
}

function stepX(i) {
  const g = TPH_GEOM
  return g.padX + i * ((g.viewW - g.padX * 2) / (g.n - 1))
}

function circleY(i) {
  const g = TPH_GEOM
  // Alternate between high and low positions
  return i % 2 === 0 ? g.circleYLow : g.circleYHigh
}

function linesSvg() {
  const g = TPH_GEOM
  const x1 = g.padX - 30
  const x2 = g.viewW - g.padX + 30
  
  // Add dots at each step position
  const dots = []
  for (let i = 0; i < g.n; i += 1) {
    const x = stepX(i)
    const color = TPH_PALETTE[i]
    dots.push(`<circle cx="${x}" cy="${g.topLineY}" r="${g.dotR}" fill="${color}"/>`)
    dots.push(`<circle cx="${x}" cy="${g.botLineY}" r="${g.dotR}" fill="${color}"/>`)
  }
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="${x1}" y1="${g.topLineY}" x2="${x2}" y2="${g.topLineY}" stroke="#9CA3AF" stroke-width="2" stroke-dasharray="8 6"/>
    <line x1="${x1}" y1="${g.botLineY}" x2="${x2}" y2="${g.botLineY}" stroke="#9CA3AF" stroke-width="2" stroke-dasharray="8 6"/>
    ${dots.join('\n    ')}
  </svg>`
}

function circleSvg(spec) {
  const g = TPH_GEOM
  const r = g.circleR
  // Different icons for each circle
  const icons = [
    // Lightbulb
    `<circle cx="${r}" cy="${r + 4}" r="6" fill="none" stroke="#FFFFFF" stroke-width="2"/><path d="M${r - 3} ${r + 12} L${r + 3} ${r + 12}" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/><path d="M${r} ${r - 4} L${r} ${r - 8}" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>`,
    // Computer/Monitor
    `<rect x="${r - 8}" y="${r - 6}" width="16" height="11" rx="1" fill="none" stroke="#FFFFFF" stroke-width="2"/><path d="M${r - 4} ${r + 5} L${r + 4} ${r + 5}" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>`,
    // Handshake
    `<path d="M${r - 8} ${r} L${r} ${r - 6} L${r + 8} ${r}" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M${r - 4} ${r + 4} L${r + 4} ${r + 4}" stroke="#FFFFFF" stroke-width="2"/>`,
    // Calendar
    `<rect x="${r - 7}" y="${r - 6}" width="14" height="13" rx="1" fill="none" stroke="#FFFFFF" stroke-width="2"/><line x1="${r - 7}" y1="${r - 2}" x2="${r + 7}" y2="${r - 2}" stroke="#FFFFFF" stroke-width="2"/><line x1="${r - 4}" y1="${r - 8}" x2="${r - 4}" y2="${r - 4}" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/><line x1="${r + 4}" y1="${r - 8}" x2="${r + 4}" y2="${r - 4}" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>`,
    // Clock
    `<circle cx="${r}" cy="${r}" r="9" fill="none" stroke="#FFFFFF" stroke-width="2"/><path d="M${r} ${r} L${r} ${r - 5}" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/><path d="M${r} ${r} L${r + 4} ${r}" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>`,
    // Document/Note
    `<rect x="${r - 6}" y="${r - 7}" width="12" height="14" rx="1" fill="none" stroke="#FFFFFF" stroke-width="2"/><line x1="${r - 3}" y1="${r - 3}" x2="${r + 3}" y2="${r - 3}" stroke="#FFFFFF" stroke-width="1.5"/><line x1="${r - 3}" y1="${r + 1}" x2="${r + 3}" y2="${r + 1}" stroke="#FFFFFF" stroke-width="1.5"/>`,
  ]
  const icon = icons[spec.n - 1] || icons[0]
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${r * 2} ${r * 2}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${r}" cy="${r}" r="${r - 2}" fill="currentColor"/>
    ${icon}
  </svg>`
}

function connectorSvg(spec) {
  const g = TPH_GEOM
  const h = g.botLineY - g.topLineY
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2 ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="1" y1="0" x2="1" y2="${h}" stroke="#9CA3AF" stroke-width="2" stroke-dasharray="6 4"/>
  </svg>`
}

function chevronSvg(spec) {
  const g = TPH_GEOM
  const w = g.chevronW
  const h = g.chevronH
  const tipX = w - 8
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="M 0 0 L ${tipX} 0 L ${w} ${h / 2} L ${tipX} ${h} L 0 ${h} L 8 ${h / 2} Z" fill="currentColor"/>
  </svg>`
}

function hexLum(hex) {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette = {}) {
  const bg = palette.bg || palette.background || palette.slideBg
    || palette.colors?.bg || palette.colors?.background || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111111'
}

function timelineProcessHorizontalChromeSpecs() {
  const g = TPH_GEOM
  const specs = [{
    slotId: 'TPH_LINES',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#9CA3AF',
    layer: 2,
    kind: 'lines',
  }]
  
  for (let i = 0; i < g.n; i += 1) {
    const x = stepX(i)
    const cy = circleY(i)
    const color = TPH_PALETTE[i]
    const n = i + 1

    // Circle at alternating heights
    specs.push({
      slotId: `TPH_CIRCLE_${n}`,
      n,
      x: x - g.circleR,
      y: cy - g.circleR,
      w: g.circleR * 2,
      h: g.circleR * 2,
      color,
      layer: 6,
      kind: 'circle',
      fill: color,
    })

    // Vertical connector from circle to bottom line
    const connH = g.botLineY - (cy + g.circleR)
    specs.push({
      slotId: `TPH_CONN_${n}`,
      n,
      x: x - 1,
      y: cy + g.circleR,
      w: 2,
      h: connH,
      color: '#9CA3AF',
      layer: 3,
      kind: 'connector',
    })

    // Chevron between the two lines
    specs.push({
      slotId: `TPH_CHEVRON_${n}`,
      n,
      x: x - g.chevronW / 2,
      y: (g.topLineY + g.botLineY) / 2 - g.chevronH / 2,
      w: g.chevronW,
      h: g.chevronH,
      color,
      layer: 7,
      kind: 'chevron',
      fill: color,
    })
  }
  
  return specs
}

function timelineProcessHorizontalOverlay(gx, gy, gw, gh) {
  const g = TPH_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const years = []
  const titles = []
  const descs = []
  
  for (let i = 0; i < g.n; i += 1) {
    const x = stepX(i)
    const tx = x - g.textW / 2
    const chevronY = (g.topLineY + g.botLineY) / 2
    
    // Year/date in chevron (between the lines)
    years.push(box(x - g.chevronW / 2 + 6, chevronY - g.chevronH / 2 + 6, g.chevronW - 14, g.chevronH - 12))
    
    // Title below bottom line (colored, bold)
    titles.push(box(tx, g.botLineY + 16, g.textW, g.titleH))
    
    // Description below title (gray text)
    descs.push(box(tx, g.botLineY + 16 + g.titleH + 4, g.textW, g.descH))
  }
  
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    years,
    titles,
    descs,
  }
}

function specToTimelineProcessHorizontalContent(spec) {
  if (spec.kind === 'lines') return { svg: linesSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'circle') return { svg: circleSvg(spec), colorMode: 'recolorable', fill: spec.fill }
  if (spec.kind === 'connector') return { svg: connectorSvg(spec), colorMode: 'fixed', fill: spec.color }
  return { svg: chevronSvg(spec), colorMode: 'recolorable', fill: spec.fill }
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
  const existing = plainTextFromContent(el?.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (TPH_DEFAULTS[sid] || existing)
  return {
    ...(el?.content || {}),
    ...style,
    text,
    runs: null,
    listType: null,
    letterSpacing: style.letterSpacing ?? '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  }
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutTimelineProcessHorizontalElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TPH_GEOM.viewW
  const sy = canvasH / TPH_GEOM.viewH
  const overlay = timelineProcessHorizontalOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TPH_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineProcessHorizontalTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tph'),
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
      align: 'center', verticalAlign: 'center', fontSize: 32, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
  ]
  
  for (let i = 0; i < TPH_GEOM.n; i += 1) {
    const n = i + 1
    const color = TPH_PALETTE[i]
    
    next.push(placeText(`step_${n}_year`, overlay.years[i], {
      align: 'center', verticalAlign: 'center', fontSize: 20, fontWeight: 700, color: '#FFFFFF', clipToSlot: true, lineHeight: 1,
    }, 'caption'))
    
    next.push(placeText(`step_${n}_title`, overlay.titles[i], {
      align: 'center', verticalAlign: 'top', fontSize: 16, fontWeight: 700, color: color, clipToSlot: true, lineHeight: 1.2,
    }, 'heading'))
    
    next.push(placeText(`step_${n}_desc`, overlay.descs[i], {
      align: 'center', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3,
    }, 'body'))
  }

  const chrome = timelineProcessHorizontalChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineProcessHorizontalContent(spec)
    return {
      id: prev?.id || newId('shp-tph'),
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
  
  return [...chrome, ...next]
}

function layoutTimelineProcessHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineProcessHorizontalElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineProcessHorizontalElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineProcessHorizontalLayout,
  layoutTimelineProcessHorizontal,
}
