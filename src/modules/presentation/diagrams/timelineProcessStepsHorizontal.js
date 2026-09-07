/**
 * Timeline process steps horizontal — connector line with 6 alternating circles,
 * title boxes, and text above/below.
 * Layout id: timeline_process_steps_v1 only.
 */

const TLPS_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 40,
  headingY: 16,
  headingW: 920,
  headingH: 40,
  n: 6,
  padX: 60,
  lineY: 280,
  circleR: 32,
  boxW: 140,
  boxH: 36,
  textW: 150,
  descH: 60,
  detailH: 70,
}

const TLPS_PALETTE = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#6B7280']

const LOREM = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'

const TLPS_DEFAULTS = {
  HEADING: 'PROCESS TIMELINE',
  ...Array.from({ length: 6 }, (_, i) => {
    const n = i + 1
    return {
      [`step_${n}_label`]: String(n).padStart(2, '0'),
      [`step_${n}_title`]: 'Title',
      [`step_${n}_desc`]: LOREM,
      [`step_${n}_detail`]: LOREM,
    }
  }).reduce((acc, obj) => ({ ...acc, ...obj }), {}),
}

function isTimelineProcessStepsHorizontalLayout(layoutId) {
  return /timeline_process_steps_v1$/i.test(String(layoutId || ''))
}

function isTimelineProcessStepsHorizontalTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^step_\d+_(label|title|desc|detail)$/i.test(sid)
}

function stepX(i) {
  const g = TLPS_GEOM
  return g.padX + i * ((g.viewW - g.padX * 2) / (g.n - 1))
}

function isTop(i) {
  return i % 2 === 0
}

function linePathD() {
  const g = TLPS_GEOM
  const parts = []
  
  // Start at the beginning
  parts.push(`M ${g.padX - 30} ${g.lineY}`)
  
  // Draw connecting line with vertical segments to circles
  for (let i = 0; i < g.n; i += 1) {
    const x = stepX(i)
    const top = isTop(i)
    const yCircle = g.lineY
    const yBox = top ? g.lineY + g.circleR + 12 + g.boxH / 2 : g.lineY - g.circleR - 12 - g.boxH / 2
    
    if (i === 0) {
      // First segment: horizontal to first circle, then vertical to box
      parts.push(`L ${x} ${yCircle}`)
      parts.push(`L ${x} ${yBox}`)
    } else {
      const prevX = stepX(i - 1)
      const prevTop = isTop(i - 1)
      const prevYBox = prevTop ? g.lineY + g.circleR + 12 + g.boxH / 2 : g.lineY - g.circleR - 12 - g.boxH / 2
      
      // Horizontal from previous box to midpoint
      const midX = (prevX + x) / 2
      parts.push(`L ${midX} ${prevYBox}`)
      // Vertical to baseline
      parts.push(`L ${midX} ${yCircle}`)
      // Vertical to current box height
      parts.push(`L ${midX} ${yBox}`)
      // Horizontal to current position
      parts.push(`L ${x} ${yBox}`)
    }
  }
  
  // Final horizontal segment to the end
  const lastX = stepX(g.n - 1)
  const lastTop = isTop(g.n - 1)
  const lastYBox = lastTop ? g.lineY + g.circleR + 12 + g.boxH / 2 : g.lineY - g.circleR - 12 - g.boxH / 2
  parts.push(`L ${g.viewW - g.padX + 30} ${lastYBox}`)
  
  return parts.join(' ')
}

function circleSvg(spec) {
  const g = TLPS_GEOM
  const r = g.circleR
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${r * 2} ${r * 2}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${r}" cy="${r}" r="${r - 3}" fill="currentColor" stroke="#FFFFFF" stroke-width="4"/>
  </svg>`
}

function titleBoxSvg(spec) {
  const g = TLPS_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.boxW} ${g.boxH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect width="${g.boxW}" height="${g.boxH}" rx="4" fill="currentColor"/>
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

function lineSvg() {
  const g = TLPS_GEOM
  const d = linePathD()
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="${d}" fill="none" stroke="#9CA3AF" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`
}

function timelineProcessStepsHorizontalChromeSpecs() {
  const g = TLPS_GEOM
  const specs = [{
    slotId: 'TLPS_LINE',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#D1D5DB',
    layer: 3,
    kind: 'line',
  }]
  
  for (let i = 0; i < g.n; i += 1) {
    const x = stepX(i)
    const top = isTop(i)
    const color = TLPS_PALETTE[i]
    const n = i + 1

    // Circle
    specs.push({
      slotId: `TLPS_CIRCLE_${n}`,
      n,
      x: x - g.circleR,
      y: g.lineY - g.circleR,
      w: g.circleR * 2,
      h: g.circleR * 2,
      color,
      layer: 6,
      kind: 'circle',
      fill: color,
    })

    // Title box
    specs.push({
      slotId: `TLPS_BOX_${n}`,
      n,
      x: x - g.boxW / 2,
      y: top ? g.lineY + g.circleR + 12 : g.lineY - g.circleR - 12 - g.boxH,
      w: g.boxW,
      h: g.boxH,
      color,
      layer: 5,
      kind: 'box',
      fill: color,
    })
  }
  
  return specs
}

function timelineProcessStepsHorizontalOverlay(gx, gy, gw, gh) {
  const g = TLPS_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const labels = []
  const titles = []
  const descs = []
  const details = []
  
  for (let i = 0; i < g.n; i += 1) {
    const x = stepX(i)
    const top = isTop(i)
    const tx = x - g.textW / 2
    
    // Number label inside circle
    labels.push(box(x - g.circleR * 0.7, g.lineY - g.circleR * 0.5, g.circleR * 1.4, g.circleR))
    
    if (top) {
      // Top: desc above circle, title box below, detail below box
      descs.push(box(tx, g.lineY - g.circleR - 16 - g.descH, g.textW, g.descH))
      titles.push(box(x - g.boxW / 2, g.lineY + g.circleR + 12, g.boxW, g.boxH))
      details.push(box(tx, g.lineY + g.circleR + 12 + g.boxH + 8, g.textW, g.detailH))
    } else {
      // Bottom: desc below circle, title box above, detail above box
      descs.push(box(tx, g.lineY + g.circleR + 16, g.textW, g.descH))
      titles.push(box(x - g.boxW / 2, g.lineY - g.circleR - 12 - g.boxH, g.boxW, g.boxH))
      details.push(box(tx, g.lineY - g.circleR - 12 - g.boxH - 8 - g.detailH, g.textW, g.detailH))
    }
  }
  
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    titles,
    descs,
    details,
  }
}

function specToTimelineProcessStepsHorizontalContent(spec) {
  if (spec.kind === 'line') return { svg: lineSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'circle') return { svg: circleSvg(spec), colorMode: 'recolorable', fill: spec.fill }
  return { svg: titleBoxSvg(spec), colorMode: 'recolorable', fill: spec.fill }
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
    : (TLPS_DEFAULTS[sid] || existing)
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

function layoutTimelineProcessStepsHorizontalElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLPS_GEOM.viewW
  const sy = canvasH / TLPS_GEOM.viewH
  const overlay = timelineProcessStepsHorizontalOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLPS_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineProcessStepsHorizontalTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlps'),
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
      align: 'left', verticalAlign: 'center', fontSize: 28, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
  ]
  
  for (let i = 0; i < TLPS_GEOM.n; i += 1) {
    const n = i + 1
    const color = TLPS_PALETTE[i]
    
    next.push(placeText(`step_${n}_label`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 28, fontWeight: 800, color: '#FFFFFF', clipToSlot: true, lineHeight: 1,
    }, 'caption'))
    
    next.push(placeText(`step_${n}_title`, overlay.titles[i], {
      align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 700, color: '#FFFFFF', clipToSlot: false, lineHeight: 1.1,
    }, 'heading'))
    
    next.push(placeText(`step_${n}_desc`, overlay.descs[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'))
    
    next.push(placeText(`step_${n}_detail`, overlay.details[i], {
      align: 'center', verticalAlign: 'top', fontSize: 10, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineProcessStepsHorizontalChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineProcessStepsHorizontalContent(spec)
    return {
      id: prev?.id || newId('shp-tlps'),
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

function layoutTimelineProcessStepsHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineProcessStepsHorizontalElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineProcessStepsHorizontalElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineProcessStepsHorizontalLayout,
  layoutTimelineProcessStepsHorizontal,
}
