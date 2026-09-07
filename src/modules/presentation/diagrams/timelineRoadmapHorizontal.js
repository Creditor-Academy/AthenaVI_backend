/**
 * Timeline roadmap horizontal — wavy two-lane road with 6 alternating pins.
 * Layout id: timeline_roadmap_horizontal_v1 only.
 */

const TLRH_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 40,
  headingY: 16,
  headingW: 920,
  headingH: 48,
  n: 6,
  padX: 60,
  midY: 310,
  amp: 95,
  roadW: 48,
  pinW: 46,
  pinH: 62,
  textW: 150,
  labelH: 30,
  detailH: 95,
}

const TLRH_PALETTE = ['#9B3044', '#7CB342', '#E07A1A', '#C62828', '#2E7D6F', '#7A2D3A']

const LOREM = 'Maecenas non laoreet odio. Fusce lobortis porttitor purus, vel vestibulum libero pharetra vel.'

const YEARS = ['2022', '2023', '2024', '2025', '2026', '2027']

const TLRH_DEFAULTS = {
  HEADING: 'Roadmap Timeline Template',
  ...YEARS.reduce((acc, year, i) => {
    const n = i + 1
    acc[`milestone_${n}_label`] = year
    acc[`milestone_${n}_detail`] = LOREM
    return acc
  }, {}),
}

function isTimelineRoadmapHorizontalLayout(layoutId) {
  return /timeline_roadmap_horizontal_v1$/i.test(String(layoutId || ''))
}

function isTimelineRoadmapHorizontalTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_detail$/i.test(sid)
}

function pinX(i) {
  const g = TLRH_GEOM
  return g.padX + i * ((g.viewW - g.padX * 2) / (g.n - 1))
}

function roadYAt(i) {
  return TLRH_GEOM.midY - TLRH_GEOM.amp * Math.cos(i * Math.PI)
}

function isPeak(i) {
  return i % 2 === 0
}

function roadPathD() {
  const g = TLRH_GEOM
  const samples = 96
  const span = g.viewW - g.padX * 2
  const parts = []
  for (let s = 0; s <= samples; s += 1) {
    const t = s / samples
    const x = (g.padX + t * span).toFixed(1)
    const y = (g.midY - g.amp * Math.cos(t * (g.n - 1) * Math.PI)).toFixed(1)
    parts.push(`${s === 0 ? 'M' : 'L'} ${x} ${y}`)
  }
  return parts.join(' ')
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

function roadSvg() {
  const g = TLRH_GEOM
  const d = roadPathD()
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="${d}" fill="none" stroke="#3C4043" stroke-width="${g.roadW + 6}" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="${d}" fill="none" stroke="#5F6368" stroke-width="${g.roadW}" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="${d}" fill="none" stroke="#E8EAED" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="12 10"/>
  </svg>`
}

function pinSvg(spec) {
  const g = TLRH_GEOM
  const flipped = spec.flip
  const inner = `<g ${flipped ? `transform="rotate(180 ${g.pinW / 2} ${g.pinH / 2})"` : ''}>
    <path d="M23 59 C23 59 4 34 4 21 a19 19 0 1 1 38 0 C42 34 23 59 23 59z" fill="currentColor" stroke="rgba(0,0,0,0.12)" stroke-width="1"/>
    <circle cx="23" cy="20" r="11" fill="#ffffff" stroke="rgba(0,0,0,0.08)" stroke-width="0.5"/>
  </g>`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.pinW} ${g.pinH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${inner}</svg>`
}

function timelineRoadmapHorizontalChromeSpecs() {
  const g = TLRH_GEOM
  const specs = [{
    slotId: 'TLRH_ROAD',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#5F6368',
    layer: 3,
    kind: 'road',
  }]
  for (let i = 0; i < g.n; i += 1) {
    const x = pinX(i)
    const y = roadYAt(i)
    const peak = isPeak(i)
    const overlap = 8
    specs.push({
      slotId: `TLRH_${i + 1}`,
      n: i + 1,
      x: x - g.pinW / 2,
      y: peak ? y - g.pinH + overlap : y - overlap,
      w: g.pinW,
      h: g.pinH,
      color: TLRH_PALETTE[i],
      layer: 6,
      kind: 'pin',
      flip: !peak,
    })
  }
  return specs
}

function timelineRoadmapHorizontalOverlay(gx, gy, gw, gh) {
  const g = TLRH_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  const labels = []
  const details = []
  for (let i = 0; i < g.n; i += 1) {
    const x = pinX(i)
    const y = roadYAt(i)
    const peak = isPeak(i)
    const tx = x - g.textW / 2
    if (peak) {
      // Label above pin, detail text BELOW road (way more spacing to avoid overlap)
      labels.push(box(tx, y - g.pinH - g.labelH + 4, g.textW, g.labelH))
      details.push(box(tx, y + g.roadW / 2 + 70, g.textW, g.detailH))
    } else {
      // Label below pin, detail text ABOVE road (way more spacing to avoid overlap)
      labels.push(box(tx, y + g.pinH - 6, g.textW, g.labelH))
      details.push(box(tx, y - g.roadW / 2 - 70 - g.detailH, g.textW, g.detailH))
    }
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    details,
  }
}

function specToTimelineRoadmapHorizontalContent(spec) {
  if (spec.kind === 'road') return { svg: roadSvg(), colorMode: 'fixed', fill: spec.color }
  return { svg: pinSvg(spec), colorMode: 'recolorable', fill: spec.color }
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
  const stale = /^(product roadmap|q[1-4]|foundation release|growth features|enterprise push|scale and optimize)$/i.test(existing.trim())
  const text = existing && existing.toLowerCase() !== 'double-click to edit' && !stale
    ? existing
    : (TLRH_DEFAULTS[sid] || existing)
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

function layoutTimelineRoadmapHorizontalElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLRH_GEOM.viewW
  const sy = canvasH / TLRH_GEOM.viewH
  const overlay = timelineRoadmapHorizontalOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLRH_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineRoadmapHorizontalTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlrh'),
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
      align: 'center', verticalAlign: 'center', fontSize: 26, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
  ]
  for (let i = 0; i < TLRH_GEOM.n; i += 1) {
    const n = i + 1
    const accent = TLRH_PALETTE[i]
    next.push(placeText(`milestone_${n}_label`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 18, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1.05,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: 'center', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineRoadmapHorizontalChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineRoadmapHorizontalContent(spec)
    return {
      id: prev?.id || newId('shp-tlrh'),
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

function layoutTimelineRoadmapHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineRoadmapHorizontalElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineRoadmapHorizontalElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineRoadmapHorizontalLayout,
  layoutTimelineRoadmapHorizontal,
}
