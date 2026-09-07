/**
 * Timeline roadmap — winding road with 5 map-pin milestones.
 * Layout id: timeline_roadmap_v1 only (not horizontal / lanes).
 */

const TLR_GEOM = {
  viewW: 1000,
  viewH: 560,
  kickerX: 28,
  kickerY: 10,
  kickerW: 280,
  kickerH: 16,
  headingX: 28,
  headingY: 28,
  headingW: 560,
  headingH: 34,
  n: 5,
  pinW: 52,
  pinH: 68,
  textW: 210,
}

const TLR_PALETTE = ['#1B3A5C', '#E0B025', '#E07A1A', '#2A9B8F', '#D23A3A']

const ROAD_D = 'M 72 508 C 210 498 318 448 368 392 C 422 328 318 288 278 238 C 236 186 430 168 568 176 C 730 186 808 128 918 96'

const PINS = [
  { x: 168, y: 500, side: 'right' },
  { x: 408, y: 372, side: 'right' },
  { x: 270, y: 236, side: 'left' },
  { x: 648, y: 178, side: 'right' },
  { x: 900, y: 100, side: 'left' },
]

const LOREM = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.'

const PHASES = [
  { title: 'Kickoff' },
  { title: 'Scope' },
  { title: 'Build' },
  { title: 'Launch' },
  { title: 'Scale' },
]

const TLR_DEFAULTS = {
  SUBHEADING: 'TIMELINE',
  HEADING: 'Timeline roadmap with milestones',
  ...PHASES.reduce((acc, phase, i) => {
    const n = i + 1
    acc[`milestone_${n}_label`] = phase.title
    acc[`milestone_${n}_detail`] = LOREM
    return acc
  }, {}),
}

function isTimelineRoadmapLayout(layoutId) {
  const id = String(layoutId || '')
  if (/horizontal|lanes/i.test(id)) return false
  return /timeline_roadmap_v1$/i.test(id)
}

function isTimelineRoadmapTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'SUBHEADING'
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_detail$/i.test(sid)
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#374151'
}

function pinIcon(n) {
  const s = 'stroke="currentColor" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"'
  const icons = [
    `<g transform="translate(16,12) scale(0.85)" ${s}>
      <rect x="5" y="8" width="14" height="11" rx="1.4"/>
      <path d="M5 11h14"/>
      <path d="M9 8V6.5a3 3 0 0 1 6 0V8"/>
    </g>`,
    `<g transform="translate(16,12) scale(0.85)" ${s}>
      <path d="M7 6h9l3 3v10H7z"/>
      <path d="M16 6v3h3"/>
      <path d="M5 9h9l2.5 2.5V20H5z"/>
    </g>`,
    `<g transform="translate(16,12) scale(0.9)" ${s}>
      <circle cx="9" cy="10" r="3.2"/>
      <path d="M12 10h8"/>
      <path d="M17 10v3"/>
      <path d="M20 10v2"/>
    </g>`,
    `<g transform="translate(15.5,11.5) scale(0.88)" ${s}>
      <circle cx="12" cy="12" r="4.2"/>
      <path d="M12 5.2v2.2"/>
      <path d="M12 16.6v2.2"/>
      <path d="M5.2 12h2.2"/>
      <path d="M16.6 12h2.2"/>
      <path d="M7.2 7.2l1.6 1.6"/>
      <path d="M15.2 15.2l1.6 1.6"/>
      <path d="M16.8 7.2l-1.6 1.6"/>
      <path d="M8.8 15.2l-1.6 1.6"/>
    </g>`,
    `<g transform="translate(16,12) scale(0.88)" ${s}>
      <path d="M6 18V10"/>
      <path d="M11 18V7"/>
      <path d="M16 18v-5"/>
      <path d="M6 10h3"/>
      <path d="M11 7h3"/>
      <path d="M16 13h3"/>
    </g>`,
  ]
  return icons[(n - 1) % icons.length]
}

function roadSvg() {
  const g = TLR_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="${ROAD_D}" fill="none" stroke="#3F4A56" stroke-width="42" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="${ROAD_D}" fill="none" stroke="#5B6570" stroke-width="34" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="${ROAD_D}" fill="none" stroke="#F8FAFC" stroke-width="3.2" stroke-linecap="round" stroke-dasharray="11 13"/>
  </svg>`
}

function pinSvg(spec) {
  const g = TLR_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.pinW} ${g.pinH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <path d="M26 66 C26 66 6 40 6 24 a20 20 0 1 1 40 0 C46 40 26 66 26 66z" fill="currentColor"/>
    <circle cx="26" cy="23" r="12.5" fill="#ffffff"/>
    ${pinIcon(spec.n || 1)}
  </svg>`
}

function timelineRoadmapChromeSpecs() {
  const g = TLR_GEOM
  const specs = [{
    slotId: 'TLR_ROAD',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#5B6570',
    layer: 3,
    kind: 'road',
  }]
  for (let i = 0; i < g.n; i += 1) {
    const pin = PINS[i]
    specs.push({
      slotId: `TLR_${i + 1}`,
      n: i + 1,
      x: pin.x - g.pinW / 2,
      y: pin.y - g.pinH + 6,
      w: g.pinW,
      h: g.pinH,
      color: TLR_PALETTE[i],
      layer: 6,
      kind: 'pin',
    })
  }
  return specs
}

function timelineRoadmapOverlay(gx, gy, gw, gh) {
  const g = TLR_GEOM
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
  const aligns = []
  for (let i = 0; i < g.n; i += 1) {
    const pin = PINS[i]
    const tw = g.textW
    const left = pin.side === 'left'
    const tx = left ? pin.x - 18 - tw : pin.x + 22
    const ty = pin.y - (left ? 58 : 52)
    labels.push(box(tx, ty, tw, 18))
    details.push(box(tx, ty + 20, tw, 42))
    aligns.push(left ? 'right' : 'left')
  }
  return {
    kicker: box(g.kickerX, g.kickerY, g.kickerW, g.kickerH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    details,
    aligns,
  }
}

function specToTimelineRoadmapContent(spec) {
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
    : (TLR_DEFAULTS[sid] || existing)
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

function layoutTimelineRoadmapElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLR_GEOM.viewW
  const sy = canvasH / TLR_GEOM.viewH
  const overlay = timelineRoadmapOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLR_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineRoadmapTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlr'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    placeText('SUBHEADING', overlay.kicker, {
      align: 'left', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: '#E07A1A', clipToSlot: true, lineHeight: 1, letterSpacing: '0.16em',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.05,
    }, 'heading'),
  ]
  for (let i = 0; i < TLR_GEOM.n; i += 1) {
    const n = i + 1
    const accent = TLR_PALETTE[i]
    const align = overlay.aligns[i]
    next.push(placeText(`milestone_${n}_label`, overlay.labels[i], {
      align, verticalAlign: 'center', fontSize: 13, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1.1,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align, verticalAlign: 'top', fontSize: 10, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineRoadmapChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineRoadmapContent(spec)
    return {
      id: prev?.id || newId('shp-tlr'),
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


function layoutTimelineRoadmap(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineRoadmapElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineRoadmapElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineRoadmapLayout,
  layoutTimelineRoadmap,
}
