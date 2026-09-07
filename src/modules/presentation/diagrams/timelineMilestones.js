/**
 * Timeline milestones — 6 ribbon cards above year nodes, option labels below.
 * Layout id: timeline_milestones_v1 only (not cards / image).
 */

const TLM_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 10,
  headingW: 944,
  headingH: 32,
  padX: 18,
  gap: 12,
  n: 6,
  cardY: 86,
  cardH: 168,
  ribbonH: 30,
  foldH: 10,
  axisY: 330,
  nodeR: 26,
  belowY: 372,
}

const TLM_PALETTE = ['#1A6B6B', '#2A9B8F', '#7A8F3A', '#E08A2A', '#D4453A', '#8B2E2E']

const BLURB = 'Insert your desired text here.'
const LOWER = 'This is a sample text. Insert your desired text here.'

const PHASES = [
  { ribbon: 'Launch', year: '2018', option: 'Option 01' },
  { ribbon: 'Capital', year: '2019', option: 'Option 02' },
  { ribbon: 'Insights', year: '2020', option: 'Option 03' },
  { ribbon: 'Growth', year: '2021', option: 'Option 04' },
  { ribbon: 'Campus', year: '2022', option: 'Option 05' },
  { ribbon: 'Global', year: '2023', option: 'Option 06' },
]

const TLM_DEFAULTS = {
  HEADING: 'Key milestones',
  ...PHASES.reduce((acc, phase, i) => {
    const n = i + 1
    acc[`milestone_${n}_card`] = BLURB
    acc[`milestone_${n}_label`] = phase.ribbon
    acc[`milestone_${n}_num`] = phase.year
    acc[`milestone_${n}_title`] = phase.option
    acc[`milestone_${n}_detail`] = LOWER
    return acc
  }, {}),
}

function isTimelineMilestonesLayout(layoutId) {
  const id = String(layoutId || '')
  if (/cards|image/i.test(id)) return false
  return /timeline_milestones_v1$/i.test(id)
}

function isTimelineMilestonesTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^milestone_\d+_card$/i.test(sid)
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_num$/i.test(sid)
    || /^milestone_\d+_title$/i.test(sid)
    || /^milestone_\d+_detail$/i.test(sid)
}

function cardW() {
  const g = TLM_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return TLM_GEOM.padX + i * (cardW() + TLM_GEOM.gap)
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827'
}

function columnIcon(n, cx, cy) {
  const wrap = (inner) => `<g transform="translate(${cx},${cy}) scale(1.55) translate(-16,-16)" fill="currentColor">${inner}</g>`
  const icons = [
    `<path d="M10 24 L10 10 L16 6 L16 14 L22 10 L22 24 Z"/>`,
    `<g>
      <circle cx="12" cy="14" r="5.5"/>
      <rect x="16" y="11" width="8" height="6" rx="1"/>
      <path d="M18 11 V9 h4 v2"/>
    </g>`,
    `<g fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round">
      <polyline points="5,22 12,14 16,17 26,7"/>
    </g>`,
    `<g>
      <rect x="6" y="16" width="4" height="10"/>
      <rect x="13" y="11" width="4" height="15"/>
      <rect x="20" y="7" width="4" height="19"/>
    </g>`,
    `<g>
      <rect x="7" y="14" width="18" height="12"/>
      <rect x="12" y="8" width="8" height="6"/>
      <rect x="10" y="17" width="3" height="5" fill="#fff"/>
      <rect x="19" y="17" width="3" height="5" fill="#fff"/>
    </g>`,
    `<g fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="16" cy="16" r="10"/>
      <ellipse cx="16" cy="16" rx="4.5" ry="10"/>
      <path d="M6 16 H26 M8 10 H24 M8 22 H24"/>
    </g>`,
  ]
  return wrap(icons[(n - 1) % icons.length])
}

function cardSvg(spec) {
  const g = TLM_GEOM
  const w = cardW()
  const h = g.cardH + g.foldH
  const ribbonY = g.cardH - g.ribbonH
  const fid = `tlmsh${spec.n || 1}`
  const n = spec.n || 1
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-18%" y="-10%" width="136%" height="140%">
        <feDropShadow dx="0" dy="3" stdDeviation="3.2" flood-color="#111827" flood-opacity="0.12"/>
      </filter>
    </defs>
    <rect x="3" y="3" width="${w - 6}" height="${g.cardH - 3}" rx="7" fill="#ffffff" filter="url(#${fid})"/>
    ${columnIcon(n, w / 2, 36)}
    <rect x="3" y="${ribbonY}" width="${w - 6}" height="${g.ribbonH}" fill="currentColor"/>
    <polygon points="3,${g.cardH} 15,${g.cardH} 3,${g.cardH + g.foldH}" fill="currentColor"/>
  </svg>`
}

function axisSvg() {
  const g = TLM_GEOM
  const w = g.nodeR * 2 + 8
  const h = Math.max(8, g.axisY + g.nodeR + 4 - (g.cardY + g.cardH + g.foldH))
  const startY = g.cardY + g.cardH + g.foldH
  const cx = w / 2
  const cy = g.axisY - startY
  const r = g.nodeR
  const stroke = 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="${cx - stroke / 2}" y="0" width="${stroke}" height="${Math.max(0, cy - r)}" fill="currentColor"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>
  </svg>`
}

function spineSvg() {
  const g = TLM_GEOM
  const lastCx = cardX(g.n - 1) + cardW() / 2
  const endX = Math.min(g.viewW - 16, lastCx + 52)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="${g.padX}" y1="${g.axisY}" x2="${endX}" y2="${g.axisY}" stroke="#C5CBD3" stroke-width="1.8"/>
    <circle cx="${endX}" cy="${g.axisY}" r="4.5" fill="#1A6B6B"/>
  </svg>`
}

function timelineMilestonesChromeSpecs() {
  const g = TLM_GEOM
  const w = cardW()
  const specs = [{
    slotId: 'TLM_SPINE',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#C5CBD3',
    layer: 3,
    kind: 'spine',
  }]
  const nodeS = g.nodeR * 2 + 8
  const axisTop = g.cardY + g.cardH + g.foldH
  const axisH = g.axisY + g.nodeR + 4 - axisTop
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const color = TLM_PALETTE[i]
    const n = i + 1
    specs.push({
      slotId: `TLM_${n}`,
      n,
      x,
      y: g.cardY,
      w,
      h: g.cardH + g.foldH,
      color,
      layer: 5,
      kind: 'card',
    })
    specs.push({
      slotId: `TLM_${n}N`,
      n,
      x: x + w / 2 - nodeS / 2,
      y: axisTop,
      w: nodeS,
      h: axisH,
      color,
      layer: 7,
      kind: 'node',
    })
  }
  return specs
}

function timelineMilestonesOverlay(gx, gy, gw, gh) {
  const g = TLM_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })
  const w = cardW()
  const cards = []
  const labels = []
  const nums = []
  const titles = []
  const details = []
  const ribbonY = g.cardY + g.cardH - g.ribbonH
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    cards.push(box(x + 10, g.cardY + 58, w - 20, g.cardH - g.ribbonH - 66))
    labels.push(box(x + 8, ribbonY + 4, w - 16, g.ribbonH - 8))
    nums.push(box(x + w / 2 - 28, g.axisY - 12, 56, 24))
    titles.push(box(x + 4, g.belowY, w - 8, 22))
    details.push(box(x + 6, g.belowY + 24, w - 12, 72))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    cards,
    labels,
    nums,
    titles,
    details,
  }
}

function specToTimelineMilestonesContent(spec) {
  if (spec.kind === 'spine') return { svg: spineSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'node') return { svg: axisSvg(), colorMode: 'recolorable', fill: spec.color }
  return { svg: cardSvg(spec), colorMode: 'recolorable', fill: spec.color }
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
    : (TLM_DEFAULTS[sid] || existing)
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

function layoutTimelineMilestonesElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLM_GEOM.viewW
  const sy = canvasH / TLM_GEOM.viewH
  const overlay = timelineMilestonesOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLM_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineMilestonesTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlm'),
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
      align: 'left', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.05,
    }, 'heading'),
  ]
  for (let i = 0; i < 6; i += 1) {
    const n = i + 1
    const accent = TLM_PALETTE[i]
    next.push(placeText(`milestone_${n}_card`, overlay.cards[i], {
      align: 'center', verticalAlign: 'top', fontSize: 10, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap',
    }, 'body'))
    next.push(placeText(`milestone_${n}_label`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_num`, overlay.nums[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`milestone_${n}_title`, overlay.titles[i], {
      align: 'center', verticalAlign: 'center', fontSize: 12, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1,
    }, 'subheading'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: 'center', verticalAlign: 'top', fontSize: 10, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineMilestonesChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineMilestonesContent(spec)
    return {
      id: prev?.id || newId('shp-tlm'),
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


function layoutTimelineMilestones(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineMilestonesElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineMilestonesElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineMilestonesLayout,
  layoutTimelineMilestones,
}
