/**
 * Timeline milestones cards — year labels, flag nodes, grey brackets, gradient cards.
 * Layout id: timeline_milestones_cards_v1 only.
 */

const TLMC_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 8,
  headingW: 944,
  headingH: 32,
  padX: 32,
  gap: 24,
  n: 5,
  yearY: 78,
  axisY: 138,
  nodeR: 24,
  cardY: 204,
  cardH: 300,
  headerH: 46,
}

const TLMC_PALETTE = ['#2F6FBF', '#3D9A4A', '#D4A017', '#C75B12', '#8B1E3F']

const BODY = 'Insert your desired text here. This is a sample text.'

const TLMC_DEFAULTS = {
  HEADING: 'Key milestones',
  milestone_1_num: '2027',
  milestone_2_num: '2028',
  milestone_3_num: '2029',
  milestone_4_num: '2030',
  milestone_5_num: '2031',
  milestone_1_label: 'Milestone 01',
  milestone_2_label: 'Milestone 02',
  milestone_3_label: 'Milestone 03',
  milestone_4_label: 'Milestone 04',
  milestone_5_label: 'Milestone 05',
  milestone_1_detail: BODY,
  milestone_2_detail: BODY,
  milestone_3_detail: BODY,
  milestone_4_detail: BODY,
  milestone_5_detail: BODY,
}

function isTimelineMilestonesCardsLayout(layoutId) {
  return /timeline_milestones_cards_v1$/i.test(String(layoutId || ''))
}

function isTimelineMilestonesCardsTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^milestone_\d+_num$/i.test(sid)
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_detail$/i.test(sid)
}

function cardW() {
  const g = TLMC_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return TLMC_GEOM.padX + i * (cardW() + TLMC_GEOM.gap)
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

function flagIcon(cx, cy) {
  return `<g transform="translate(${cx - 9},${cy - 10})" fill="#ffffff">
    <rect x="3" y="1" width="2.2" height="18" rx="0.6"/>
    <path d="M5.2 2.2 L16.5 6.2 L5.2 10.4 Z"/>
  </g>`
}

function nodeSvg() {
  const g = TLMC_GEOM
  const s = g.nodeR * 2 + 8
  const c = s / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${s} ${s}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${c}" cy="${c}" r="${g.nodeR}" fill="currentColor"/>
    ${flagIcon(c, c)}
  </svg>`
}

function bracketSvg() {
  const g = TLMC_GEOM
  const w = cardW()
  const h = g.cardY - (g.axisY + g.nodeR)
  const cx = w / 2
  const barY = Math.max(10, h - 10)
  const inset = 4
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="${cx - 0.9}" y="0" width="1.8" height="${barY}" fill="#B8BFC8"/>
    <rect x="${inset}" y="${barY - 0.9}" width="${w - inset * 2}" height="1.8" fill="#B8BFC8"/>
    <rect x="${inset}" y="${barY}" width="1.8" height="${h - barY}" fill="#B8BFC8"/>
    <rect x="${w - inset - 1.8}" y="${barY}" width="1.8" height="${h - barY}" fill="#B8BFC8"/>
  </svg>`
}

function cardSvg(spec) {
  const g = TLMC_GEOM
  const w = cardW()
  const h = g.cardH
  const gid = `tlmcg${spec.n || 1}`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="currentColor" stop-opacity="0.92"/>
        <stop offset="100%" stop-color="currentColor" stop-opacity="0.55"/>
      </linearGradient>
    </defs>
    <rect x="0" y="${g.headerH}" width="${w}" height="${h - g.headerH}" fill="url(#${gid})"/>
    <rect x="0" y="0" width="${w}" height="${g.headerH}" fill="currentColor"/>
  </svg>`
}

function spineSvg() {
  const g = TLMC_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="${g.padX}" y1="${g.axisY}" x2="${g.viewW - g.padX}" y2="${g.axisY}" stroke="#C5CBD3" stroke-width="1.8"/>
  </svg>`
}

function timelineMilestonesCardsChromeSpecs() {
  const g = TLMC_GEOM
  const w = cardW()
  const nodeS = g.nodeR * 2 + 8
  const bracketH = g.cardY - (g.axisY + g.nodeR)
  const specs = [{
    slotId: 'TLMC_SPINE',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#C5CBD3',
    layer: 3,
    kind: 'spine',
  }]
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const color = TLMC_PALETTE[i]
    const n = i + 1
    specs.push({
      slotId: `TLMC_${n}N`,
      n,
      x: x + w / 2 - nodeS / 2,
      y: g.axisY - nodeS / 2,
      w: nodeS,
      h: nodeS,
      color,
      layer: 7,
      kind: 'node',
    })
    specs.push({
      slotId: `TLMC_${n}B`,
      n,
      x,
      y: g.axisY + g.nodeR,
      w,
      h: bracketH,
      color: '#B8BFC8',
      layer: 4,
      kind: 'bracket',
    })
    specs.push({
      slotId: `TLMC_${n}`,
      n,
      x,
      y: g.cardY,
      w,
      h: g.cardH,
      color,
      layer: 5,
      kind: 'card',
    })
  }
  return specs
}

function timelineMilestonesCardsOverlay(gx, gy, gw, gh) {
  const g = TLMC_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })
  const w = cardW()
  const years = []
  const labels = []
  const details = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    years.push(box(x, g.yearY, w, 28))
    labels.push(box(x + 8, g.cardY + 8, w - 16, g.headerH - 16))
    details.push(box(x + 12, g.cardY + g.headerH + 16, w - 24, g.cardH - g.headerH - 28))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    years,
    labels,
    details,
  }
}

function specToTimelineMilestonesCardsContent(spec) {
  if (spec.kind === 'spine') return { svg: spineSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'bracket') return { svg: bracketSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'node') return { svg: nodeSvg(), colorMode: 'recolorable', fill: spec.color }
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
  const stale = /^(2020|key event summary)$/i.test(existing.trim())
  const text = existing && existing.toLowerCase() !== 'double-click to edit' && !stale
    ? existing
    : (TLMC_DEFAULTS[sid] || existing)
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

function layoutTimelineMilestonesCardsElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLMC_GEOM.viewW
  const sy = canvasH / TLMC_GEOM.viewH
  const overlay = timelineMilestonesCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLMC_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineMilestonesCardsTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlmc'),
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
      align: 'left', verticalAlign: 'center', fontSize: 20, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.05,
    }, 'heading'),
  ]
  for (let i = 0; i < 5; i += 1) {
    const n = i + 1
    next.push(placeText(`milestone_${n}_num`, overlay.years[i], {
      align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 800, color: '#111827', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`milestone_${n}_label`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 13, fontWeight: 700, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: 'center', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#ffffff', clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineMilestonesCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineMilestonesCardsContent(spec)
    return {
      id: prev?.id || newId('shp-tlmc'),
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


function layoutTimelineMilestonesCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineMilestonesCardsElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineMilestonesCardsElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineMilestonesCardsLayout,
  layoutTimelineMilestonesCards,
}
