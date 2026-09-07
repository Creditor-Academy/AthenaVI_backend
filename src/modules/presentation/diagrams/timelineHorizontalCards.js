/**
 * Timeline horizontal cards — swim-lane cards, numbered axis, period footers.
 * Layout id: timeline_horizontal_cards_v1 only.
 */

const TLHC_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 10,
  headingW: 944,
  headingH: 36,
  padX: 24,
  gap: 16,
  n: 5,
  cardY: 108,
  cardH: 198,
  barH: 9,
  axisY: 392,
  nodeR: 28,
  footY: 476,
  footH: 38,
}

const TLHC_PALETTE = ['#E4453A', '#E0892A', '#3D9A5F', '#3B82C4', '#7B5EA7']

const PHASES = [
  { label: 'Phase 01', title: 'Discovery', num: '01', foot: 'Kickoff', detail: '• Stakeholder interviews\n• Market research\n• Define KPIs' },
  { label: 'Phase 02', title: 'Design', num: '02', foot: 'Prototype', detail: '• Design system\n• Prototyping\n• User testing' },
  { label: 'Phase 03', title: 'Development', num: '03', foot: 'Build', detail: '• Core features\n• API build\n• QA & testing' },
  { label: 'Phase 04', title: 'Launch', num: '04', foot: 'Go live', detail: '• Go-to-market\n• Press release\n• Onboarding' },
  { label: 'Phase 05', title: 'Scale', num: '05', foot: 'Expand', detail: '• New markets\n• V2 planning\n• Growth KPIs' },
]

const TLHC_DEFAULTS = {
  HEADING: 'Horizontal Swim-Lane Timeline',
  ...PHASES.reduce((acc, phase, i) => {
    const n = i + 1
    acc[`milestone_${n}_label`] = phase.label
    acc[`milestone_${n}_title`] = phase.title
    acc[`milestone_${n}_detail`] = phase.detail
    acc[`milestone_${n}_num`] = phase.num
    acc[`milestone_${n}_foot`] = phase.foot
    return acc
  }, {}),
}

function isTimelineHorizontalCardsLayout(layoutId) {
  return /timeline_horizontal_cards_v1$/i.test(String(layoutId || ''))
}

function isTimelineHorizontalCardsTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_title$/i.test(sid)
    || /^milestone_\d+_detail$/i.test(sid)
    || /^milestone_\d+_num$/i.test(sid)
    || /^milestone_\d+_foot$/i.test(sid)
}

function cardW() {
  const g = TLHC_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return TLHC_GEOM.padX + i * (cardW() + TLHC_GEOM.gap)
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

function cardSvg(spec) {
  const g = TLHC_GEOM
  const w = cardW()
  const h = g.cardH
  const fid = `tlhcsh${spec.n || 1}`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-20%" y="-12%" width="140%" height="140%">
        <feDropShadow dx="0" dy="4" stdDeviation="4.5" flood-color="#111827" flood-opacity="0.14"/>
      </filter>
    </defs>
    <rect x="5" y="6" width="${w - 10}" height="${h - 10}" rx="8" fill="#ffffff" stroke="currentColor" stroke-width="1.4" filter="url(#${fid})"/>
    <rect x="5" y="6" width="${w - 10}" height="${g.barH}" fill="currentColor"/>
  </svg>`
}

function axisSvg() {
  const g = TLHC_GEOM
  const w = g.nodeR * 2 + 8
  const h = Math.max(8, g.footY - (g.cardY + g.cardH))
  const cx = w / 2
  const cy = g.axisY - (g.cardY + g.cardH)
  const r = g.nodeR
  const stroke = 2.2
  const x = cx - stroke / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="${x}" y="0" width="${stroke}" height="${Math.max(0, cy - r)}" fill="currentColor"/>
    <rect x="${x}" y="${cy + r}" width="${stroke}" height="${Math.max(0, h - (cy + r))}" fill="currentColor"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>
    <circle cx="${cx}" cy="${cy}" r="${r - 3.5}" fill="none" stroke="#ffffff" stroke-width="2"/>
  </svg>`
}

function footSvg() {
  const w = cardW()
  const h = TLHC_GEOM.footH
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="8" y="3" width="${w - 16}" height="${h - 6}" rx="5" fill="currentColor" opacity="0.12" stroke="currentColor" stroke-width="1.4"/>
  </svg>`
}

function spineSvg() {
  const g = TLHC_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="${g.padX}" y1="${g.axisY}" x2="${g.viewW - g.padX}" y2="${g.axisY}" stroke="#9CA3AF" stroke-width="1.8"/>
  </svg>`
}

function timelineHorizontalCardsChromeSpecs() {
  const g = TLHC_GEOM
  const w = cardW()
  const specs = [{
    slotId: 'TLHC_SPINE',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#9CA3AF',
    layer: 3,
    kind: 'spine',
  }]
  const axisH = g.footY - (g.cardY + g.cardH)
  const nodeS = g.nodeR * 2 + 8
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const color = TLHC_PALETTE[i]
    const n = i + 1
    specs.push({
      slotId: `TLHC_${n}`,
      n,
      x,
      y: g.cardY,
      w,
      h: g.cardH,
      color,
      layer: 5,
      kind: 'card',
    })
    specs.push({
      slotId: `TLHC_${n}N`,
      n,
      x: x + w / 2 - nodeS / 2,
      y: g.cardY + g.cardH,
      w: nodeS,
      h: axisH,
      color,
      layer: 7,
      kind: 'node',
    })
    specs.push({
      slotId: `TLHC_${n}F`,
      n,
      x,
      y: g.footY,
      w,
      h: g.footH,
      color,
      layer: 5,
      kind: 'foot',
    })
  }
  return specs
}

function timelineHorizontalCardsOverlay(gx, gy, gw, gh) {
  const g = TLHC_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })
  const w = cardW()
  const labels = []
  const titles = []
  const details = []
  const nums = []
  const foots = []
  const nodeS = g.nodeR * 2 + 8
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    labels.push(box(x + 14, g.cardY + 18, w - 28, 18))
    titles.push(box(x + 14, g.cardY + 38, w - 28, 28))
    details.push(box(x + 14, g.cardY + 70, w - 28, g.cardH - 86))
    nums.push(box(x + w / 2 - nodeS / 2 + 6, g.axisY - 14, nodeS - 12, 28))
    foots.push(box(x + 12, g.footY + 6, w - 24, g.footH - 12))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    titles,
    details,
    nums,
    foots,
  }
}

function specToTimelineHorizontalCardsContent(spec) {
  if (spec.kind === 'spine') return { svg: spineSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec.kind === 'node') return { svg: axisSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec.kind === 'foot') return { svg: footSvg(), colorMode: 'recolorable', fill: spec.color }
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
  const staleQuarter = /^Q[1-4]\s*20\d{2}$/i.test(existing.trim())
  const text = existing && existing.toLowerCase() !== 'double-click to edit' && !staleQuarter
    ? existing
    : (TLHC_DEFAULTS[sid] || existing)
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

function layoutTimelineHorizontalCardsElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLHC_GEOM.viewW
  const sy = canvasH / TLHC_GEOM.viewH
  const overlay = timelineHorizontalCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLHC_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineHorizontalCardsTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlhc'),
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
      align: 'left', verticalAlign: 'center', fontSize: 24, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.05,
    }, 'heading'),
  ]
  for (let i = 0; i < 5; i += 1) {
    const n = i + 1
    const accent = TLHC_PALETTE[i]
    next.push(placeText(`milestone_${n}_label`, overlay.labels[i], {
      align: 'left', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: accent, clipToSlot: true, lineHeight: 1,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_title`, overlay.titles[i], {
      align: 'left', verticalAlign: 'center', fontSize: 16, fontWeight: 800, color: '#111827', clipToSlot: true, lineHeight: 1.1,
    }, 'subheading'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'body'))
    next.push(placeText(`milestone_${n}_num`, overlay.nums[i], {
      align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`milestone_${n}_foot`, overlay.foots[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: accent, clipToSlot: true, lineHeight: 1,
    }, 'caption'))
  }

  const chrome = timelineHorizontalCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineHorizontalCardsContent(spec)
    return {
      id: prev?.id || newId('shp-tlhc'),
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


function layoutTimelineHorizontalCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineHorizontalCardsElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineHorizontalCardsElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineHorizontalCardsLayout,
  layoutTimelineHorizontalCards,
}
