/**
 * Timeline vertical cards — 5 identical cards alternating L-R on a dotted axis.
 * Layout id: timeline_vertical_cards_v1 only.
 */

const TLVC_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 6,
  headingW: 640,
  headingH: 32,
  n: 5,
  startY: 84,
  cardW: 392,
  cardH: 86,
  gapY: 8,
  cx: 500,
  axisGap: 24,
  accentW: 8,
  colW: 100,
  nodeR: 7,
}

const TLVC_PALETTE = ['#2F6FBF', '#E0564A', '#E0A01A', '#3D9A5F', '#6B4C9A']

const BODY = 'Plan, coordinate, and deliver this stage with clear owners and checkpoints.'

const PHASES = [
  { date: 'JAN 2023', title: 'STAGE 1: MASTER PLAN' },
  { date: 'MAR 2023', title: 'STAGE 2: PERMITS' },
  { date: 'JUN 2023', title: 'STAGE 3: DESIGN' },
  { date: 'SEP 2023', title: 'STAGE 4: SCHEDULE' },
  { date: 'DEC 2023', title: 'STAGE 5: BUILD' },
]

const TLVC_DEFAULTS = {
  HEADING: '5 Stage Planning Process',
  ...PHASES.reduce((acc, phase, i) => {
    const n = i + 1
    acc[`milestone_${n}_num`] = phase.date
    acc[`milestone_${n}_label`] = phase.title
    acc[`milestone_${n}_detail`] = BODY
    return acc
  }, {}),
}

function isTimelineVerticalCardsLayout(layoutId) {
  return /timeline_vertical_cards_v1$/i.test(String(layoutId || ''))
}

function isTimelineVerticalCardsTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^milestone_\d+_num$/i.test(sid)
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#1A1A1A'
}

function isLeft(i) {
  return i % 2 === 0
}

function rowY(i) {
  const g = TLVC_GEOM
  return g.startY + i * (g.cardH + g.gapY)
}

function cardX(i) {
  const g = TLVC_GEOM
  if (isLeft(i)) return g.cx - g.axisGap - g.cardW
  return g.cx + g.axisGap
}

function stageIcon(n, x, y) {
  const wrap = (inner) => `<g transform="translate(${x},${y}) scale(1.58)">${inner}</g>`
  const stroke = 'stroke="#2D3340" fill="none" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"'
  const fill = 'fill="#2D3340"'
  const icons = [
    `<g ${stroke}>
      <path d="M3 6l9-3 9 3v15l-9-3-9 3z"/>
      <path d="M12 3v15"/>
      <circle cx="12" cy="11" r="2.2" fill="#2D3340" stroke="none"/>
    </g>`,
    `<g ${stroke}>
      <rect x="5" y="3" width="14" height="18" rx="1.4"/>
      <path d="M8 9l2.2 2.2L14.8 7"/>
      <path d="M8 14h8"/>
      <path d="M8 17.5h5"/>
    </g>`,
    `<g ${stroke}>
      <path d="M4 20l9-9"/>
      <path d="M14.2 9.2l3.6-3.6 2.6 2.6-3.6 3.6z" ${fill} stroke="#2D3340" stroke-width="1.2"/>
      <path d="M4 16h5"/>
      <path d="M4 20h8"/>
    </g>`,
    `<g ${stroke}>
      <rect x="4" y="6" width="16" height="15" rx="1.4"/>
      <path d="M4 10.5h16"/>
      <path d="M8 4v4"/>
      <path d="M16 4v4"/>
      <rect x="7.5" y="13" width="3" height="3" rx="0.4" ${fill} stroke="none"/>
      <rect x="13.5" y="13" width="3" height="3" rx="0.4" ${fill} stroke="none"/>
    </g>`,
    `<g ${stroke}>
      <circle cx="8.5" cy="8" r="2.3"/>
      <circle cx="15.5" cy="8" r="2.3"/>
      <path d="M4.8 18c.4-3 2-4.6 3.7-4.6s3.2 1.4 3.6 3.4"/>
      <path d="M12 16.6c.5-2.2 1.8-3.4 3.5-3.4 2 0 3.6 1.8 3.8 4.8"/>
    </g>`,
  ]
  return wrap(icons[(n - 1) % icons.length])
}

function spineSvg() {
  const g = TLVC_GEOM
  const y1 = rowY(0) + g.cardH / 2
  const y2 = rowY(g.n - 1) + g.cardH / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="${g.cx}" y1="${y1}" x2="${g.cx}" y2="${y2}" stroke="#1F2937" stroke-width="1.6" stroke-dasharray="2.4 4.2" stroke-linecap="round"/>
  </svg>`
}

function rowSvg(spec) {
  const g = TLVC_GEOM
  const i = (spec.n || 1) - 1
  const left = isLeft(i)
  const w = g.cardW + g.axisGap
  const h = g.cardH
  const cardX0 = left ? 0 : g.axisGap
  const accentX = left ? cardX0 + g.cardW - g.accentW : cardX0
  const divX = left ? cardX0 + g.colW : cardX0 + g.cardW - g.colW
  const stemX1 = left ? cardX0 + g.cardW : 0
  const stemX2 = left ? w : g.axisGap
  const nodeX = left ? w : 0
  const mid = h / 2
  const iconSize = 38
  const iconX = left
    ? cardX0 + (g.colW - iconSize) / 2
    : cardX0 + g.cardW - g.colW + (g.colW - iconSize) / 2
  const iconY = h - iconSize - 8
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="${cardX0}" y="0" width="${g.cardW}" height="${h}" fill="#ffffff" stroke="#E5E7EB" stroke-width="1"/>
    <rect x="${accentX}" y="0" width="${g.accentW}" height="${h}" fill="currentColor"/>
    <rect x="${divX}" y="10" width="1" height="${h - 20}" fill="#D1D5DB"/>
    <line x1="${stemX1}" y1="${mid}" x2="${stemX2}" y2="${mid}" stroke="currentColor" stroke-width="2.2"/>
    <circle cx="${nodeX}" cy="${mid}" r="${g.nodeR}" fill="currentColor"/>
    ${stageIcon(spec.n || 1, iconX, iconY)}
  </svg>`
}

function timelineVerticalCardsChromeSpecs() {
  const g = TLVC_GEOM
  const specs = [{
    slotId: 'TLVC_SPINE',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#1F2937',
    layer: 3,
    kind: 'spine',
  }]
  for (let i = 0; i < g.n; i += 1) {
    const left = isLeft(i)
    const span = g.cardW + g.axisGap
    specs.push({
      slotId: `TLVC_${i + 1}`,
      n: i + 1,
      x: left ? cardX(i) : g.cx,
      y: rowY(i),
      w: span,
      h: g.cardH,
      color: TLVC_PALETTE[i],
      layer: 5,
      kind: 'row',
    })
  }
  return specs
}

function timelineVerticalCardsOverlay(gx, gy, gw, gh) {
  const g = TLVC_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  const dates = []
  const titles = []
  const details = []
  const pad = 12
  const innerW = g.cardW - g.colW - g.accentW - pad * 2
  for (let i = 0; i < g.n; i += 1) {
    const y = rowY(i)
    const x = cardX(i)
    const left = isLeft(i)
    if (left) {
      dates.push(box(x + 8, y + 10, g.colW - 16, 16))
      titles.push(box(x + g.colW + 10, y + 8, innerW, 16))
      details.push(box(x + g.colW + 10, y + 26, innerW, hBody()))
    } else {
      dates.push(box(x + g.cardW - g.colW + 8, y + 10, g.colW - 16, 16))
      titles.push(box(x + g.accentW + 10, y + 8, innerW, 16))
      details.push(box(x + g.accentW + 10, y + 26, innerW, hBody()))
    }
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    dates,
    titles,
    details,
  }
}

function hBody() {
  return TLVC_GEOM.cardH - 34
}

function specToTimelineVerticalCardsContent(spec) {
  if (spec.kind === 'spine') return { svg: spineSvg(), colorMode: 'fixed', fill: spec.color }
  return { svg: rowSvg(spec), colorMode: 'recolorable', fill: spec.color }
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
  const stale = /^(0[1-5]|discover|design|build|launch|scale|phase\s*\d|five staged vertical timeline|research and scope|prototype and test)$/i.test(existing.trim())
    || /hospital timeline/i.test(existing)
  const text = existing && existing.toLowerCase() !== 'double-click to edit' && !stale
    ? existing
    : (TLVC_DEFAULTS[sid] || existing)
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

function layoutTimelineVerticalCardsElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLVC_GEOM.viewW
  const sy = canvasH / TLVC_GEOM.viewH
  const overlay = timelineVerticalCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLVC_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineVerticalCardsTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlvc'),
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
  for (let i = 0; i < TLVC_GEOM.n; i += 1) {
    const n = i + 1
    const accent = TLVC_PALETTE[i]
    const left = isLeft(i)
    const dateAlign = left ? 'left' : 'right'
    const copyAlign = left ? 'left' : 'left'
    next.push(placeText(`milestone_${n}_num`, overlay.dates[i], {
      align: dateAlign, verticalAlign: 'center', fontSize: 9, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1, letterSpacing: '0.04em',
    }, 'stat'))
    next.push(placeText(`milestone_${n}_label`, overlay.titles[i], {
      align: copyAlign, verticalAlign: 'center', fontSize: 10, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1.1, letterSpacing: '0.02em',
    }, 'caption'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: copyAlign, verticalAlign: 'top', fontSize: 10, fontWeight: 400, color: '#1F2937', clipToSlot: true, lineHeight: 1.28, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineVerticalCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineVerticalCardsContent(spec)
    return {
      id: prev?.id || newId('shp-tlvc'),
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


function layoutTimelineVerticalCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineVerticalCardsElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineVerticalCardsElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineVerticalCardsLayout,
  layoutTimelineVerticalCards,
}
