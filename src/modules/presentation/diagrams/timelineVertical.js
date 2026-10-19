/**
 * Timeline vertical — center pillar with 5 alternating numbered ribbons.
 * Layout id: timeline_vertical_v1 only (not cards).
 */

const TLV_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 8,
  headingW: 720,
  headingH: 30,
  n: 5,
  startY: 52,
  rowH: 96,
  gap: 4,
  cx: 500,
  pillarW: 28,
  capW: 118,
  capH: 56,
  neck: 22,
}

const TLV_PALETTE = ['#5BA84A', '#2EB5E0', '#E0A01A', '#E23B3B', '#2F6FBF']

const BODY = 'Bring your presentation to life. Capture your audience\'s attention.'

const PHASES = [
  { num: '01', title: 'Discover', sub: 'Research and scope' },
  { num: '02', title: 'Design', sub: 'Prototype and test' },
  { num: '03', title: 'Build', sub: 'Engineer the core' },
  { num: '04', title: 'Launch', sub: 'Go to market' },
  { num: '05', title: 'Scale', sub: 'Grow and expand' },
]

const TLV_DEFAULTS = {
  HEADING: 'Five staged vertical timeline',
  ...PHASES.reduce((acc, phase, i) => {
    const n = i + 1
    acc[`milestone_${n}_num`] = phase.num
    acc[`milestone_${n}_label`] = phase.title
    acc[`milestone_${n}_title`] = phase.sub
    acc[`milestone_${n}_detail`] = BODY
    return acc
  }, {}),
}

function isTimelineVerticalLayout(layoutId) {
  const id = String(layoutId || '')
  if (/cards/i.test(id)) return false
  return /timeline_vertical_v1$/i.test(id)
}

function isTimelineVerticalTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^milestone_\d+_num$/i.test(sid)
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_title$/i.test(sid)
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#1F2937'
}

function isRight(i) {
  return i % 2 === 0
}

function rowY(i) {
  const g = TLV_GEOM
  return g.startY + i * (g.rowH + g.gap)
}

function ribbonGeom(i) {
  const g = TLV_GEOM
  const h = g.rowH
  const mid = h / 2
  const capH = g.capH
  const capW = g.capW
  const r = capH / 2
  const join = 5.5
  if (isRight(i)) {
    const joinX = g.cx + g.pillarW / 2
    const headL = joinX + g.neck
    const headR = headL + capW
    return {
      right: true,
      joinX,
      headL,
      headR,
      top: mid - r,
      bot: mid + r,
      r,
      mid,
      numX: (headL + headR) / 2 - 22,
      numW: 44,
      textX: headR + 16,
      textW: g.viewW - (headL + capW) - 16 - 24,
      ruleX: headR + 16,
      ruleW: 92,
    }
  }
  const joinX = g.cx - g.pillarW / 2
  const headR = joinX - g.neck
  const headL = headR - capW
  return {
    right: false,
    joinX,
    headL,
    headR,
    top: mid - r,
    bot: mid + r,
    r,
    mid,
    numX: (headL + headR) / 2 - 22,
    numW: 44,
    textX: 24,
    textW: headL - 16 - 24,
    ruleX: (24 + (headL - 16 - 24)) - 92,
    ruleW: 92,
  }
}

function ribbonPath(rg) {
  const { joinX, headL, headR, top, bot, r, mid, right } = rg
  if (right) {
    return `M ${joinX} ${mid - 5.5}
      C ${joinX + 16} ${mid - 5.5} ${headL} ${top} ${headL + r} ${top}
      H ${headR - r}
      A ${r} ${r} 0 0 1 ${headR - r} ${bot}
      H ${headL + r}
      C ${headL} ${bot} ${joinX + 16} ${mid + 5.5} ${joinX} ${mid + 5.5} Z`
  }
  return `M ${joinX} ${mid - 5.5}
    C ${joinX - 16} ${mid - 5.5} ${headR} ${top} ${headR - r} ${top}
    H ${headL + r}
    A ${r} ${r} 0 0 0 ${headL + r} ${bot}
    H ${headR - r}
    C ${headR} ${bot} ${joinX - 16} ${mid + 5.5} ${joinX} ${mid + 5.5} Z`
}

function pillarSvg() {
  const g = TLV_GEOM
  const x = g.cx - g.pillarW / 2
  const y = g.startY - 6
  const h = rowY(g.n - 1) + g.rowH - y + 8
  const w = g.pillarW
  const rx = w / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="${x + 2}" y="${y + 3}" width="${w}" height="${h}" rx="${rx}" fill="#C5CBD3" opacity="0.35"/>
    <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${rx}" fill="#F7F8FA"/>
    <rect x="${x + 5}" y="${y + 4}" width="7" height="${h - 8}" rx="3.5" fill="#ffffff" opacity="0.85"/>
    <rect x="${x + w - 9}" y="${y + 6}" width="5" height="${h - 12}" rx="2.5" fill="#D3D9E0" opacity="0.55"/>
  </svg>`
}

function rowSvg(spec) {
  const g = TLV_GEOM
  const i = (spec.n || 1) - 1
  const rg = ribbonGeom(i)
  const path = ribbonPath(rg)
  const shadow = ribbonPath({
    ...rg,
    joinX: rg.joinX,
    headL: rg.headL,
    headR: rg.headR,
    top: rg.top + 2,
    bot: rg.bot + 2,
    mid: rg.mid + 2,
  })
  const ruleY = 38
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.rowH}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="${shadow}" fill="#1F2937" opacity="0.12"/>
    <path d="${path}" fill="currentColor"/>
    <path d="${path}" fill="#ffffff" opacity="0.16"/>
    <circle cx="${g.cx}" cy="${rg.mid}" r="8.5" fill="#ffffff"/>
    <circle cx="${g.cx}" cy="${rg.mid}" r="6" fill="currentColor"/>
    <rect x="${rg.ruleX}" y="${ruleY}" width="${rg.ruleW}" height="2" rx="1" fill="currentColor"/>
  </svg>`
}

function timelineVerticalChromeSpecs() {
  const g = TLV_GEOM
  const specs = [{
    slotId: 'TLV_PILLAR',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#F7F8FA',
    layer: 3,
    kind: 'pillar',
  }]
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `TLV_${i + 1}`,
      n: i + 1,
      x: 0,
      y: rowY(i),
      w: g.viewW,
      h: g.rowH,
      color: TLV_PALETTE[i],
      layer: 5,
      kind: 'row',
    })
  }
  return specs
}

function timelineVerticalOverlay(gx, gy, gw, gh) {
  const g = TLV_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  const nums = []
  const labels = []
  const titles = []
  const details = []
  for (let i = 0; i < g.n; i += 1) {
    const y = rowY(i)
    const rg = ribbonGeom(i)
    nums.push(box(rg.numX, y + rg.top + 8, rg.numW, g.capH - 16))
    labels.push(box(rg.textX, y + 8, rg.textW, 18))
    titles.push(box(rg.textX, y + 26, rg.textW, 14))
    details.push(box(rg.textX, y + 44, rg.textW, 44))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    nums,
    labels,
    titles,
    details,
    align: Array.from({ length: g.n }, (_, i) => (isRight(i) ? 'left' : 'right')),
  }
}

function specToTimelineVerticalContent(spec) {
  if (spec.kind === 'pillar') return { svg: pillarSvg(), colorMode: 'fixed', fill: spec.color }
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
  const stale = /^(phase\s*\d|project phases|discovery and planning|build and iterate|launch and scale|2024 q[13]|milestone detail)$/i.test(existing.trim())
  const text = existing && existing.toLowerCase() !== 'double-click to edit' && !stale
    ? existing
    : (TLV_DEFAULTS[sid] || existing)
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

function layoutTimelineVerticalElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLV_GEOM.viewW
  const sy = canvasH / TLV_GEOM.viewH
  const overlay = timelineVerticalOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLV_(PILLAR|\d+)$/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineVerticalTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlv'),
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
  for (let i = 0; i < TLV_GEOM.n; i += 1) {
    const n = i + 1
    const align = overlay.align[i]
    next.push(placeText(`milestone_${n}_num`, overlay.nums[i], {
      align: 'center', verticalAlign: 'center', fontSize: 18, fontWeight: 800, color: '#FFFFFF', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`milestone_${n}_label`, overlay.labels[i], {
      align, verticalAlign: 'center', fontSize: 14, fontWeight: 800, color: '#1F2937', clipToSlot: true, lineHeight: 1.1,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_title`, overlay.titles[i], {
      align, verticalAlign: 'center', fontSize: 10, fontWeight: 500, color: '#8A9099', clipToSlot: true, lineHeight: 1.1,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align, verticalAlign: 'top', fontSize: 10, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineVerticalChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineVerticalContent(spec)
    return {
      id: prev?.id || newId('shp-tlv'),
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


function layoutTimelineVertical(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineVerticalElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineVerticalElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineVerticalLayout,
  layoutTimelineVertical,
}
