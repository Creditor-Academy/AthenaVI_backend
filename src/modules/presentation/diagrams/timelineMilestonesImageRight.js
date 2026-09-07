/**
 * Timeline milestones image right — vertical list, photos on the right of each row.
 * Layout id: timeline_milestones_image_right_v1 only (not image / image_top).
 */

const TLMIR_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 10,
  headingW: 620,
  headingH: 28,
  subX: 28,
  subY: 40,
  subW: 480,
  subH: 16,
  n: 4,
  startY: 70,
  rowH: 112,
  gap: 10,
  accentX: 28,
  accentW: 5,
  spineX: 536,
  nodeR: 7,
  img: 108,
  imgX: 864,
}

const TLMIR_PALETTE = ['#1F4E79', '#1F8A7A', '#C45C26', '#6B2D5B']

const LOREM = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.'

const PHASES = [
  { year: '2018', title: 'LAUNCH' },
  { year: '2021', title: 'GROWTH' },
  { year: '2023', title: 'PRODUCT' },
  { year: '2026', title: 'GLOBAL' },
]

const TLMIR_DEFAULTS = {
  HEADING: 'Milestones at a glance',
  SUBHEADING: 'CHAPTER TIMELINE',
  ...PHASES.reduce((acc, phase, i) => {
    const n = i + 1
    acc[`milestone_${n}_num`] = phase.year
    acc[`milestone_${n}_label`] = phase.title
    acc[`milestone_${n}_detail`] = LOREM
    return acc
  }, {}),
}

function isTimelineMilestonesImageRightLayout(layoutId) {
  return /timeline_milestones_image_right_v1$/i.test(String(layoutId || ''))
}

function isTimelineMilestonesImageRightTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'SUBHEADING'
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#2D3340'
}

function rowY(i) {
  const g = TLMIR_GEOM
  return g.startY + i * (g.rowH + g.gap)
}

function rowMid(i) {
  return rowY(i) + TLMIR_GEOM.rowH / 2
}

function imageBox(i) {
  const g = TLMIR_GEOM
  return {
    x: g.imgX,
    y: rowY(i) + (g.rowH - g.img) / 2,
    w: g.img,
    h: g.img,
  }
}

function spineSvg() {
  const g = TLMIR_GEOM
  const y1 = rowMid(0)
  const y2 = rowMid(g.n - 1)
  const h = g.viewH
  const x = g.spineX
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="${x - 1}" y="${y1}" width="2" height="${Math.max(0, y2 - y1)}" fill="currentColor"/>
    <polygon points="${x},${y2 + 10} ${x - 5},${y2} ${x + 5},${y2}" fill="currentColor"/>
  </svg>`
}

function rowSvg(spec) {
  const g = TLMIR_GEOM
  const w = g.viewW
  const h = g.rowH
  const mid = h / 2
  const barH = h - 28
  const iy = (h - g.img) / 2
  const stemX1 = g.spineX + g.nodeR + 3
  const stemX2 = g.imgX
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="${g.accentX}" y="14" width="${g.accentW}" height="${barH}" rx="2" fill="currentColor"/>
    <rect x="${stemX1}" y="${mid - 0.8}" width="${Math.max(0, stemX2 - stemX1)}" height="1.6" fill="currentColor"/>
    <circle cx="${g.spineX}" cy="${mid}" r="${g.nodeR + 3.2}" fill="#ffffff"/>
    <circle cx="${g.spineX}" cy="${mid}" r="${g.nodeR}" fill="currentColor"/>
    <rect x="${g.imgX}" y="${iy}" width="${g.img}" height="${g.img}" fill="#E7EDF2"/>
  </svg>`
}

function frameSvg() {
  const g = TLMIR_GEOM
  const s = g.img
  const pad = 5
  const arm = 18
  const w = s + pad * 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${w}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="M${pad} ${pad + arm} V${pad} H${pad + arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
    <path d="M${w - pad - arm} ${pad} H${w - pad} V${pad + arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
    <path d="M${pad} ${w - pad - arm} V${w - pad} H${pad + arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
    <path d="M${w - pad - arm} ${w - pad} H${w - pad} V${w - pad - arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
  </svg>`
}

function timelineMilestonesImageRightChromeSpecs() {
  const g = TLMIR_GEOM
  const specs = [{
    slotId: 'TLMIR_SPINE',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#C5CBD3',
    layer: 4,
    kind: 'spine',
  }]
  const framePad = 5
  const frameS = g.img + framePad * 2
  for (let i = 0; i < g.n; i += 1) {
    const img = imageBox(i)
    specs.push({
      slotId: `TLMIR_${i + 1}`,
      n: i + 1,
      x: 0,
      y: rowY(i),
      w: g.viewW,
      h: g.rowH,
      color: TLMIR_PALETTE[i],
      layer: 5,
      kind: 'row',
    })
    specs.push({
      slotId: `TLMIR_${i + 1}F`,
      n: i + 1,
      x: img.x - framePad,
      y: img.y - framePad,
      w: frameS,
      h: frameS,
      color: TLMIR_PALETTE[i],
      layer: 9,
      kind: 'frame',
    })
  }
  return specs
}

function timelineMilestonesImageRightOverlay(gx, gy, gw, gh) {
  const g = TLMIR_GEOM
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
  const details = []
  const images = []
  const textLeft = g.accentX + g.accentW + 14
  const textW = g.spineX - textLeft - 22
  for (let i = 0; i < g.n; i += 1) {
    const y = rowY(i)
    const img = imageBox(i)
    images.push(box(img.x, img.y, img.w, img.h))
    years.push(box(textLeft, y + 14, 88, 24))
    titles.push(box(textLeft + 96, y + 14, textW - 96, 24))
    details.push(box(textLeft + 96, y + 42, textW - 96, 58))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    sub: box(g.subX, g.subY, g.subW, g.subH),
    years,
    titles,
    details,
    images,
  }
}

function specToTimelineMilestonesImageRightContent(spec) {
  if (spec.kind === 'spine') return { svg: spineSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'frame') return { svg: frameSvg(), colorMode: 'recolorable', fill: spec.color }
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
  const stale = /^(2020|key event summary|key milestones)$/i.test(existing.trim())
  const text = existing && existing.toLowerCase() !== 'double-click to edit' && !stale
    ? existing
    : (TLMIR_DEFAULTS[sid] || existing)
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

function imageIndex(el) {
  const sid = String(el.slotId || '')
  const m = sid.match(/^IMAGE_(\d+)$/i)
  if (m) return Number(m[1]) - 1
  return -1
}

function layoutTimelineMilestonesImageRightElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLMIR_GEOM.viewW
  const sy = canvasH / TLMIR_GEOM.viewH
  const overlay = timelineMilestonesImageRightOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLMIR_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const images = elements.filter((el) => el.type === 'image' || /^IMAGE_\d+$/i.test(String(el.slotId || '')))
  const filtered = elements.filter((el) => (
    !chromeRe.test(String(el.slotId || ''))
    && el.type !== 'image'
    && !/^IMAGE_\d+$/i.test(String(el.slotId || ''))
    && isTimelineMilestonesImageRightTextSlot(el.slotId)
  ))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlmir'),
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
    placeText('SUBHEADING', overlay.sub, {
      align: 'left', verticalAlign: 'center', fontSize: 10, fontWeight: 600, color: '#9AA3B2', clipToSlot: true, lineHeight: 1, letterSpacing: '0.18em',
    }, 'caption'),
  ]
  for (let i = 0; i < TLMIR_GEOM.n; i += 1) {
    const n = i + 1
    const accent = TLMIR_PALETTE[i]
    next.push(placeText(`milestone_${n}_num`, overlay.years[i], {
      align: 'left', verticalAlign: 'center', fontSize: 16, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`milestone_${n}_label`, overlay.titles[i], {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1, letterSpacing: '0.06em',
    }, 'caption'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap',
    }, 'body'))
  }

  const placedImages = []
  const used = new Set()
  for (let i = 0; i < TLMIR_GEOM.n; i += 1) {
    const box = overlay.images[i]
    const prev = images.find((el) => imageIndex(el) === i && !used.has(el.id))
      || images.find((el) => !used.has(el.id) && imageIndex(el) < 0)
    if (prev?.id) used.add(prev.id)
    placedImages.push({
      ...(prev || {}),
      id: prev?.id || newId('img-tlmir'),
      type: 'image',
      slotId: `IMAGE_${i + 1}`,
      layer: 8,
      role: prev?.role || 'image',
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: { ...(prev?.content || {}), fit: 'cover', objectFit: 'cover' },
    })
  }

  const chrome = timelineMilestonesImageRightChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineMilestonesImageRightContent(spec)
    return {
      id: prev?.id || newId('shp-tlmir'),
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
  return [...chrome, ...placedImages, ...next]
}


function layoutTimelineMilestonesImageRight(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineMilestonesImageRightElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineMilestonesImageRightElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineMilestonesImageRightLayout,
  layoutTimelineMilestonesImageRight,
}
