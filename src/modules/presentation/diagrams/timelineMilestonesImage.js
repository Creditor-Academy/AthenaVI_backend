/**
 * Timeline milestones image — alternating above/below arrow-bar with photo frames.
 * Layout id: timeline_milestones_image_v1 only (not image_right / image_top).
 */

const TLMI_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 10,
  headingW: 700,
  headingH: 30,
  subX: 28,
  subY: 40,
  subW: 520,
  subH: 16,
  padX: 18,
  gap: 8,
  n: 6,
  axisY: 272,
  barH: 18,
  img: 86,
  nodeR: 7,
}

const TLMI_PALETTE = ['#1B3A5F', '#2E6BA6', '#2F9BB0', '#5AB3D0', '#7EC6DC', '#F08A2A']

const LOREM = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor.'

const PHASES = [
  { year: '1998', title: 'FOUNDATION' },
  { year: '2001', title: 'EXPANSION' },
  { year: '2005', title: 'PRODUCT' },
  { year: '2011', title: 'SCALE' },
  { year: '2013', title: 'PARTNERS' },
  { year: '2017', title: 'GLOBAL' },
]

const TLMI_DEFAULTS = {
  HEADING: 'Company milestones',
  SUBHEADING: 'INFOGRAPHIC TEMPLATE',
  ...PHASES.reduce((acc, phase, i) => {
    const n = i + 1
    acc[`milestone_${n}_num`] = phase.year
    acc[`milestone_${n}_label`] = phase.title
    acc[`milestone_${n}_detail`] = LOREM
    return acc
  }, {}),
}

function isTimelineMilestonesImageLayout(layoutId) {
  const id = String(layoutId || '')
  if (/right|top/i.test(id)) return false
  return /timeline_milestones_image_v1$/i.test(id)
}

function isTimelineMilestonesImageTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'SUBHEADING'
    || /^milestone_\d+_num$/i.test(sid)
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_detail$/i.test(sid)
}

function cardW() {
  const g = TLMI_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return TLMI_GEOM.padX + i * (cardW() + TLMI_GEOM.gap)
}

function isBelow(i) {
  return i % 2 === 0
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

function imageBox(i) {
  const g = TLMI_GEOM
  const w = cardW()
  const x = cardX(i) + (w - g.img) / 2
  const gap = 26
  if (isBelow(i)) return { x, y: g.axisY + g.barH / 2 + gap, w: g.img, h: g.img }
  return { x, y: g.axisY - g.barH / 2 - gap - g.img, w: g.img, h: g.img }
}

function columnChromeSvg(spec) {
  const g = TLMI_GEOM
  const w = cardW()
  const h = g.viewH
  const i = (spec.n || 1) - 1
  const below = isBelow(i)
  const cy = g.axisY
  const bh = g.barH
  const tip = w - 11
  const chev = `M 0 ${cy - bh / 2} L ${tip} ${cy - bh / 2} L ${w} ${cy} L ${tip} ${cy + bh / 2} L 0 ${cy + bh / 2} L 11 ${cy} Z`
  const img = imageBox(i)
  const iy = img.y
  const s = g.img
  const stemX = w / 2 - 0.8
  const stemY1 = below ? cy + bh / 2 : iy + s
  const stemY2 = below ? iy : cy - bh / 2
  const yTop = Math.min(stemY1, stemY2)
  const yBot = Math.max(stemY1, stemY2)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="${chev}" fill="currentColor"/>
    <rect x="${stemX}" y="${yTop}" width="1.6" height="${Math.max(0, yBot - yTop)}" fill="currentColor"/>
    <circle cx="${w / 2}" cy="${cy}" r="${g.nodeR + 3.2}" fill="#ffffff"/>
    <circle cx="${w / 2}" cy="${cy}" r="${g.nodeR}" fill="currentColor"/>
    <rect x="${(w - s) / 2}" y="${iy}" width="${s}" height="${s}" fill="#E7EDF2"/>
  </svg>`
}

function frameSvg() {
  const g = TLMI_GEOM
  const s = g.img
  const pad = 5
  const arm = 16
  const w = s + pad * 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${w}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="M${pad} ${pad + arm} V${pad} H${pad + arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
    <path d="M${w - pad - arm} ${pad} H${w - pad} V${pad + arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
    <path d="M${pad} ${w - pad - arm} V${w - pad} H${pad + arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
    <path d="M${w - pad - arm} ${w - pad} H${w - pad} V${w - pad - arm}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="square"/>
  </svg>`
}

function timelineMilestonesImageChromeSpecs() {
  const g = TLMI_GEOM
  const w = cardW()
  const specs = []
  const framePad = 5
  const frameS = g.img + framePad * 2
  for (let i = 0; i < g.n; i += 1) {
    const img = imageBox(i)
    specs.push({
      slotId: `TLMI_${i + 1}`,
      n: i + 1,
      x: cardX(i),
      y: 0,
      w,
      h: g.viewH,
      color: TLMI_PALETTE[i],
      layer: 5,
      kind: 'col',
    })
    specs.push({
      slotId: `TLMI_${i + 1}F`,
      n: i + 1,
      x: img.x - framePad,
      y: img.y - framePad,
      w: frameS,
      h: frameS,
      color: TLMI_PALETTE[i],
      layer: 9,
      kind: 'frame',
    })
  }
  return specs
}

function timelineMilestonesImageOverlay(gx, gy, gw, gh) {
  const g = TLMI_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  const w = cardW()
  const years = []
  const titles = []
  const details = []
  const images = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const img = imageBox(i)
    images.push(box(img.x, img.y, img.w, img.h))
    if (isBelow(i)) {
      years.push(box(x, g.axisY - 34, w, 22))
      titles.push(box(x + 4, img.y + img.h + 8, w - 8, 16))
      details.push(box(x + 4, img.y + img.h + 26, w - 8, 72))
    } else {
      years.push(box(x, g.axisY + 16, w, 22))
      titles.push(box(x + 4, img.y - 86, w - 8, 16))
      details.push(box(x + 4, img.y - 68, w - 8, 48))
    }
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

function specToTimelineMilestonesImageContent(spec) {
  if (spec.kind === 'frame') return { svg: frameSvg(), colorMode: 'recolorable', fill: spec.color }
  return { svg: columnChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
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
    : (TLMI_DEFAULTS[sid] || existing)
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

function layoutTimelineMilestonesImageElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLMI_GEOM.viewW
  const sy = canvasH / TLMI_GEOM.viewH
  const overlay = timelineMilestonesImageOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLMI_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const images = elements.filter((el) => el.type === 'image' || /^IMAGE_\d+$/i.test(String(el.slotId || '')))
  const filtered = elements.filter((el) => (
    !chromeRe.test(String(el.slotId || ''))
    && el.type !== 'image'
    && !/^IMAGE_\d+$/i.test(String(el.slotId || ''))
    && isTimelineMilestonesImageTextSlot(el.slotId)
  ))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlmi'),
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
  for (let i = 0; i < 6; i += 1) {
    const n = i + 1
    const accent = TLMI_PALETTE[i]
    next.push(placeText(`milestone_${n}_num`, overlay.years[i], {
      align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`milestone_${n}_label`, overlay.titles[i], {
      align: 'center', verticalAlign: 'center', fontSize: 10, fontWeight: 800, color: accent, clipToSlot: true, lineHeight: 1, letterSpacing: '0.04em',
    }, 'caption'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: 'center', verticalAlign: 'top', fontSize: 9, fontWeight: 400, color: '#6B7280', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap',
    }, 'body'))
  }

  const placedImages = []
  const used = new Set()
  for (let i = 0; i < 6; i += 1) {
    const box = overlay.images[i]
    const prev = images.find((el) => imageIndex(el) === i && !used.has(el.id))
      || images.find((el) => !used.has(el.id) && imageIndex(el) < 0)
    if (prev?.id) used.add(prev.id)
    placedImages.push({
      ...(prev || {}),
      id: prev?.id || newId('img-tlmi'),
      type: 'image',
      slotId: `IMAGE_${i + 1}`,
      layer: 8,
      role: prev?.role || 'image',
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: { ...(prev?.content || {}), fit: 'cover', objectFit: 'cover' },
    })
  }

  const chrome = timelineMilestonesImageChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineMilestonesImageContent(spec)
    return {
      id: prev?.id || newId('shp-tlmi'),
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


function layoutTimelineMilestonesImage(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineMilestonesImageElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineMilestonesImageElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineMilestonesImageLayout,
  layoutTimelineMilestonesImage,
}
