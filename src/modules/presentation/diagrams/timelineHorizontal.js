/**
 * Timeline horizontal — year badges, numbered dots, icons, closed body cards.
 * Layout id: timeline_horizontal_v1 only (not cards).
 *
 * Badge/icon chrome is a short graphic so circles and icons stay round.
 * Body cards are a separate graphic so tall rounding is not applied to the icons.
 */

const TLH_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 28,
  headingY: 8,
  headingW: 944,
  headingH: 38,
  padX: 42,
  gap: 34,
  n: 5,
  cardY: 92,
  badgeY: 14,
  badgeH: 44,
  badgeOffX: 8,
  badgeOffY: -6,
  numR: 13,
  clusterH: 136,
  bodyGap: 4,
  bodyBottom: 78,
}

const TLH_PALETTE = ['#F05A4A', '#E7A033', '#74A572', '#44B1D2', '#27406A']

const LOREM = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore.'

const TLH_DEFAULTS = {
  HEADING: '5-Year Horizontal Timeline',
  milestone_1_label: '2021',
  milestone_2_label: '2022',
  milestone_3_label: '2023',
  milestone_4_label: '2024',
  milestone_5_label: '2025',
  milestone_1_num: '1',
  milestone_2_num: '2',
  milestone_3_num: '3',
  milestone_4_num: '4',
  milestone_5_num: '5',
  milestone_1_detail: LOREM,
  milestone_2_detail: LOREM,
  milestone_3_detail: LOREM,
  milestone_4_detail: LOREM,
  milestone_5_detail: LOREM,
}

function isTimelineHorizontalLayout(layoutId) {
  const id = String(layoutId || '')
  if (/cards/i.test(id)) return false
  return /timeline_horizontal_v1$/i.test(id)
}

function isTimelineHorizontalTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || /^milestone_\d+_label$/i.test(sid)
    || /^milestone_\d+_num$/i.test(sid)
    || /^milestone_\d+_detail$/i.test(sid)
}

function cardW() {
  const g = TLH_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return TLH_GEOM.padX + i * (cardW() + TLH_GEOM.gap)
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

function bodyTop() {
  const g = TLH_GEOM
  return g.cardY + g.clusterH + g.bodyGap
}

function bodyH() {
  return TLH_GEOM.viewH - bodyTop() - TLH_GEOM.bodyBottom
}

function columnIcon(n, cx, cy) {
  const scale = 1.7
  const wrap = (inner) => `<g transform="translate(${cx},${cy}) scale(${scale}) translate(-16,-16)">${inner}</g>`
  const icons = [
    `<g fill="currentColor">
      <path d="M21.8 4.2c.6 3.8-.5 8.1-3.2 11.8l-3.6-1.4-1.8 4.2-2-3-3.4 1.3C6.2 13.4 6.8 9 9.2 4.8 13.2 3.2 18.2 3 21.8 4.2z"/>
      <circle cx="16.8" cy="9.6" r="2" fill="#fff"/>
      <path d="M10.6 22.2c2.4-1.7 6.4-1.8 8.6.2" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>
      <path d="M10.2 22.6l-3.2 6.2 6.4-2.8z"/>
    </g>`,
    `<g fill="currentColor">
      <path d="M16 3.2a8 8 0 0 0-4.6 14.6v2.6h9.2v-2.6A8 8 0 0 0 16 3.2z"/>
      <circle cx="16" cy="11.2" r="2.5" fill="#fff"/>
      <rect x="12.1" y="21.4" width="7.8" height="1.7" rx="0.7"/>
      <rect x="12.8" y="23.9" width="6.4" height="1.6" rx="0.7"/>
      <rect x="13.8" y="26.3" width="4.4" height="1.6" rx="0.7"/>
    </g>`,
    `<g fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="14" cy="13.2" r="5.1"/>
      <circle cx="22.2" cy="21" r="5.1"/>
      <g fill="currentColor" stroke="none">
        <circle cx="14" cy="13.2" r="1.7"/>
        <circle cx="22.2" cy="21" r="1.7"/>
        <rect x="13.1" y="5.4" width="1.8" height="3.4" rx="0.5"/>
        <rect x="13.1" y="17.6" width="1.8" height="3.4" rx="0.5"/>
        <rect x="6.2" y="12.3" width="3.4" height="1.8" rx="0.5"/>
        <rect x="18.4" y="12.3" width="3.4" height="1.8" rx="0.5"/>
        <rect x="21.3" y="13.2" width="1.8" height="3.4" rx="0.5"/>
        <rect x="21.3" y="25.4" width="1.8" height="3.4" rx="0.5"/>
        <rect x="14.4" y="20.1" width="3.4" height="1.8" rx="0.5"/>
        <rect x="26.6" y="20.1" width="3.4" height="1.8" rx="0.5"/>
      </g>
    </g>`,
    `<g fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <polyline points="4.5,25 12,16.5 17.2,20.2 26.5,8.5"/>
      <polyline points="19.2,8.5 26.5,8.5 26.5,16"/>
    </g>`,
    `<g fill="currentColor">
      <path d="M11.2 9.4c0-4.2 3.1-7.2 6.8-7.2s6.8 3 6.8 7.2v5c0 3.8-2.9 6.4-6.8 6.4s-6.8-2.6-6.8-6.4z"/>
      <path d="M10.2 10.6c-2.4 0-3.8 1.8-3.8 3.8 0 2.6 2.4 4.4 5.4 4.8"/>
      <path d="M25.8 10.6c2.4 0 3.8 1.8 3.8 3.8 0 2.6-2.4 4.4-5.4 4.8"/>
      <rect x="16.4" y="21.4" width="3.2" height="3.6" rx="0.4"/>
      <rect x="12.6" y="25.4" width="10.8" height="2.4" rx="1.1"/>
    </g>`,
  ]
  return wrap(icons[(n - 1) % icons.length])
}

function badgeSize(w) {
  return Math.min(w - 16, w * 0.82)
}

function clusterSvg(spec) {
  const g = TLH_GEOM
  const w = cardW()
  const h = g.clusterH
  const bw = badgeSize(w)
  const bx = (w - bw) / 2 - g.badgeOffX / 2
  const by = g.badgeY
  const cx = w / 2
  const numCy = by + g.badgeH
  const iconCy = numCy + g.numR + 28
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="${bx + g.badgeOffX}" y="${by + g.badgeOffY}" width="${bw}" height="${g.badgeH}" rx="0" fill="currentColor" opacity="0.4"/>
    <rect x="${bx}" y="${by}" width="${bw}" height="${g.badgeH}" rx="0" fill="currentColor"/>
    <circle cx="${cx}" cy="${numCy}" r="${g.numR}" fill="currentColor"/>
    ${columnIcon(spec.n || 1, cx, iconCy)}
  </svg>`
}

function bodySvg() {
  const w = cardW()
  const h = bodyH()
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="5" y="2" width="${w - 10}" height="${h - 4}" rx="18" fill="#ffffff" stroke="#D2D6DC" stroke-width="1.5"/>
  </svg>`
}

function spineSvg() {
  const g = TLH_GEOM
  const y = g.cardY + g.badgeY + g.badgeH / 2
  const x1 = g.padX
  const x2 = g.viewW - g.padX
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="#4B5563" stroke-width="1.6" stroke-dasharray="3.5 5.5" stroke-linecap="round"/>
  </svg>`
}

function timelineHorizontalChromeSpecs() {
  const g = TLH_GEOM
  const w = cardW()
  const specs = [{
    slotId: 'TLH_SPINE',
    x: 0,
    y: 0,
    w: g.viewW,
    h: g.viewH,
    color: '#8A919C',
    layer: 3,
    spine: true,
  }]
  const by = bodyTop()
  const bh = bodyH()
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `TLH_${i + 1}B`,
      n: i + 1,
      x: cardX(i),
      y: by,
      w,
      h: bh,
      color: '#ffffff',
      layer: 4,
      body: true,
    })
    specs.push({
      slotId: `TLH_${i + 1}`,
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h: g.clusterH,
      color: TLH_PALETTE[i],
      layer: 6,
    })
  }
  return specs
}

function timelineHorizontalOverlay(gx, gy, gw, gh) {
  const g = TLH_GEOM
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
  const nums = []
  const details = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const y = g.cardY
    const bw = badgeSize(w)
    const bx = x + (w - bw) / 2 - TLH_GEOM.badgeOffX / 2
    const numCy = y + g.badgeY + g.badgeH
    const by = bodyTop()
    labels.push(box(bx + 4, y + g.badgeY + 2, bw - 8, g.badgeH - 6))
    nums.push(box(x + w / 2 - 12, numCy - 11, 24, 22))
    details.push(box(x + 12, by + 18, w - 24, bodyH() - 36))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    nums,
    details,
  }
}

function specToTimelineHorizontalContent(spec) {
  if (spec.spine) return { svg: spineSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec.body) return { svg: bodySvg(), colorMode: 'fixed', fill: '#ffffff' }
  return { svg: clusterSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function timelineHorizontalPreviewSvg() {
  const specs = timelineHorizontalChromeSpecs()
  const g = TLH_GEOM
  const parts = specs.map((spec) => {
    const inner = specToTimelineHorizontalContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 100 100'}" preserveAspectRatio="none" color="${spec.color}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
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
    : (TLH_DEFAULTS[sid] || existing)
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

function layoutTimelineHorizontalElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / TLH_GEOM.viewW
  const sy = canvasH / TLH_GEOM.viewH
  const overlay = timelineHorizontalOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^TLH_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isTimelineHorizontalTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-tlh'),
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
    next.push(placeText(`milestone_${n}_label`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 18, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'caption'))
    next.push(placeText(`milestone_${n}_num`, overlay.nums[i], {
      align: 'center', verticalAlign: 'center', fontSize: 12, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`milestone_${n}_detail`, overlay.details[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.45, wrap: 'wrap',
    }, 'body'))
  }

  const chrome = timelineHorizontalChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToTimelineHorizontalContent(spec)
    return {
      id: prev?.id || newId('shp-tlh'),
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


function layoutTimelineHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutTimelineHorizontalElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTimelineHorizontalElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTimelineHorizontalLayout,
  layoutTimelineHorizontal,
}
