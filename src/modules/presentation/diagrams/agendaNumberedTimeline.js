/**
 * Agenda numbered timeline — horizontal axis, ripple nodes, staggered labels (4 stops).
 */

const AGENDA_NUMBERED_TL_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 16,
  headingH: 42,
  padX: 108,
  axisY: 198,
  nodeR: 44,
  n: 4,
}

const NUMBERED_TL_PALETTE = [
  { main: '#7CB342', icon: 'bulb' },
  { main: '#2F6FED', icon: 'clock' },
  { main: '#E53935', icon: 'budget' },
  { main: '#FF6E40', icon: 'megaphone' },
]

function nodeCenters() {
  const { viewW, padX, n } = AGENDA_NUMBERED_TL_GEOM
  const span = viewW - padX * 2
  const step = n <= 1 ? 0 : span / (n - 1)
  return Array.from({ length: n }, (_, i) => padX + i * step)
}

function isLow(i) {
  return i % 2 === 0
}

function stemLen(i) {
  return isLow(i) ? 156 : 84
}

function iconMarkup(key, cx, cy, r) {
  const s = r * 0.42
  const sw = 2.1
  if (key === 'clock') {
    return `<circle cx="${cx}" cy="${cy}" r="${s}" fill="none" stroke="#fff" stroke-width="${sw}"/>
      <path d="M ${cx} ${cy - s * 0.55} V ${cy} L ${cx + s * 0.38} ${cy + s * 0.18}" fill="none" stroke="#fff" stroke-width="${sw}" stroke-linecap="round"/>`
  }
  if (key === 'megaphone') {
    return `<path d="M ${cx - s * 0.55} ${cy - s * 0.12} L ${cx + s * 0.15} ${cy - s * 0.48} L ${cx + s * 0.15} ${cy + s * 0.48} L ${cx - s * 0.55} ${cy + s * 0.12} Z" fill="none" stroke="#fff" stroke-width="${sw}" stroke-linejoin="round"/>
      <path d="M ${cx + s * 0.22} ${cy - s * 0.18} Q ${cx + s * 0.55} ${cy} ${cx + s * 0.22} ${cy + s * 0.18}" fill="none" stroke="#fff" stroke-width="${sw}" stroke-linecap="round"/>`
  }
  if (key === 'budget') {
    return `<circle cx="${cx}" cy="${cy}" r="${s}" fill="none" stroke="#fff" stroke-width="${sw}"/>
      <path d="M ${cx} ${cy - s * 0.42} V ${cy + s * 0.42} M ${cx - s * 0.28} ${cy - s * 0.18} Q ${cx} ${cy - s * 0.38} ${cx + s * 0.28} ${cy - s * 0.08} Q ${cx} ${cy + s * 0.12} ${cx - s * 0.22} ${cy + s * 0.22}" fill="none" stroke="#fff" stroke-width="${sw}" stroke-linecap="round"/>`
  }
  return `<path d="M ${cx} ${cy - s * 0.62} Q ${cx + s * 0.48} ${cy - s * 0.18} ${cx + s * 0.22} ${cy + s * 0.18} H ${cx - s * 0.22} Q ${cx - s * 0.48} ${cy - s * 0.18} ${cx} ${cy - s * 0.62} Z" fill="none" stroke="#fff" stroke-width="${sw}" stroke-linejoin="round"/>
    <path d="M ${cx - s * 0.12} ${cy + s * 0.22} V ${cy + s * 0.5} H ${cx + s * 0.12}" fill="none" stroke="#fff" stroke-width="${sw}" stroke-linecap="round"/>`
}

function agendaNumberedTimelineGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.04),
    headingH: Math.round(canvasH * 0.08),
  }
}

function nodeBox(i, cx) {
  const { axisY, nodeR } = AGENDA_NUMBERED_TL_GEOM
  const ring = nodeR + 34
  const numH = 30
  const stem = stemLen(i)
  return {
    x: cx - ring - 8,
    y: axisY - ring - numH,
    w: ring * 2 + 16,
    h: numH + ring + stem + 6,
    cxLocal: ring + 8,
    cyLocal: numH + ring,
    stem,
  }
}

function axisInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 8" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="0" y1="4" x2="100" y2="4" stroke="currentColor" stroke-width="3.4" stroke-linecap="round"/>
  </svg>`
}

function agendaNumberedTimelineNodeInlineSvg(spec) {
  const w = spec.w
  const h = spec.h
  const r = spec.nodeR || AGENDA_NUMBERED_TL_GEOM.nodeR
  const cx = spec.cxLocal != null ? spec.cxLocal : w / 2
  const cy = spec.cyLocal != null ? spec.cyLocal : r + 34 + 30
  const stem = spec.stem || 84
  const n = spec.n || 1
  const rings = [10, 18, 26, 34].map((extra, ri) => (
    `<circle cx="${cx}" cy="${cy}" r="${r + extra}" fill="none" stroke="currentColor" stroke-width="1.6" opacity="${0.38 - ri * 0.07}"/>`
  )).join('')
  const num = String(n).padStart(2, '0')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="${cx}" y1="${cy}" x2="${cx}" y2="${cy + stem}" stroke="currentColor" stroke-width="2.2"/>
    ${rings}
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>
    ${iconMarkup(spec.iconKey, cx, cy, r)}
    <text x="${cx}" y="${cy - r - 38}" text-anchor="middle" fill="currentColor" stroke="none" font-size="18" font-weight="800" font-family="Arial,Helvetica,sans-serif">${num}</text>
  </svg>`
}

function agendaNumberedTimelineInlineSvg() {
  const specs = agendaNumberedTimelineChromeSpecs()
  const { viewW, viewH } = AGENDA_NUMBERED_TL_GEOM
  const parts = specs.map((spec) => {
    const inner = spec.axis ? axisInlineSvg() : agendaNumberedTimelineNodeInlineSvg(spec)
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="none">${parts.join('')}</svg>`
}

function agendaNumberedTimelineChromeSpecs() {
  const { viewW, padX, axisY, nodeR } = AGENDA_NUMBERED_TL_GEOM
  const centers = nodeCenters()
  const specs = [{
    slotId: 'AGENDA_NUM_TL_AXIS',
    kind: 'graphic',
    axis: true,
    x: padX - 48,
    y: axisY - 4,
    w: viewW - (padX - 48) * 2,
    h: 8,
    color: '#C5CAD3',
    layer: 3,
  }]
  centers.forEach((cx, i) => {
    const pal = NUMBERED_TL_PALETTE[i]
    const box = nodeBox(i, cx)
    specs.push({
      slotId: `AGENDA_NUM_TL_NODE_${i + 1}`,
      kind: 'graphic',
      x: box.x,
      y: box.y,
      w: box.w,
      h: box.h,
      cxLocal: box.cxLocal,
      cyLocal: box.cyLocal,
      stem: box.stem,
      nodeR,
      n: i + 1,
      color: pal.main,
      iconKey: pal.icon,
      layer: 4,
    })
  })
  return specs
}

function agendaNumberedTimelineOverlayPlacements(gx, gy, gw, gh) {
  const { viewW, viewH, headingY, headingH, axisY } = AGENDA_NUMBERED_TL_GEOM
  const sx = gw / viewW
  const sy = gh / viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(24, Math.round(w * sx)),
    height: Math.max(18, Math.round(h * sy)),
  })
  const overlay = {
    heading: box(80, headingY, viewW - 160, headingH),
    items: [],
    itemBodies: [],
  }
  const centers = nodeCenters()
  const colW = 168
  for (let i = 0; i < centers.length; i += 1) {
    const cx = centers[i]
    const titleY = axisY + stemLen(i) + 8
    overlay.items.push(box(cx - colW / 2, titleY, colW, 28))
    overlay.itemBodies.push(box(cx - colW / 2, titleY + 30, colW, isLow(i) ? 88 : 72))
  }
  return overlay
}

function agendaNumberedTimelinePreviewSvg() {
  return agendaNumberedTimelineInlineSvg().replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"'
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"'
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"'
    return `<svg${next}>`
  })
}

function specToNumberedTimelineContent(spec) {
  if (spec?.axis) {
    return { svg: axisInlineSvg(), colorMode: 'recolorable', fill: spec.color || '#C5CAD3' }
  }
  return { svg: agendaNumberedTimelineNodeInlineSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function isAgendaNumberedTimelineLayout(layoutId, family, variant) {
  if (family === 'numbered' && (variant === 'path' || variant === 'timeline')) return true
  return /agenda_numbered_timeline/i.test(String(layoutId || ''))
}

function isAgendaNumberedTimelineTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || /^ITEM_\d+$/.test(sid) || /^ITEM_\d+_BODY$/.test(sid)
}

module.exports = { AGENDA_NUMBERED_TL_GEOM, NUMBERED_TL_PALETTE, agendaNumberedTimelineGraphicFrame, agendaNumberedTimelineNodeInlineSvg, agendaNumberedTimelineInlineSvg, agendaNumberedTimelineChromeSpecs, agendaNumberedTimelineOverlayPlacements, agendaNumberedTimelinePreviewSvg, specToNumberedTimelineContent, isAgendaNumberedTimelineLayout, isAgendaNumberedTimelineTextSlot };
