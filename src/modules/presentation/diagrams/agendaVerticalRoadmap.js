/**
 * Agenda vertical roadmap — 4 recolorable rows (capsule + node + arm + icon).
 */

const AGENDA_VR_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 80,
  headingY: 10,
  headingW: 840,
  headingH: 44,
  cx: 500,
  spineW: 22,
  rowTop: 62,
  rowH: 122,
  gap: 10,
  n: 4,
  iconR: 40,
  iconOffset: 198,
  nodeR: 18,
  textW: 372,
}

const VR_PALETTE = [
  { main: '#8BC34A', icon: 'leaf' },
  { main: '#F0A202', icon: 'doc' },
  { main: '#E85D75', icon: 'search' },
  { main: '#4A90D9', icon: 'globe' },
]

function agendaVerticalRoadmapGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.018),
    headingH: Math.round(canvasH * 0.078),
  }
}

function iconMarkup(key, cx, cy) {
  const s = 16
  const sw = 2.4
  const c = `fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round"`
  if (key === 'doc') {
    return `<path d="M ${cx - s * 0.42} ${cy - s * 0.55} H ${cx + s * 0.12} L ${cx + s * 0.42} ${cy - s * 0.22} V ${cy + s * 0.55} H ${cx - s * 0.42} Z" ${c}/>
      <path d="M ${cx + s * 0.12} ${cy - s * 0.55} V ${cy - s * 0.22} H ${cx + s * 0.42}" ${c}/>
      <path d="M ${cx - s * 0.2} ${cy} H ${cx + s * 0.18} M ${cx - s * 0.2} ${cy + s * 0.22} H ${cx + s * 0.18}" ${c}/>`
  }
  if (key === 'search') {
    return `<circle cx="${cx - 3}" cy="${cy - 3}" r="${s * 0.42}" ${c}/>
      <path d="M ${cx + 5} ${cy + 6} L ${cx + 12} ${cy + 13}" ${c}/>`
  }
  if (key === 'globe') {
    return `<circle cx="${cx}" cy="${cy}" r="${s * 0.62}" ${c}/>
      <ellipse cx="${cx}" cy="${cy}" rx="${s * 0.28}" ry="${s * 0.62}" ${c}/>
      <path d="M ${cx - s * 0.58} ${cy} H ${cx + s * 0.58} M ${cx - s * 0.42} ${cy - s * 0.28} H ${cx + s * 0.42} M ${cx - s * 0.42} ${cy + s * 0.28} H ${cx + s * 0.42}" ${c}/>`
  }
  return `<path d="M ${cx} ${cy + s * 0.55} Q ${cx - s * 0.55} ${cy + s * 0.1} ${cx - s * 0.18} ${cy - s * 0.45} Q ${cx} ${cy - s * 0.7} ${cx + s * 0.28} ${cy - s * 0.22} Q ${cx + s * 0.5} ${cy + s * 0.18} ${cx} ${cy + s * 0.55} Z" ${c}/>
    <path d="M ${cx} ${cy + s * 0.55} V ${cy - s * 0.2}" ${c}/>`
}

function rowInlineSvg(spec) {
  const g = AGENDA_VR_GEOM
  const w = g.viewW
  const h = g.rowH
  const cx = g.cx
  const cy = h / 2
  const capH = h - g.gap
  const capY = (h - capH) / 2
  const iconOnRight = spec.iconOnRight !== false
  const iconX = cx + (iconOnRight ? g.iconOffset : -g.iconOffset)
  const armFrom = cx + (iconOnRight ? g.nodeR + 8 : -(g.nodeR + 8))
  const armTo = iconX + (iconOnRight ? -(g.iconR + 2) : g.iconR + 2)
  const fid = `vrSh${spec.n || 1}`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs><filter id="${fid}" x="-40%" y="-40%" width="180%" height="180%">
      <feDropShadow dx="0" dy="2" stdDeviation="2.2" flood-color="#1f2937" flood-opacity="0.18"/>
    </filter></defs>
    <rect x="${cx - g.spineW / 2}" y="${capY}" width="${g.spineW}" height="${capH}" rx="${g.spineW / 2}" fill="currentColor"/>
    <line x1="${armFrom}" y1="${cy}" x2="${armTo}" y2="${cy}" stroke="currentColor" stroke-width="3.2" stroke-linecap="round"/>
    <circle cx="${cx}" cy="${cy}" r="${g.nodeR + 6}" fill="#ffffff"/>
    <circle cx="${cx}" cy="${cy}" r="${g.nodeR}" fill="#ffffff" stroke="currentColor" stroke-width="3" filter="url(#${fid})"/>
    <circle cx="${cx}" cy="${cy}" r="6.5" fill="currentColor"/>
    <circle cx="${iconX}" cy="${cy}" r="${g.iconR}" fill="#ffffff" stroke="currentColor" stroke-width="5" filter="url(#${fid})"/>
    ${iconMarkup(spec.iconKey || 'leaf', iconX, cy)}
  </svg>`
}

function agendaVerticalRoadmapChromeSpecs() {
  const g = AGENDA_VR_GEOM
  const specs = []
  for (let i = 0; i < g.n; i += 1) {
    const pal = VR_PALETTE[i]
    specs.push({
      slotId: `AGENDA_VR_${i + 1}`,
      kind: 'graphic',
      roadmap: true,
      n: i + 1,
      iconKey: pal.icon,
      iconOnRight: i % 2 === 0,
      x: 0,
      y: g.rowTop + i * g.rowH,
      w: g.viewW,
      h: g.rowH,
      color: pal.main,
      layer: 4,
    })
  }
  return specs
}

function agendaVerticalRoadmapOverlayPlacements(gx, gy, gw, gh) {
  const g = AGENDA_VR_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(20, Math.round(w * sx)),
    height: Math.max(14, Math.round(h * sy)),
  })
  const items = []
  const years = []
  const itemBodies = []
  for (let i = 0; i < g.n; i += 1) {
    const cy = g.rowTop + i * g.rowH + g.rowH / 2
    const textOnLeft = i % 2 === 0
    const textX = textOnLeft ? 40 : g.cx + 48
    years.push(box(textX, cy - 30, 86, 32))
    items.push(box(textX + 90, cy - 30, g.textW - 90, 32))
    itemBodies.push(box(textX, cy + 6, g.textW, 48))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    items,
    years,
    itemBodies,
    columns: [],
    milestones: [],
  }
}

function specToVerticalRoadmapContent(spec) {
  return { svg: rowInlineSvg(spec), colorMode: 'recolorable', fill: spec?.color || VR_PALETTE[0].main }
}

function agendaVerticalRoadmapPreviewSvg() {
  const specs = agendaVerticalRoadmapChromeSpecs()
  const { viewW, viewH } = AGENDA_VR_GEOM
  const parts = specs.map((spec) => {
    const inner = specToVerticalRoadmapContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 1000 122'}" preserveAspectRatio="none" color="${spec.color}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function isAgendaVerticalRoadmapLayout(layoutId, family, variant) {
  if (family === 'timeline' && variant === 'vertical') return true
  return /agenda_vertical_roadmap_v1$/i.test(String(layoutId || ''))
}

function isAgendaVerticalRoadmapTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || /^ITEM_\d+$/.test(sid) || /^ITEM_\d+_YEAR$/.test(sid) || /^ITEM_\d+_BODY$/.test(sid)
}

module.exports = {
  AGENDA_VR_GEOM,
  VR_PALETTE,
  agendaVerticalRoadmapGraphicFrame,
  agendaVerticalRoadmapChromeSpecs,
  agendaVerticalRoadmapOverlayPlacements,
  specToVerticalRoadmapContent,
  agendaVerticalRoadmapPreviewSvg,
  isAgendaVerticalRoadmapLayout,
  isAgendaVerticalRoadmapTextSlot,
}
