/**
 * Agenda timeline preview — 6 hex nodes + pastel body cards (no time pills).
 */

const AGENDA_TL_HEX_GEOM = {
  viewW: 1000,
  viewH: 560,
  n: 6,
  padX: 22,
  gap: 16,
  headingX: 80,
  headingY: 10,
  headingW: 840,
  headingH: 38,
  subX: 310,
  subY: 50,
  subW: 380,
  subH: 28,
  titleY: 88,
  titleH: 24,
  hexSize: 92,
}

const TL_HEX_PALETTE = [
  { main: '#7CB342', icon: 'bulb' },
  { main: '#2F6FED', icon: 'clock' },
  { main: '#E53935', icon: 'budget' },
  { main: '#E0A106', icon: 'megaphone' },
  { main: '#FF8A3D', icon: 'gears' },
  { main: '#8B5CF6', icon: 'alert' },
]

function colW() {
  const g = AGENDA_TL_HEX_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function colX(i) {
  return AGENDA_TL_HEX_GEOM.padX + i * (colW() + AGENDA_TL_HEX_GEOM.gap)
}

function stackY() {
  const g = AGENDA_TL_HEX_GEOM
  const hexY = g.titleY + g.titleH + 6
  const hexH = g.hexSize
  const badgeCy = hexY + hexH * 0.78
  const cardY = hexY + hexH + 4
  return { hexY, hexH, badgeCy, cardY, cardH: g.viewH - cardY - 18 }
}

function agendaTimelineHexGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.018),
    headingH: Math.round(canvasH * 0.068),
  }
}

function hexPoints(cx, cy, r) {
  const pts = []
  for (let i = 0; i < 6; i += 1) {
    const a = ((-90 + i * 60) * Math.PI) / 180
    pts.push(`${(cx + r * Math.cos(a)).toFixed(1)},${(cy + r * Math.sin(a)).toFixed(1)}`)
  }
  return pts.join(' ')
}

function iconMarkup(key, cx, cy, r) {
  const s = r * 0.4
  const sw = 2.3
  const common = `fill="none" stroke="#fff" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round"`
  if (key === 'clock') {
    return `<circle cx="${cx}" cy="${cy}" r="${s}" ${common}/>
      <path d="M ${cx} ${cy - s * 0.52} V ${cy} L ${cx + s * 0.38} ${cy + s * 0.18}" ${common}/>`
  }
  if (key === 'megaphone') {
    return `<path d="M ${cx - s * 0.58} ${cy - s * 0.12} L ${cx + s * 0.08} ${cy - s * 0.52} L ${cx + s * 0.08} ${cy + s * 0.52} L ${cx - s * 0.58} ${cy + s * 0.12} Z" ${common}/>
      <path d="M ${cx - s * 0.58} ${cy - s * 0.12} V ${cy + s * 0.12} L ${cx - s * 0.82} ${cy + s * 0.28} V ${cy - s * 0.28} Z" ${common}/>
      <path d="M ${cx + s * 0.22} ${cy - s * 0.18} Q ${cx + s * 0.62} ${cy} ${cx + s * 0.22} ${cy + s * 0.18}" ${common}/>`
  }
  if (key === 'budget') {
    return `<circle cx="${cx}" cy="${cy}" r="${s}" ${common}/>
      <path d="M ${cx} ${cy - s * 0.42} V ${cy + s * 0.42} M ${cx - s * 0.28} ${cy - s * 0.18} Q ${cx} ${cy - s * 0.38} ${cx + s * 0.28} ${cy - s * 0.1} Q ${cx} ${cy + 2} ${cx - s * 0.22} ${cy + s * 0.18} Q ${cx + s * 0.08} ${cy + s * 0.38} ${cx + s * 0.3} ${cy + s * 0.22}" ${common}/>`
  }
  if (key === 'gears') {
    return `<circle cx="${cx - s * 0.16}" cy="${cy - s * 0.06}" r="${s * 0.34}" ${common}/>
      <circle cx="${cx + s * 0.28}" cy="${cy + s * 0.18}" r="${s * 0.24}" ${common}/>
      <path d="M ${cx - s * 0.16} ${cy - s * 0.46} V ${cy + s * 0.34} M ${cx - s * 0.5} ${cy - s * 0.06} H ${cx + s * 0.18}" ${common}/>`
  }
  if (key === 'alert') {
    return `<path d="M ${cx} ${cy - s * 0.62} L ${cx + s * 0.58} ${cy + s * 0.5} H ${cx - s * 0.58} Z" ${common}/>
      <path d="M ${cx} ${cy - s * 0.18} V ${cy + s * 0.14}" ${common}/>
      <circle cx="${cx}" cy="${cy + s * 0.32}" r="1.4" fill="#fff" stroke="none"/>`
  }
  return `<path d="M ${cx} ${cy - s * 0.58} Q ${cx + s * 0.5} ${cy - s * 0.22} ${cx + s * 0.22} ${cy + s * 0.14} H ${cx - s * 0.22} Q ${cx - s * 0.5} ${cy - s * 0.22} ${cx} ${cy - s * 0.58} Z" ${common}/>
    <path d="M ${cx} ${cy + s * 0.14} V ${cy + s * 0.42} M ${cx - s * 0.16} ${cy + s * 0.42} H ${cx + s * 0.16}" ${common}/>`
}

function hexNodeInlineSvg(spec) {
  const vb = 100
  const cx = 50
  const cy = 44
  const r = 36
  const badgeCy = 80
  const n = String(spec.n || 1).padStart(2, '0')
  const icon = spec.iconKey || 'bulb'
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${vb} ${vb}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <polygon points="${hexPoints(cx, cy, r)}" fill="currentColor"/>
    ${iconMarkup(icon, cx, cy, r)}
    <circle cx="${cx}" cy="${badgeCy}" r="15.5" fill="#ffffff"/>
    <circle cx="${cx}" cy="${badgeCy}" r="15.5" fill="none" stroke="currentColor" stroke-width="2.4"/>
    <text x="${cx}" y="${badgeCy + 4.5}" text-anchor="middle" fill="currentColor" stroke="none" font-size="11" font-weight="800" font-family="Arial,Helvetica,sans-serif">${n}</text>
  </svg>`
}

function cardInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 220" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="2" y="4" width="116" height="214" rx="14" fill="currentColor" opacity="0.15"/>
    <rect x="2" y="4" width="116" height="6" rx="3" fill="currentColor" opacity="0.85"/>
  </svg>`
}

function axisInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 8" width="100%" height="100%" preserveAspectRatio="none">
    <line x1="0" y1="4" x2="100" y2="4" stroke="#C5CAD3" stroke-width="2" stroke-dasharray="5 6" stroke-linecap="round"/>
  </svg>`
}

function agendaTimelineHexChromeSpecs() {
  const g = AGENDA_TL_HEX_GEOM
  const { hexY, hexH, badgeCy, cardY, cardH } = stackY()
  const w = colW()
  const specs = [
    {
      slotId: 'AGENDA_TLH_CAP',
      kind: 'shape',
      x: g.subX,
      y: g.subY,
      w: g.subW,
      h: g.subH,
      borderRadius: 20,
      fill: '#EEF1F4',
      layer: 3,
    },
    {
      slotId: 'AGENDA_TLH_AXIS',
      kind: 'graphic',
      axis: true,
      x: g.padX + w * 0.18,
      y: badgeCy - 4,
      w: g.viewW - g.padX * 2 - w * 0.36,
      h: 8,
      color: '#C5CAD3',
      layer: 4,
    },
  ]
  for (let i = 0; i < g.n; i += 1) {
    const pal = TL_HEX_PALETTE[i]
    const x = colX(i)
    specs.push({
      slotId: `AGENDA_TLH_${i + 1}_CARD`,
      kind: 'graphic',
      card: true,
      x: x + 4,
      y: cardY,
      w: w - 8,
      h: cardH,
      color: pal.main,
      layer: 5,
    })
    specs.push({
      slotId: `AGENDA_TLH_${i + 1}`,
      kind: 'graphic',
      n: i + 1,
      iconKey: pal.icon,
      x: x + (w - hexH) / 2,
      y: hexY,
      w: hexH,
      h: hexH,
      color: pal.main,
      layer: 6,
    })
  }
  return specs
}

function agendaTimelineHexOverlayPlacements(gx, gy, gw, gh) {
  const g = AGENDA_TL_HEX_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(20, Math.round(w * sx)),
    height: Math.max(14, Math.round(h * sy)),
  })
  const { cardY, cardH } = stackY()
  const w = colW()
  const items = []
  const itemBodies = []
  for (let i = 0; i < g.n; i += 1) {
    const x = colX(i)
    items.push(box(x, g.titleY, w, g.titleH))
    itemBodies.push(box(x + 14, cardY + 18, w - 28, cardH - 30))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subX + 10, g.subY, g.subW - 20, g.subH),
    items,
    itemBodies,
    columns: [],
    milestones: [],
  }
}

function specToTimelineHexContent(spec) {
  if (spec?.axis) return { svg: axisInlineSvg(), colorMode: 'fixed', fill: '#C5CAD3' }
  if (spec?.card) return { svg: cardInlineSvg(), colorMode: 'recolorable', fill: spec.color }
  return { svg: hexNodeInlineSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function agendaTimelineHexPreviewSvg() {
  const specs = agendaTimelineHexChromeSpecs()
  const { viewW, viewH } = AGENDA_TL_HEX_GEOM
  const cap = `<rect x="310" y="50" width="380" height="28" rx="14" fill="#EEF1F4"/>`
  const parts = specs.filter((s) => s.kind === 'graphic').map((spec) => {
    const inner = specToTimelineHexContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    const par = spec.card || spec.axis ? 'none' : 'xMidYMid meet'
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 100 100'}" preserveAspectRatio="${par}" color="${spec.color || '#C5CAD3'}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${cap}${parts.join('')}</svg>`
}

function isAgendaTimelineHexLayout(layoutId, family, variant) {
  if (family === 'timeline' && variant !== 'vertical' && variant !== 'curved' && variant !== 'path') return true
  return /agenda_timeline_preview_v1$/i.test(String(layoutId || ''))
}

function isAgendaTimelineHexTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  if (/^ITEM_\d+_TIME$/.test(sid)) return false
  return sid === 'HEADING' || sid === 'SUBHEADING' || /^ITEM_\d+$/.test(sid) || /^ITEM_\d+_BODY$/.test(sid)
}

module.exports = {
  AGENDA_TL_HEX_GEOM,
  TL_HEX_PALETTE,
  agendaTimelineHexGraphicFrame,
  agendaTimelineHexChromeSpecs,
  agendaTimelineHexOverlayPlacements,
  specToTimelineHexContent,
  agendaTimelineHexPreviewSvg,
  isAgendaTimelineHexLayout,
  isAgendaTimelineHexTextSlot,
}
