/**
 * Agenda editorial — hub circle, dashed arc, five numbered arrow banners.
 */

const AGENDA_EDITORIAL_GEOM = {
  viewW: 1000,
  viewH: 560,
  n: 5,
  hubCx: 198,
  hubR: 152,
  rowH: 62,
  gap: 18,
  rowX: 478,
  rowW: 492,
}

const EDITORIAL_ROW_PALETTE = ['#2F6FED', '#E57373', '#9CCC65', '#26A69A', '#42A5F5']

function rowMetrics() {
  const g = AGENDA_EDITORIAL_GEOM
  const headingReserve = 56
  const total = g.n * g.rowH + (g.n - 1) * g.gap
  const available = g.viewH - headingReserve
  const top = headingReserve + Math.max(8, (available - total) / 2)
  return { top, total, hubCy: top + total / 2 }
}

function rowTop(i) {
  const { top } = rowMetrics()
  const g = AGENDA_EDITORIAL_GEOM
  return top + i * (g.rowH + g.gap)
}

function arcRadius() {
  return AGENDA_EDITORIAL_GEOM.hubR + 16
}

function nodePos(i) {
  const { hubCx } = AGENDA_EDITORIAL_GEOM
  const { hubCy } = rowMetrics()
  const n = AGENDA_EDITORIAL_GEOM.n
  const r = arcRadius()
  const a0 = -0.92
  const a1 = 0.92
  const ang = n <= 1 ? 0 : a0 + (i / (n - 1)) * (a1 - a0)
  return {
    x: hubCx + r * Math.cos(ang),
    y: hubCy + r * Math.sin(ang),
  }
}

function agendaEditorialGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.38),
    headingH: Math.round(canvasH * 0.2),
  }
}

function hubInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 304 304" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <radialGradient id="edHubShade" cx="50%" cy="42%" r="62%">
        <stop offset="0%" stop-color="#ffffff"/>
        <stop offset="70%" stop-color="#ffffff"/>
        <stop offset="100%" stop-color="#eef1f5"/>
      </radialGradient>
    </defs>
    <circle cx="152" cy="156" r="146" fill="#000000" fill-opacity="0.06"/>
    <circle cx="152" cy="152" r="146" fill="url(#edHubShade)" stroke="currentColor" stroke-width="3"/>
    <circle cx="152" cy="152" r="138" fill="none" stroke="#d8dee8" stroke-width="7"/>
    <circle cx="152" cy="152" r="128" fill="none" stroke="#000000" stroke-opacity="0.06" stroke-width="10"/>
    <text x="152" y="162" text-anchor="middle" fill="#4B5563" stroke="none" font-size="28" font-weight="800" font-family="Arial,Helvetica,sans-serif">Agenda</text>
  </svg>`
}

function arcInlineSvg() {
  const g = AGENDA_EDITORIAL_GEOM
  const r = arcRadius()
  const start = nodePos(0)
  const end = nodePos(g.n - 1)
  const parts = [
    `<path d="M ${start.x.toFixed(1)} ${start.y.toFixed(1)} A ${r} ${r} 0 0 1 ${end.x.toFixed(1)} ${end.y.toFixed(1)}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-dasharray="4 6" stroke-linecap="round"/>`,
  ]
  for (let i = 0; i < g.n; i += 1) {
    const p = nodePos(i)
    const cy = rowTop(i) + g.rowH / 2
    const tipX = g.rowX + 8
    parts.push(`<path d="M ${p.x.toFixed(1)} ${p.y.toFixed(1)} L ${tipX.toFixed(1)} ${cy.toFixed(1)}" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>`)
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="none">${parts.join('')}</svg>`
}

function nodeInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18" width="100%" height="100%" preserveAspectRatio="none">
    <circle cx="9" cy="9" r="7.5" fill="currentColor"/>
    <circle cx="9" cy="9" r="7.5" fill="none" stroke="#ffffff" stroke-width="1.4"/>
  </svg>`
}

function rowInlineSvg(n) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 492 62" width="100%" height="100%" preserveAspectRatio="none">
    <path d="M40 8 H448 L484 35 L448 62 H40 Z" transform="translate(2 3)" fill="#000000" fill-opacity="0.12"/>
    <path d="M40 5 H448 L484 31 L448 57 H40 Z" fill="currentColor"/>
    <path d="M31 5 L61 31 L31 57 L1 31 Z" fill="currentColor"/>
    <path d="M1 31 L31 57 L31 31 Z" fill="#000000" fill-opacity="0.28"/>
    <text x="31" y="37" text-anchor="middle" fill="#ffffff" stroke="none" font-size="18" font-weight="800" font-family="Arial,Helvetica,sans-serif">${n}</text>
  </svg>`
}

function agendaEditorialChromeSpecs() {
  const g = AGENDA_EDITORIAL_GEOM
  const { hubCy } = rowMetrics()
  const hubS = g.hubR * 2
  const specs = [
    {
      slotId: 'AGENDA_ED_HUB',
      kind: 'graphic',
      editorial: 'hub',
      x: g.hubCx - g.hubR,
      y: hubCy - g.hubR,
      w: hubS,
      h: hubS,
      color: '#C5CAD3',
      layer: 3,
    },
    {
      slotId: 'AGENDA_ED_ARC',
      kind: 'graphic',
      editorial: 'arc',
      x: 0,
      y: 0,
      w: g.viewW,
      h: g.viewH,
      color: '#C5CAD3',
      layer: 4,
    },
  ]
  const nodeR = 9
  for (let i = 0; i < g.n; i += 1) {
    const color = EDITORIAL_ROW_PALETTE[i]
    const p = nodePos(i)
    specs.push({
      slotId: `AGENDA_ED_NODE_${i + 1}`,
      kind: 'graphic',
      editorial: 'node',
      x: p.x - nodeR,
      y: p.y - nodeR,
      w: nodeR * 2,
      h: nodeR * 2,
      color,
      layer: 6,
    })
    specs.push({
      slotId: `AGENDA_ED_ROW_${i + 1}`,
      kind: 'graphic',
      editorial: 'row',
      n: i + 1,
      x: g.rowX,
      y: rowTop(i),
      w: g.rowW,
      h: g.rowH,
      color,
      layer: 5,
    })
  }
  return specs
}

function agendaEditorialOverlayPlacements(gx, gy, gw, gh) {
  const g = AGENDA_EDITORIAL_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(24, Math.round(w * sx)),
    height: Math.max(20, Math.round(h * sy)),
  })
  const overlay = {
    heading: box(48, 14, 900, 42),
    items: [],
  }
  const textX = g.rowX + 70
  const textW = 360
  const textH = 28
  for (let i = 0; i < g.n; i += 1) {
    const y = rowTop(i) + (g.rowH - textH) / 2
    overlay.items.push(box(textX, y, textW, textH))
  }
  return overlay
}

function specToEditorialContent(spec) {
  if (spec?.editorial === 'hub') return { svg: hubInlineSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec?.editorial === 'arc') return { svg: arcInlineSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec?.editorial === 'node') return { svg: nodeInlineSvg(), colorMode: 'recolorable', fill: spec.color }
  return { svg: rowInlineSvg(spec?.n || 1), colorMode: 'recolorable', fill: spec.color }
}

function agendaEditorialPreviewSvg() {
  const specs = agendaEditorialChromeSpecs()
  const { viewW, viewH } = AGENDA_EDITORIAL_GEOM
  const parts = specs.map((spec) => {
    const inner = specToEditorialContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})" color="${spec.color}">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function isAgendaEditorialLayout(layoutId, family, variant) {
  if (family === 'minimal' && variant === 'editorial') return true
  return /agenda_editorial_v1$/i.test(String(layoutId || ''))
}

function isAgendaEditorialTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || /^ITEM_\d+$/.test(sid)
}

module.exports = {
  AGENDA_EDITORIAL_GEOM,
  EDITORIAL_ROW_PALETTE,
  agendaEditorialGraphicFrame,
  agendaEditorialChromeSpecs,
  agendaEditorialOverlayPlacements,
  specToEditorialContent,
  agendaEditorialPreviewSvg,
  isAgendaEditorialLayout,
  isAgendaEditorialTextSlot,
}
