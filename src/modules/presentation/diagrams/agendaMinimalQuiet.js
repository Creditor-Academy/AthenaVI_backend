/**
 * Agenda minimal (default) — left index: accent bar, title, numbered pills, list.
 */

const AGENDA_MINIMAL_QUIET_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 88,
  headingY: 52,
  headingW: 820,
  headingH: 64,
  ruleX: 88,
  ruleY: 128,
  ruleW: 72,
  ruleH: 5,
  barW: 12,
  listTop: 168,
  rowH: 82,
  mark: 48,
  n: 4,
}

function agendaMinimalQuietGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.09),
    headingH: Math.round(canvasH * 0.11),
  }
}

function markInlineSvg(n) {
  const label = String(n).padStart(2, '0')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="48" height="48" rx="10" fill="currentColor"/>
    <text x="24" y="31" text-anchor="middle" fill="#ffffff" stroke="none" font-size="16" font-weight="800" font-family="Arial,Helvetica,sans-serif">${label}</text>
  </svg>`
}

function barInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 12 560" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="12" height="560" fill="currentColor"/>
  </svg>`
}

function ruleInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 72 5" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="72" height="5" rx="2" fill="currentColor"/>
  </svg>`
}

function agendaMinimalQuietChromeSpecs() {
  const g = AGENDA_MINIMAL_QUIET_GEOM
  const specs = [
    {
      slotId: 'AGENDA_MIN_BAR',
      kind: 'graphic',
      quiet: 'bar',
      x: 0,
      y: 0,
      w: g.barW,
      h: g.viewH,
      color: '#1E4B8C',
      layer: 3,
    },
    {
      slotId: 'AGENDA_MIN_RULE',
      kind: 'graphic',
      quiet: 'rule',
      x: g.ruleX,
      y: g.ruleY,
      w: g.ruleW,
      h: g.ruleH,
      color: '#1E4B8C',
      layer: 4,
    },
  ]
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `AGENDA_MIN_MARK_${i + 1}`,
      kind: 'graphic',
      quiet: 'mark',
      n: i + 1,
      x: g.headingX,
      y: g.listTop + i * g.rowH + (g.rowH - g.mark) / 2,
      w: g.mark,
      h: g.mark,
      color: '#1E4B8C',
      layer: 4,
    })
  }
  return specs
}

function agendaMinimalQuietOverlayPlacements(gx, gy, gw, gh) {
  const g = AGENDA_MINIMAL_QUIET_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(24, Math.round(w * sx)),
    height: Math.max(20, Math.round(h * sy)),
  })
  const overlay = {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    items: [],
  }
  const textX = g.headingX + g.mark + 22
  const textW = g.viewW - textX - 72
  for (let i = 0; i < g.n; i += 1) {
    const markY = g.listTop + i * g.rowH + (g.rowH - g.mark) / 2
    overlay.items.push(box(textX, markY, textW, g.mark))
  }
  return overlay
}

function specToMinimalQuietContent(spec) {
  if (spec?.quiet === 'bar') return { svg: barInlineSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec?.quiet === 'rule') return { svg: ruleInlineSvg(), colorMode: 'recolorable', fill: spec.color }
  return { svg: markInlineSvg(spec?.n || 1), colorMode: 'recolorable', fill: spec.color }
}

function agendaMinimalQuietPreviewSvg() {
  const specs = agendaMinimalQuietChromeSpecs()
  const { viewW, viewH } = AGENDA_MINIMAL_QUIET_GEOM
  const parts = specs.map((spec) => {
    const inner = specToMinimalQuietContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})" color="${spec.color}">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function isAgendaMinimalQuietLayout(layoutId, family, variant) {
  if (family === 'minimal' && variant !== 'editorial' && variant !== 'icon_list' && variant !== 'cards') return true
  return /agenda_minimal_v1$/i.test(String(layoutId || ''))
}

function isAgendaMinimalQuietTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || /^ITEM_\d+$/.test(sid)
}

module.exports = {
  AGENDA_MINIMAL_QUIET_GEOM,
  agendaMinimalQuietGraphicFrame,
  agendaMinimalQuietChromeSpecs,
  agendaMinimalQuietOverlayPlacements,
  specToMinimalQuietContent,
  agendaMinimalQuietPreviewSvg,
  isAgendaMinimalQuietLayout,
  isAgendaMinimalQuietTextSlot,
}
