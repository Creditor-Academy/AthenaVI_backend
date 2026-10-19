/**
 * Agenda cards — 2x2 index tiles with accent cap, badge, watermark number.
 */

const AGENDA_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,
  n: 4,
  headingX: 48,
  headingY: 18,
  headingW: 904,
  headingH: 48,
  padX: 48,
  gridY: 82,
  gapX: 22,
  gapY: 20,
  cols: 2,
  rows: 2,
}

const AGENDA_CARDS_PALETTE = ['#2F6FED', '#E85D4C', '#2A9D8F', '#E09F3E']

function cardRects() {
  const g = AGENDA_CARDS_GEOM
  const cardW = (g.viewW - g.padX * 2 - g.gapX) / 2
  const cardH = (g.viewH - g.gridY - 36 - g.gapY) / 2
  return Array.from({ length: g.n }, (_, i) => {
    const col = i % g.cols
    const row = Math.floor(i / g.cols)
    return {
      x: g.padX + col * (cardW + g.gapX),
      y: g.gridY + row * (cardH + g.gapY),
      w: cardW,
      h: cardH,
      i,
    }
  })
}

function agendaCardsGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.03),
    headingH: Math.round(canvasH * 0.09),
  }
}

function cardInlineSvg(n) {
  const label = String(n).padStart(2, '0')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 442 206" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="4" y="8" width="438" height="198" rx="20" fill="#000000" fill-opacity="0.07"/>
    <rect x="0" y="0" width="442" height="206" rx="20" fill="#ffffff"/>
    <path d="M0 20 A20 20 0 0 1 20 0 H422 A20 20 0 0 1 442 20 V12 H0 Z" fill="currentColor"/>
    <circle cx="40" cy="52" r="22" fill="currentColor"/>
    <text x="40" y="59" text-anchor="middle" fill="#ffffff" stroke="none" font-size="16" font-weight="800" font-family="Arial,Helvetica,sans-serif">${label}</text>
    <text x="418" y="188" text-anchor="end" fill="currentColor" fill-opacity="0.12" stroke="none" font-size="72" font-weight="800" font-family="Arial,Helvetica,sans-serif">${label}</text>
  </svg>`
}

function agendaCardsChromeSpecs() {
  return cardRects().map((rect, i) => ({
    slotId: `AGENDA_CRD_${i + 1}`,
    kind: 'graphic',
    cards: 'tile',
    n: i + 1,
    x: rect.x,
    y: rect.y,
    w: rect.w,
    h: rect.h,
    color: AGENDA_CARDS_PALETTE[i],
    layer: 4,
  }))
}

function agendaCardsOverlayPlacements(gx, gy, gw, gh) {
  const g = AGENDA_CARDS_GEOM
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
    itemBodies: [],
  }
  for (const rect of cardRects()) {
    overlay.items.push(box(rect.x + 74, rect.y + 28, rect.w - 108, 40))
    overlay.itemBodies.push(box(rect.x + 28, rect.y + 84, rect.w - 56, rect.h - 118))
  }
  return overlay
}

function specToAgendaCardsContent(spec) {
  return { svg: cardInlineSvg(spec?.n || 1), colorMode: 'recolorable', fill: spec.color }
}

function agendaCardsPreviewSvg() {
  const specs = agendaCardsChromeSpecs()
  const { viewW, viewH } = AGENDA_CARDS_GEOM
  const parts = specs.map((spec) => {
    const inner = specToAgendaCardsContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})" color="${spec.color}">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function isAgendaCardsLayout(layoutId, family, variant) {
  if (family === 'minimal' && variant === 'cards') return true
  return /agenda_cards_v1$/i.test(String(layoutId || ''))
}

function isAgendaCardsTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || /^ITEM_\d+$/.test(sid) || /^ITEM_\d+_BODY$/.test(sid)
}

module.exports = {
  AGENDA_CARDS_GEOM,
  AGENDA_CARDS_PALETTE,
  agendaCardsGraphicFrame,
  agendaCardsChromeSpecs,
  agendaCardsOverlayPlacements,
  specToAgendaCardsContent,
  agendaCardsPreviewSvg,
  isAgendaCardsLayout,
  isAgendaCardsTextSlot,
}
