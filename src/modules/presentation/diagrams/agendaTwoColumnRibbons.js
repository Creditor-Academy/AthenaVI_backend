/**
 * Agenda two-column (default) — folded ribbon headers, numbered list cards.
 */

const AGENDA_TWO_COL_RIBBON_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 40,
  headingY: 12,
  headingW: 920,
  headingH: 40,
  colY: 62,
  colH: 478,
  colW: 442,
  gap: 36,
  padX: 40,
  ribbonH: 56,
  rows: 5,
}

const TWO_COL_RIBBON_PALETTE = ['#1AA6A6', '#7CB342']

function colX(i) {
  const g = AGENDA_TWO_COL_RIBBON_GEOM
  return g.padX + i * (g.colW + g.gap)
}

function rowBand() {
  const g = AGENDA_TWO_COL_RIBBON_GEOM
  return (g.colH - g.ribbonH - 14) / g.rows
}

function agendaTwoColumnRibbonGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.02),
    headingH: Math.round(canvasH * 0.075),
  }
}

function iconPeople() {
  return `<g fill="none" stroke="#ffffff" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
    <circle cx="19" cy="13" r="4.2"/>
    <circle cx="9" cy="16" r="3.1"/>
    <circle cx="29" cy="16" r="3.1"/>
    <path d="M11 30c0-5.2 3.2-8 8-8s8 2.8 8 8"/>
    <path d="M5 30c.4-3.6 2.4-5.6 5.6-6.2"/>
    <path d="M33 30c-.4-3.6-2.4-5.6-5.6-6.2"/>
  </g>`
}

function iconCoin() {
  return `<g fill="none" stroke="#ffffff" stroke-width="1.7" stroke-linecap="round">
    <circle cx="19" cy="18" r="9"/>
    <path d="M19 12v12"/>
    <path d="M15.5 15.2c.8-1.2 2-1.8 3.5-1.8 2.2 0 3.6 1.2 3.6 2.8 0 3.6-7.2 1.8-7.2 5.2 0 1.6 1.5 2.8 3.8 2.8 1.6 0 2.8-.6 3.6-1.7"/>
  </g>`
}

function columnInlineSvg(colIndex) {
  const g = AGENDA_TWO_COL_RIBBON_GEOM
  const band = rowBand()
  const rh = g.ribbonH
  const parts = [
    `<rect x="0" y="${rh}" width="442" height="${g.colH - rh}" fill="#ffffff" stroke="#e5e7eb" stroke-width="1.4"/>`,
    `<rect x="0" y="0" width="442" height="${rh}" fill="currentColor"/>`,
    `<path d="M0 ${rh} L16 ${rh + 14} L16 ${rh} Z" fill="#000000" fill-opacity="0.22"/>`,
    `<rect x="10" y="8" width="40" height="40" rx="7" fill="#000000" fill-opacity="0.22"/>`,
    `<g transform="translate(11,8)">${colIndex === 0 ? iconPeople() : iconCoin()}</g>`,
    `<rect x="0" y="${g.colH - 12}" width="442" height="12" fill="currentColor"/>`,
  ]
  for (let i = 0; i < g.rows; i += 1) {
    const y = rh + i * band
    const label = String(i + 1).padStart(2, '0')
    parts.push(`<text x="28" y="${y + 28}" fill="#111827" stroke="none" font-size="15" font-weight="800" font-family="Arial,Helvetica,sans-serif">${label}</text>`)
    if (i < g.rows - 1) {
      parts.push(`<line x1="22" y1="${y + band}" x2="420" y2="${y + band}" stroke="#d1d5db" stroke-width="1.2" stroke-dasharray="5 5"/>`)
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 442 ${g.colH}" width="100%" height="100%" preserveAspectRatio="none">${parts.join('')}</svg>`
}

function agendaTwoColumnRibbonChromeSpecs() {
  const g = AGENDA_TWO_COL_RIBBON_GEOM
  return [0, 1].map((i) => ({
    slotId: `AGENDA_TC_COL_${i + 1}`,
    kind: 'graphic',
    twoCol: 'column',
    n: i,
    x: colX(i),
    y: g.colY,
    w: g.colW,
    h: g.colH,
    color: TWO_COL_RIBBON_PALETTE[i],
    layer: 4,
  }))
}

function agendaTwoColumnRibbonOverlayPlacements(gx, gy, gw, gh) {
  const g = AGENDA_TWO_COL_RIBBON_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(24, Math.round(w * sx)),
    height: Math.max(16, Math.round(h * sy)),
  })
  const overlay = {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    columns: [],
  }
  const band = rowBand()
  for (let c = 0; c < 2; c += 1) {
    const x = colX(c)
    const items = []
    const itemBodies = []
    for (let i = 0; i < g.rows; i += 1) {
      const y = g.colY + g.ribbonH + i * band
      items.push(box(x + 62, y + 8, g.colW - 88, 22))
      itemBodies.push(box(x + 62, y + 30, g.colW - 88, 40))
    }
    overlay.columns.push({
      heading: box(x + 62, g.colY + 8, g.colW - 84, 40),
      items,
      itemBodies,
    })
  }
  return overlay
}

function specToTwoColumnRibbonContent(spec) {
  return { svg: columnInlineSvg(spec?.n || 0), colorMode: 'recolorable', fill: spec.color }
}

function agendaTwoColumnRibbonPreviewSvg() {
  const specs = agendaTwoColumnRibbonChromeSpecs()
  const { viewW, viewH } = AGENDA_TWO_COL_RIBBON_GEOM
  const parts = specs.map((spec) => {
    const inner = specToTwoColumnRibbonContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})" color="${spec.color}">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function isAgendaTwoColumnRibbonLayout(layoutId, family, variant) {
  if (family === 'two_col' && variant !== 'split_visual' && variant !== 'split_panel' && variant !== 'asymmetric') return true
  return /agenda_two_column_v1$/i.test(String(layoutId || ''))
}

function isAgendaTwoColumnRibbonTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || /^AGENDA_COL_\d+_HEADING$/.test(sid) || /^AGENDA_COL_\d+_ITEM_\d+$/.test(sid) || /^AGENDA_COL_\d+_ITEM_\d+_BODY$/.test(sid)
}

module.exports = {
  AGENDA_TWO_COL_RIBBON_GEOM,
  TWO_COL_RIBBON_PALETTE,
  agendaTwoColumnRibbonGraphicFrame,
  agendaTwoColumnRibbonChromeSpecs,
  agendaTwoColumnRibbonOverlayPlacements,
  specToTwoColumnRibbonContent,
  agendaTwoColumnRibbonPreviewSvg,
  isAgendaTwoColumnRibbonLayout,
  isAgendaTwoColumnRibbonTextSlot,
}
