/**
 * Agenda 3-columns hero — keep the top image, put three shadowed cards below.
 */

const AGENDA_HERO_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 228,
  headingH: 42,
  padX: 28,
  gutter: 20,
  colTopY: 276,
  colBottomPad: 16,
  iconR: 28,
  radius: 12,
  inset: 8,
}

const HERO_CARD_PALETTE = [
  { main: '#1E4B8C', iconKey: 'calendar' },
  { main: '#6B7280', iconKey: 'chart' },
  { main: '#2A9B8F', iconKey: 'user' },
]

function columnRects() {
  const { viewW, viewH, padX, gutter, colTopY, colBottomPad } = AGENDA_HERO_CARDS_GEOM
  const colW = (viewW - padX * 2 - gutter * 2) / 3
  const colH = viewH - colTopY - colBottomPad
  return [0, 1, 2].map((i) => {
    const x = padX + i * (colW + gutter)
    return { x, y: colTopY, w: colW, h: colH }
  })
}

function cardMetrics(w) {
  const { iconR, inset } = AGENDA_HERO_CARDS_GEOM
  const iconCy = inset + 16 + iconR
  const headingY = iconCy + iconR + 12
  const headingH = 34
  const itemH = 30
  const itemGap = 6
  const bodyY = headingY + headingH + 8
  const textX = inset + 16
  const textW = w - textX * 2
  return { inset, iconR, iconCy, headingY, headingH, bodyY, itemH, itemGap, textX, textW }
}

function iconPath(key, cx, cy, r) {
  const s = r * 0.55
  if (key === 'chart') {
    return `M ${cx - s} ${cy + s} V ${cy - s * 0.1} M ${cx} ${cy + s} V ${cy - s} M ${cx + s} ${cy + s} V ${cy + s * 0.15}`
  }
  if (key === 'user') {
    return `M ${cx} ${cy - s * 0.45} a ${s * 0.32} ${s * 0.32} 0 1 1 0.01 0 M ${cx - s * 0.55} ${cy + s * 0.7} q ${s * 0.55} ${-s * 0.4} ${s * 1.1} 0`
  }
  return `M ${cx - s} ${cy - s * 0.25} h ${s * 2} v ${s * 1.35} h ${-s * 2} z M ${cx - s * 0.45} ${cy - s * 0.55} v ${s * 0.4} M ${cx + s * 0.45} ${cy - s * 0.55} v ${s * 0.4}`
}

function agendaHeroCardsGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.4),
    headingH: Math.round(canvasH * 0.07),
    heroH: Math.round(canvasH * 0.36),
  }
}

function agendaHeroCardsCardInlineSvg(spec) {
  const w = spec.w
  const h = spec.h
  const color = spec.color
  const m = cardMetrics(w)
  const cx = w / 2
  const uid = String(spec.slotId || 'c').replace(/[^a-z0-9]/gi, '')
  const d = spec.iconKey === 'user' ? '' : iconPath(spec.iconKey, cx, m.iconCy, m.iconR)
  const userIcon = spec.iconKey === 'user'
    ? `<circle cx="${cx}" cy="${m.iconCy - 6}" r="7" fill="none" stroke="${color}" stroke-width="2.1"/>
       <path d="M ${cx - 14} ${m.iconCy + 16} q 14 -10 28 0" fill="none" stroke="${color}" stroke-width="2.1" stroke-linecap="round"/>`
    : `<path d="${d}" fill="none" stroke="${color}" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/>`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="hsh-${uid}" x="-16%" y="-8%" width="132%" height="124%">
        <feDropShadow dx="0" dy="7" stdDeviation="7" flood-color="#1f2937" flood-opacity="0.14"/>
      </filter>
    </defs>
    <rect x="${m.inset}" y="${m.inset}" width="${w - m.inset * 2}" height="${h - m.inset * 2}" rx="${spec.radius}" fill="#ffffff" filter="url(#hsh-${uid})"/>
    <circle cx="${cx}" cy="${m.iconCy}" r="${m.iconR}" fill="#ffffff"/>
    <circle cx="${cx}" cy="${m.iconCy}" r="${m.iconR - 1}" fill="none" stroke="${color}" stroke-width="2.2"/>
    ${userIcon}
  </svg>`
}

function agendaHeroCardsChromeSpecs() {
  const { iconR, radius } = AGENDA_HERO_CARDS_GEOM
  return columnRects().map((col, i) => {
    const pal = HERO_CARD_PALETTE[i]
    return {
      slotId: `AGENDA_COL_CHROME_${i + 1}`,
      kind: 'graphic',
      cardChrome: true,
      x: col.x,
      y: col.y,
      w: col.w,
      h: col.h,
      color: pal.main,
      iconKey: pal.iconKey,
      iconR,
      radius,
      layer: 4,
    }
  })
}

function agendaHeroCardsOverlayPlacements(gx, gy, gw, gh) {
  const { viewW, viewH, headingY, headingH } = AGENDA_HERO_CARDS_GEOM
  const sx = gw / viewW
  const sy = gh / viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(28, Math.round(w * sx)),
    height: Math.max(20, Math.round(h * sy)),
  })
  const overlay = {
    heading: box(80, headingY, viewW - 160, headingH),
    columns: [],
  }
  for (const col of columnRects()) {
    const m = cardMetrics(col.w)
    overlay.columns.push({
      heading: box(col.x + m.textX, col.y + m.headingY, m.textW, m.headingH),
      items: [0, 1, 2].map((i) => box(
        col.x + m.textX,
        col.y + m.bodyY + i * (m.itemH + m.itemGap),
        m.textW,
        m.itemH,
      )).concat([box(-940, -900, 8, 8)]),
    })
  }
  return overlay
}

function specToHeroCardsContent(spec) {
  return { svg: agendaHeroCardsCardInlineSvg(spec), colorMode: 'original', fill: spec.color }
}

function isAgendaHeroCardsLayout(layoutId, family, variant) {
  if (family === 'hero' && variant !== 'panels' && variant !== 'cards') return true
  return /agenda_three_columns_hero_v1/i.test(String(layoutId || ''))
}

module.exports = { AGENDA_HERO_CARDS_GEOM, HERO_CARD_PALETTE, agendaHeroCardsGraphicFrame, agendaHeroCardsCardInlineSvg, agendaHeroCardsChromeSpecs, agendaHeroCardsOverlayPlacements, specToHeroCardsContent, isAgendaHeroCardsLayout };
