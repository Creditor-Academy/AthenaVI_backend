/**
 * Agenda 3 cards — tall shadowed cards, ring icon, gradient title bar, diamond bullets.
 */

const AGENDA_THREE_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 28,
  headingH: 52,
  padX: 6,
  gutter: 8,
  colTopY: 98,
  colBottomPad: 14,
  iconR: 34,
  barH: 48,
  radius: 8,
  inset: 10,
}

const AGENDA_THREE_CARDS_HERO_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 226,
  headingH: 40,
  padX: 22,
  gutter: 16,
  colTopY: 270,
  colBottomPad: 14,
  iconR: 24,
  barH: 36,
  radius: 8,
  inset: 8,
}

const THREE_CARDS_PALETTE = [
  { main: '#1E4B8C', light: '#3A6CB0', iconKey: 'searchPeople' },
  { main: '#6B7280', light: '#9CA3AF', iconKey: 'bulbTeam' },
  { main: '#2A9B8F', light: '#4DB8AC', iconKey: 'fourPeople' },
]

function resolveGeom(hero) {
  return hero ? AGENDA_THREE_CARDS_HERO_GEOM : AGENDA_THREE_CARDS_GEOM
}

function columnRects(geom) {
  const { viewW, viewH, padX, gutter, colTopY, colBottomPad } = geom
  const colW = (viewW - padX * 2 - gutter * 2) / 3
  const colH = viewH - colTopY - colBottomPad
  return [0, 1, 2].map((i) => {
    const x = padX + i * (colW + gutter)
    return { x, y: colTopY, w: colW, h: colH, cx: x + colW / 2 }
  })
}

function cardMetrics(w, geom) {
  const { iconR, barH, inset } = geom
  const hero = geom === AGENDA_THREE_CARDS_HERO_GEOM
  const iconCy = inset + (hero ? 12 : 18) + iconR
  const barY = iconCy + iconR + (hero ? 10 : 14)
  const barX = inset + (hero ? 12 : 18)
  const barW = w - inset * 2 - (hero ? 24 : 36)
  const itemH = hero ? 26 : 34
  const itemGap = hero ? 6 : 10
  const bodyY = barY + barH + (hero ? 12 : 22)
  const diamondX = barX + 10
  const textX = diamondX + (hero ? 14 : 16)
  const textW = w - textX - inset - (hero ? 14 : 18)
  return { inset, iconR, iconCy, barY, barH, barX, barW, bodyY, itemH, itemGap, diamondX, textX, textW }
}

function personMark(px, hy, s, color) {
  const head = s * 0.16
  return `<circle cx="${px}" cy="${hy}" r="${head}" fill="none" stroke="${color}" stroke-width="2.1"/>
    <path d="M ${px - s * 0.24} ${hy + s * 0.48} q ${s * 0.24} ${-s * 0.22} ${s * 0.48} 0" fill="none" stroke="${color}" stroke-width="2.1" stroke-linecap="round"/>`
}

function iconMarkup(key, cx, cy, r, color) {
  const s = r * 0.78
  if (key === 'bulbTeam') {
    return `<g fill="none" stroke="${color}" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round">
      <path d="M ${cx} ${cy - s * 0.62} q ${s * 0.36} ${s * 0.16} ${s * 0.36} ${s * 0.46} q 0 ${s * 0.2} ${-s * 0.16} ${s * 0.3} h ${-s * 0.4} q ${-s * 0.16} ${-s * 0.1} ${-s * 0.16} ${-s * 0.3} q 0 ${-s * 0.3} ${s * 0.36} ${-s * 0.46}"/>
      <path d="M ${cx - s * 0.1} ${cy + s * 0.2} h ${s * 0.2}"/>
    </g>
    ${personMark(cx - s * 0.4, cy + s * 0.52, s * 0.72, color)}
    ${personMark(cx, cy + s * 0.52, s * 0.72, color)}
    ${personMark(cx + s * 0.4, cy + s * 0.52, s * 0.72, color)}`
  }
  if (key === 'fourPeople') {
    return [-0.48, -0.16, 0.16, 0.48].map((t) => personMark(cx + t * s * 1.2, cy - s * 0.08, s * 0.85, color)).join('')
  }
  return `${personMark(cx - s * 0.32, cy - s * 0.18, s * 0.85, color)}
    ${personMark(cx - s * 0.02, cy - s * 0.18, s * 0.85, color)}
    <circle cx="${cx + s * 0.32}" cy="${cy + s * 0.08}" r="${s * 0.22}" fill="none" stroke="${color}" stroke-width="2.1"/>
    <path d="M ${cx + s * 0.48} ${cy + s * 0.24} l ${s * 0.16} ${s * 0.16}" fill="none" stroke="${color}" stroke-width="2.1" stroke-linecap="round"/>`
}

function agendaThreeCardsGraphicFrame(canvasW, canvasH, extra = {}) {
  if (extra.hero) {
    return {
      graphicX: 0,
      graphicY: 0,
      graphicW: canvasW,
      graphicH: canvasH,
      headingY: Math.round(canvasH * 0.4),
      headingH: Math.round(canvasH * 0.068),
      heroH: Math.round(canvasH * 0.36),
    }
  }
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.062),
    headingH: Math.round(canvasH * 0.08),
  }
}

function escapeXml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function agendaThreeCardsCardInlineSvg(spec) {
  const w = spec.w
  const h = spec.h
  const color = spec.color
  const light = spec.light || color
  const m = cardMetrics(w, spec.hero ? AGENDA_THREE_CARDS_HERO_GEOM : AGENDA_THREE_CARDS_GEOM)
  const cx = w / 2
  const barCx = m.barX + m.barW / 2
  const uid = String(spec.slotId || 'c').replace(/[^a-z0-9]/gi, '')
  const label = escapeXml(spec.label || '')
  const labelSize = Math.round(m.barH * 0.42)
  const diamonds = [0, 1, 2].map((i) => {
    const y = m.bodyY + m.itemH / 2 + i * (m.itemH + m.itemGap)
    return `<rect x="${m.diamondX - 3.5}" y="${y - 3.5}" width="7" height="7" fill="${color}" transform="rotate(45 ${m.diamondX} ${y})"/>`
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="sh-${uid}" x="-18%" y="-8%" width="136%" height="124%">
        <feDropShadow dx="0" dy="8" stdDeviation="8" flood-color="#1f2937" flood-opacity="0.18"/>
      </filter>
      <linearGradient id="bar-${uid}" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="${light}"/>
        <stop offset="100%" stop-color="${color}"/>
      </linearGradient>
    </defs>
    <rect x="${m.inset}" y="${m.inset}" width="${w - m.inset * 2}" height="${h - m.inset * 2}" rx="${spec.radius}" fill="#ffffff" filter="url(#sh-${uid})"/>
    <rect x="${m.barX}" y="${m.barY}" width="${m.barW}" height="${m.barH}" fill="url(#bar-${uid})"/>
    <text x="${barCx}" y="${m.barY + m.barH * 0.68}" text-anchor="middle" fill="#ffffff" stroke="none" font-size="${labelSize}" font-weight="800" font-family="Arial,Helvetica,sans-serif">${label}</text>
    <circle cx="${cx}" cy="${m.iconCy}" r="${m.iconR}" fill="#ffffff"/>
    <circle cx="${cx}" cy="${m.iconCy}" r="${m.iconR - 1.4}" fill="none" stroke="${color}" stroke-width="2.2"/>
    <circle cx="${cx}" cy="${m.iconCy}" r="${m.iconR - 8}" fill="none" stroke="${color}" stroke-width="1.8"/>
    ${iconMarkup(spec.iconKey, cx, m.iconCy, m.iconR, color)}
    ${diamonds}
  </svg>`
}

function agendaThreeCardsChromeSpecs(extra = {}) {
  const geom = resolveGeom(extra.hero)
  const { iconR, barH, radius } = geom
  const labels = extra.labels || ['Morning', 'Afternoon', 'Evening']
  return columnRects(geom).map((col, i) => {
    const pal = THREE_CARDS_PALETTE[i]
    return {
      slotId: `AGENDA_COL_CHROME_${i + 1}`,
      kind: 'graphic',
      cardChrome: true,
      x: col.x,
      y: col.y,
      w: col.w,
      h: col.h,
      color: pal.main,
      light: pal.light,
      iconKey: pal.iconKey,
      iconR,
      barH,
      radius,
      label: labels[i] || '',
      hero: Boolean(extra.hero),
      layer: 4,
    }
  })
}

function agendaThreeCardsOverlayPlacements(gx, gy, gw, gh, extra = {}) {
  const geom = resolveGeom(extra.hero)
  const { viewW, viewH, headingY, headingH } = geom
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
  for (const col of columnRects(geom)) {
    const m = cardMetrics(col.w, geom)
    overlay.columns.push({
      heading: box(col.x + m.barX, col.y + m.barY, m.barW, m.barH),
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

function buildPreviewSvg() {
  const specs = agendaThreeCardsChromeSpecs()
  const { viewW, viewH } = AGENDA_THREE_CARDS_GEOM
  const parts = specs.map((spec) => {
    const inner = agendaThreeCardsCardInlineSvg(spec)
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}">${parts.join('')}</svg>`
}

function agendaThreeCardsPreviewSvg() {
  return buildPreviewSvg().replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"'
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"'
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"'
    return `<svg${next}>`
  })
}

function specToThreeCardsContent(spec) {
  return { svg: agendaThreeCardsCardInlineSvg(spec), colorMode: 'original', fill: spec.color }
}

function isAgendaThreeCardsLayout(layoutId, family, variant) {
  if (family === 'three_col' && variant === 'cards') return true
  return /agenda_three_cards_v1$/i.test(String(layoutId || ''))
}

function isAgendaThreeCardsHeroLayout(layoutId, family, variant) {
  if (family === 'hero' && variant === 'cards') return true
  return /agenda_three_cards_hero/i.test(String(layoutId || ''))
}

module.exports = { AGENDA_THREE_CARDS_GEOM, AGENDA_THREE_CARDS_HERO_GEOM, THREE_CARDS_PALETTE, agendaThreeCardsGraphicFrame, agendaThreeCardsCardInlineSvg, agendaThreeCardsChromeSpecs, agendaThreeCardsOverlayPlacements, agendaThreeCardsPreviewSvg, specToThreeCardsContent, isAgendaThreeCardsLayout, isAgendaThreeCardsHeroLayout };
