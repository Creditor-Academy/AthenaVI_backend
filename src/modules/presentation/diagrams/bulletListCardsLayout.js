/**
 * Bullet List Cards
 * Layout ID: bullet_list_cards_v1
 *
 * Four equal point cards under a heading. Twin `bullet_list_grid_v1`
 * has its own staggered-column engine.
 */

function isBulletListCardsLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  if (id.includes('_grid')) return false
  return id === 'bullet_list_cards_v1' || id === 'bullet_list_cards'
}

const BULLET_LIST_CARDS_DEFAULTS = {
  HEADING: 'Key points',
  CARD_1_TITLE: 'Point one',
  CARD_2_TITLE: 'Point two',
  CARD_3_TITLE: 'Point three',
  CARD_4_TITLE: 'Point four',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headX: 80,
  headY: 48,
  headW: 1760,
  headH: 100,
  cardY: 176,
  cardW: 419,
  cardH: 820,
  cardGap: 28,
  cardXs: [80, 527, 974, 1421],
  barH: 8,
  titlePad: 36,
  titleY: 268,
  titleH: 96,
  bodyY: 384,
  bodyH: 560,
}

function cardChrome(x, y, w, h, barH, n) {
  const rx = 24
  const cx = x + w / 2
  return `
    <rect x="${x + 10}" y="${y + 14}" width="${w}" height="${h}" rx="${rx}" fill="currentColor" opacity="0.08" />
    <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${rx}" fill="#FFFFFF" />
    <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="${rx}" fill="none" stroke="currentColor" stroke-width="2" opacity="0.14" />
    <path d="M ${x} ${y + barH} L ${x + w} ${y + barH} L ${x + w} ${y + rx} Q ${x + w} ${y} ${x + w - rx} ${y} L ${x + rx} ${y} Q ${x} ${y} ${x} ${y + rx} Z" fill="currentColor" />
    <circle cx="${cx}" cy="${y + 56}" r="22" fill="currentColor" opacity="0.12" />
    <text x="${cx}" y="${y + 63}" text-anchor="middle" fill="currentColor" font-size="16" font-weight="800" font-family="system-ui, sans-serif">${n}</text>
  `
}

function buildBulletListCardsChromeSvg() {
  const { cardY, cardW, cardH, cardXs, barH } = GEOM
  const cards = cardXs.map((x, i) => cardChrome(x, cardY, cardW, cardH, barH, String(i + 1).padStart(2, '0'))).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <rect width="1920" height="1080" fill="#FFFFFF" />
    <rect width="1920" height="1080" fill="currentColor" opacity="0.04" />
    <circle cx="1760" cy="80" r="160" fill="currentColor" opacity="0.06" />
    ${cards}
  </svg>`
}

function findEl(elements, ids) {
  const set = new Set(ids)
  return (elements || []).find((e) => set.has(String(e.slotId || '').toUpperCase()))
}

function textOf(el, fallback) {
  const txt = el?.content?.text || el?.text
  if (txt && String(txt).trim()) return String(txt).trim()
  return fallback
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill
  if (fill && typeof fill === 'object' && fill.color) return fill.color
  return fallback
}

function textEl({ slotId, prev, x, y, w, h, text, fontSize, fontWeight, color, lineHeight, maxLines, sx, sy, scale, role, align }) {
  return {
    id: prev?.id || `slot-${slotId}`,
    slotId,
    type: 'text',
    role,
    layer: 10,
    placement: {
      x: Math.round(x * sx),
      y: Math.round(y * sy),
      width: Math.round(w * sx),
      height: Math.round(h * sy),
      rotation: 0,
      opacity: 1,
    },
    content: {
      text,
      fontSize: Math.round(fontSize * scale),
      fontWeight,
      color,
      align,
      verticalAlign: 'top',
      lineHeight,
      clipToSlot: true,
      maxLines,
    },
  }
}

function paletteColors(palette) {
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  return {
    accent: pal.primary || pal.accent || '#6366F1',
    textColor: pal.text || '#0F172A',
    mutedColor: pal.muted || pal.textMuted || '#64748B',
  }
}

function buildElements({ canvasW, canvasH, heading, titles, bodies, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const titleW = GEOM.cardW - GEOM.titlePad * 2
  const out = [
    {
      id: prev.IMAGE_CARD_BG?.id || prev.CARD_1_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildBulletListCardsChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    textEl({
      slotId: 'HEADING',
      prev: prev.HEADING,
      x: GEOM.headX,
      y: GEOM.headY,
      w: GEOM.headW,
      h: GEOM.headH,
      text: heading,
      fontSize: 32,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'left',
    }),
  ]
  GEOM.cardXs.forEach((cardX, i) => {
    const n = i + 1
    const tx = cardX + GEOM.titlePad
    out.push(textEl({
      slotId: `CARD_${n}_TITLE`,
      prev: prev[`CARD_${n}_TITLE`],
      x: tx,
      y: GEOM.titleY,
      w: titleW,
      h: GEOM.titleH,
      text: titles[i],
      fontSize: 20,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.2,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'left',
    }))
    out.push(textEl({
      slotId: `CARD_${n}_BODY`,
      prev: prev[`CARD_${n}_BODY`],
      x: tx,
      y: GEOM.bodyY,
      w: titleW,
      h: GEOM.bodyH,
      text: bodies[i],
      fontSize: 15,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.45,
      maxLines: 10,
      sx,
      sy,
      scale,
      role: 'body',
      align: 'left',
    }))
  })
  return out
}

function layoutBulletListCards(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'HEADLINE', 'TITLE'])
  const chromeEl = findEl(elements, ['IMAGE_CARD_BG', 'CARD_1_BG'])
  const titles = [1, 2, 3, 4].map((n) => textOf(findEl(elements, [`CARD_${n}_TITLE`]), BULLET_LIST_CARDS_DEFAULTS[`CARD_${n}_TITLE`]))
  const bodies = [1, 2, 3, 4].map((n) => textOf(findEl(elements, [`CARD_${n}_BODY`]), BULLET_LIST_CARDS_DEFAULTS.BODY))
  const prev = { IMAGE_CARD_BG: chromeEl, CARD_1_BG: chromeEl, HEADING: headingEl }
  ;[1, 2, 3, 4].forEach((n) => {
    prev[`CARD_${n}_TITLE`] = findEl(elements, [`CARD_${n}_TITLE`])
    prev[`CARD_${n}_BODY`] = findEl(elements, [`CARD_${n}_BODY`])
  })
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, BULLET_LIST_CARDS_DEFAULTS.HEADING),
    titles,
    bodies,
    accent: resolveStoredColor(chromeEl, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildBulletListCardsCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || BULLET_LIST_CARDS_DEFAULTS.HEADING).trim(),
    titles: [1, 2, 3, 4].map((n) => String(bySlot[`CARD_${n}_TITLE`] || content[`card${n}Title`] || BULLET_LIST_CARDS_DEFAULTS[`CARD_${n}_TITLE`]).trim()),
    bodies: [1, 2, 3, 4].map((n) => String(bySlot[`CARD_${n}_BODY`] || content[`card${n}Body`] || BULLET_LIST_CARDS_DEFAULTS.BODY).trim()),
    accent,
    textColor,
    mutedColor,
  })
}

function bulletListCardsPreviewSvg() {
  const chrome = buildBulletListCardsChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const titles = ['Point one', 'Point two', 'Point three', 'Point four']
  const titleNodes = GEOM.cardXs.map((x, i) =>
    `<text x="${x + 36}" y="330" fill="#0F172A" font-size="24" font-weight="800" font-family="system-ui, sans-serif">${titles[i]}</text>
     <text x="${x + 36}" y="400" fill="#64748B" font-size="16" font-family="system-ui, sans-serif">A short, scannable point.</text>`
  ).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    ${chrome}
    <text x="80" y="112" fill="#0F172A" font-size="40" font-weight="800" font-family="system-ui, sans-serif">Key points</text>
    ${titleNodes}
  </svg>`
}

module.exports = {
  isBulletListCardsLayout,
  layoutBulletListCards,
  buildBulletListCardsCanvasElements,
  buildBulletListCardsChromeSvg,
  BULLET_LIST_CARDS_DEFAULTS,
};
