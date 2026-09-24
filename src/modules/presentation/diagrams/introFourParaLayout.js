/**
 * Intro Four Para
 * Layout ID: intro_four_para_v1
 *
 * Intro heading plus a 2Ã—2 grid of numbered paragraph cards.
 * Distinct from Intro Three Para Icons and Four Para Image.
 */

function isIntroFourParaLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'intro_four_para_v1' || id === 'intro_four_para'
}

const INTRO_FOUR_PARA_DEFAULTS = {
  INTRO: 'What we will cover',
  ITEM_1: 'Introduction â€” context, audience, and the outcome this story is here to drive.',
  ITEM_2: 'Problem and opportunity â€” where the current path breaks, and the opening it creates.',
  ITEM_3: 'Solution and proof â€” the approach, evidence, and why it holds up under scrutiny.',
  ITEM_4: 'Next steps â€” owners, timing, and the first decisions that move the work forward.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  introX: 120,
  introY: 72,
  introW: 1280,
  introH: 120,
  barX: 120,
  barY: 208,
  barW: 72,
  barH: 6,
  cardXs: [120, 1000],
  cardYs: [248, 652],
  cardW: 800,
  cardH: 364,
  cardR: 28,
  cardPad: 40,
  numY: 36,
  textY: 108,
  textH: 216,
}

function cardRects() {
  const out = []
  GEOM.cardYs.forEach((y) => GEOM.cardXs.forEach((x) => out.push({ x, y })))
  return out
}

function buildIntroFourParaChromeSvg() {
  const { barX, barY, barW, barH, cardW, cardH, cardR, cardPad, numY } = GEOM
  const cards = cardRects()
    .map(({ x, y }, i) => `
    <rect x="${x}" y="${y}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="currentColor" opacity="0.055" />
    <rect x="${x + cardPad}" y="${y + numY}" width="64" height="44" rx="22" fill="currentColor" opacity="0.16" />
    <text x="${x + cardPad + 32}" y="${y + numY + 30}" text-anchor="middle" font-size="18" font-weight="800" font-family="system-ui, sans-serif" fill="currentColor">0${i + 1}</text>`)
    .join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <path d="M1420 0 H1920 V420 H1580 C 1480 240 1440 80 1420 0 Z" fill="currentColor" opacity="0.05" />
    <circle cx="1780" cy="120" r="150" fill="currentColor" opacity="0.07" />
    <circle cx="1780" cy="120" r="88" fill="none" stroke="currentColor" stroke-width="2" opacity="0.16" />
    <rect x="${barX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
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

function textEl({ slotId, prev, x, y, w, h, text, fontSize, fontWeight, color, lineHeight, maxLines, sx, sy, scale, role }) {
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
      align: 'left',
      verticalAlign: 'flex-start',
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

function buildElements({ canvasW, canvasH, intro, items, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const rects = cardRects()
  const out = [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildIntroFourParaChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    textEl({
      slotId: 'INTRO',
      prev: prev.INTRO,
      x: GEOM.introX,
      y: GEOM.introY,
      w: GEOM.introW,
      h: GEOM.introH,
      text: intro,
      fontSize: 36,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 2,
      role: 'heading',
      sx, sy, scale,
    }),
  ]
  rects.forEach(({ x, y }, i) => {
    const slotId = `ITEM_${i + 1}`
    out.push(textEl({
      slotId,
      prev: prev[slotId],
      x: x + GEOM.cardPad,
      y: y + GEOM.textY,
      w: GEOM.cardW - GEOM.cardPad * 2,
      h: GEOM.textH,
      text: items[i],
      fontSize: 18,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.45,
      maxLines: 5,
      role: 'body',
      sx, sy, scale,
    }))
  })
  return out
}

function layoutIntroFourPara(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const introEl = findEl(elements, ['INTRO', 'HEADING', 'HEADLINE', 'TITLE'])
  const itemEls = [1, 2, 3, 4].map((n) => findEl(elements, [`ITEM_${n}`, `BULLET_${n}`, `BODY_${n}`]))
  const cardEl = findEl(elements, ['IMAGE_CARD_BG'])
  const prev = { IMAGE_CARD_BG: cardEl, INTRO: introEl }
  itemEls.forEach((el, i) => { prev[`ITEM_${i + 1}`] = el })
  const out = buildElements({
    canvasW,
    canvasH,
    intro: textOf(introEl, INTRO_FOUR_PARA_DEFAULTS.INTRO),
    items: itemEls.map((el, i) => textOf(el, INTRO_FOUR_PARA_DEFAULTS[`ITEM_${i + 1}`])),
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildIntroFourParaCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    intro: String(bySlot.INTRO || bySlot.HEADING || content.heading || content.intro || INTRO_FOUR_PARA_DEFAULTS.INTRO).trim(),
    items: [1, 2, 3, 4].map((n) => String(
      bySlot[`ITEM_${n}`] || content[`item${n}`] || content.items?.[n - 1] || INTRO_FOUR_PARA_DEFAULTS[`ITEM_${n}`]
    ).trim()),
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isIntroFourParaLayout,
  layoutIntroFourPara,
  buildIntroFourParaChromeSvg,
  INTRO_FOUR_PARA_DEFAULTS,
};
