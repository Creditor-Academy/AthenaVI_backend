/**
 * Three Cards Image Text
 * Layout ID: three_cards_image_text_v1
 *
 * Heading top-left with accent bar; three elevated white cards, each with an inset photo,
 * a numbered accent chip, a bold title and a muted supporting paragraph.
 */

function isThreeCardsImageTextLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'three_cards_image_text_v1' || id === 'three_cards_image_text'
}

const THREE_CARDS_IMAGE_TEXT_DEFAULTS = {
  HEADING: 'Product highlights',
  TITLES: ['Feature A', 'Feature B', 'Feature C'],
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headX: 120,
  barY: 80,
  barW: 56,
  barH: 6,
  headY: 96,
  headW: 1680,
  headH: 148,
  cardXs: [88, 684, 1280],
  cardY: 256,
  cardW: 552,
  cardH: 780,
  cardR: 32,
  imgPad: 18,
  imgH: 268,
  imgR: 22,
  chipDy: 308,
  chipW: 68,
  chipH: 36,
  textPad: 34,
  titleDy: 364,
  titleH: 100,
  bodyDy: 474,
  bodyH: 276,
  stripH: 8,
}

const TYPE = {
  heading: { size: 40, weight: 800, lh: 1.15 },
  title: { size: 24, weight: 800, lh: 1.2 },
  body: { size: 16, weight: 400, lh: 1.5 },
}

function buildThreeCardsImageTextChromeSvg() {
  const {
    headX, barY, barW, barH, cardXs, cardY, cardW, cardH, cardR,
    chipDy, chipW, chipH, textPad, stripH,
  } = GEOM
  const cards = cardXs
    .map((x, i) => {
      const chipX = x + textPad
      const chipY = cardY + chipDy
      const lineY = chipY + chipH / 2
      return `
    <rect x="${x}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="#FFFFFF" filter="url(#tciShadow)" />
    <clipPath id="tciCard${i}"><rect x="${x}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" /></clipPath>
    <rect x="${x}" y="${cardY + cardH - stripH}" width="${cardW}" height="${stripH}" fill="currentColor" clip-path="url(#tciCard${i})" />
    <rect x="${chipX}" y="${chipY}" width="${chipW}" height="${chipH}" rx="${chipH / 2}" fill="currentColor" opacity="0.12" />
    <text x="${chipX + chipW / 2}" y="${chipY + 25}" text-anchor="middle" fill="currentColor" font-size="19" font-weight="800" font-family="system-ui, sans-serif" letter-spacing="1">0${i + 1}</text>
    <line x1="${chipX + chipW + 16}" y1="${lineY}" x2="${x + cardW - textPad}" y2="${lineY}" stroke="currentColor" stroke-width="2" stroke-dasharray="2 10" stroke-linecap="round" opacity="0.35" />`
    })
    .join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="tciShadow" x="-10%" y="-8%" width="120%" height="124%">
        <feDropShadow dx="0" dy="16" stdDeviation="22" flood-color="#94A3B8" flood-opacity="0.24" />
      </filter>
    </defs>
    <path d="M0 520 C 420 470 900 640 1920 470 L1920 1080 L0 1080 Z" fill="currentColor" opacity="0.05" />
    <circle cx="1800" cy="120" r="170" fill="currentColor" opacity="0.06" />
    <circle cx="1800" cy="120" r="96" fill="none" stroke="currentColor" stroke-width="2" opacity="0.16" />
    <rect x="${headX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
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

function buildElements({ canvasW, canvasH, heading, cards, imageUrls, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const { cardXs, cardY, cardW, imgPad, imgH, imgR, textPad, titleDy, titleH, bodyDy, bodyH } = GEOM
  const textW = cardW - textPad * 2

  const cardEls = cardXs.flatMap((x, i) => {
    const n = i + 1
    const imgSlot = `IMAGE_${n}`
    const url = imageUrls[i]
    return [
      {
        id: prev[imgSlot]?.id || `slot-${imgSlot}`,
        slotId: imgSlot,
        type: 'image',
        role: 'image',
        layer: 6,
        placement: {
          x: Math.round((x + imgPad) * sx),
          y: Math.round((cardY + imgPad) * sy),
          width: Math.round((cardW - imgPad * 2) * sx),
          height: Math.round(imgH * sy),
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...(url ? { url, src: url } : {}),
          fit: 'cover',
          borderRadius: Math.round(imgR * scale),
          alt: '',
        },
      },
      textEl({
        slotId: `CARD_${n}_TITLE`,
        prev: prev[`CARD_${n}_TITLE`],
        x: x + textPad,
        y: cardY + titleDy,
        w: textW,
        h: titleH,
        text: cards[i].title,
        fontSize: TYPE.title.size,
        fontWeight: TYPE.title.weight,
        color: textColor,
        lineHeight: TYPE.title.lh,
        maxLines: 2,
        role: 'heading',
        sx, sy, scale,
      }),
      textEl({
        slotId: `CARD_${n}_BODY`,
        prev: prev[`CARD_${n}_BODY`],
        x: x + textPad,
        y: cardY + bodyDy,
        w: textW,
        h: bodyH,
        text: cards[i].body,
        fontSize: TYPE.body.size,
        fontWeight: TYPE.body.weight,
        color: mutedColor,
        lineHeight: TYPE.body.lh,
        maxLines: 5,
        role: 'body',
        sx, sy, scale,
      }),
    ]
  })

  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildThreeCardsImageTextChromeSvg(),
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
      fontSize: TYPE.heading.size,
      fontWeight: TYPE.heading.weight,
      color: textColor,
      lineHeight: TYPE.heading.lh,
      maxLines: 2,
      role: 'heading',
      sx, sy, scale,
    }),
    ...cardEls,
  ]
}

function paletteColors(palette) {
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  return {
    accent: pal.primary || pal.accent || '#6366F1',
    textColor: pal.text || '#0F172A',
    mutedColor: pal.muted || pal.textMuted || '#64748B',
  }
}

function layoutThreeCardsImageText(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'TITLE'])
  const cardEl = findEl(elements, ['IMAGE_CARD_BG'])
  const prev = { IMAGE_CARD_BG: cardEl, HEADING: headingEl }
  const cards = [1, 2, 3].map((n, i) => {
    const titleEl = findEl(elements, [`CARD_${n}_TITLE`])
    const bodyEl = findEl(elements, [`CARD_${n}_BODY`])
    prev[`CARD_${n}_TITLE`] = titleEl
    prev[`CARD_${n}_BODY`] = bodyEl
    return {
      title: textOf(titleEl, THREE_CARDS_IMAGE_TEXT_DEFAULTS.TITLES[i]),
      body: textOf(bodyEl, THREE_CARDS_IMAGE_TEXT_DEFAULTS.BODY),
    }
  })
  const imageEls = [1, 2, 3].map((n) => findEl(elements, [`IMAGE_${n}`]))
  imageEls.forEach((el, i) => { prev[`IMAGE_${i + 1}`] = el })
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, THREE_CARDS_IMAGE_TEXT_DEFAULTS.HEADING),
    cards,
    imageUrls: imageEls.map((el) => el?.content?.url || el?.content?.src || null),
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildThreeCardsImageTextCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  const urls = Array.isArray(content.imageUrls) ? content.imageUrls : []
  const items = Array.isArray(content.items) ? content.items : []
  const cards = [1, 2, 3].map((n, i) => ({
    title: String(bySlot[`CARD_${n}_TITLE`] || items[i]?.title || THREE_CARDS_IMAGE_TEXT_DEFAULTS.TITLES[i]).trim(),
    body: String(bySlot[`CARD_${n}_BODY`] || items[i]?.body || items[i]?.description || THREE_CARDS_IMAGE_TEXT_DEFAULTS.BODY).trim(),
  }))
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || THREE_CARDS_IMAGE_TEXT_DEFAULTS.HEADING).trim(),
    cards,
    imageUrls: [1, 2, 3].map((n, i) =>
      bySlot[`IMAGE_${n}__url`] || bySlot[`IMAGE_${n}_url`] || urls[i] || null
    ),
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isThreeCardsImageTextLayout,
  layoutThreeCardsImageText,
  buildThreeCardsImageTextChromeSvg,
  THREE_CARDS_IMAGE_TEXT_DEFAULTS,
};
