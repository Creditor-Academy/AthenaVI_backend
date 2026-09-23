/**
 * Two Cards Image Text
 * Layout ID: two_cards_image_text_v1
 *
 * Eyebrow top-left with accent bar; two large elevated white cards, each with a
 * landscape photo, numbered chip, bold title and muted supporting paragraph.
 */

function isTwoCardsImageTextLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'two_cards_image_text_v1' || id === 'two_cards_image_text'
}

const TWO_CARDS_IMAGE_TEXT_DEFAULTS = {
  EYEBROW: 'Describe this slide',
  TITLES: ['Make your point', 'Make another point'],
  BODIES: [
    'Lead with the first idea in a few clear lines that a viewer can scan without crowding the photo above.',
    'Pair it with a second idea that complements the first, using the same rhythm so the two cards feel like a set.',
  ],
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  eyeX: 100,
  barY: 64,
  barW: 56,
  barH: 6,
  eyeY: 84,
  eyeW: 1720,
  eyeH: 56,
  cardXs: [88, 996],
  cardY: 168,
  cardW: 836,
  cardH: 852,
  cardR: 36,
  imgPad: 20,
  imgH: 380,
  imgR: 24,
  chipDy: 424,
  chipW: 72,
  chipH: 36,
  textPad: 40,
  titleDy: 480,
  titleH: 96,
  bodyDy: 588,
  bodyH: 228,
  stripH: 8,
}

const TYPE = {
  eyebrow: { size: 14, weight: 700, lh: 1.2 },
  title: { size: 24, weight: 800, lh: 1.2 },
  body: { size: 16, weight: 400, lh: 1.5 },
}

function buildTwoCardsImageTextChromeSvg() {
  const {
    eyeX, barY, barW, barH, cardXs, cardY, cardW, cardH, cardR,
    chipDy, chipW, chipH, textPad, stripH,
  } = GEOM
  const cards = cardXs
    .map((x, i) => {
      const chipX = x + textPad
      const chipY = cardY + chipDy
      const lineY = chipY + chipH / 2
      return `
    <rect x="${x}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="#FFFFFF" filter="url(#tci2Shadow)" />
    <clipPath id="tci2Card${i}"><rect x="${x}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" /></clipPath>
    <rect x="${x}" y="${cardY + cardH - stripH}" width="${cardW}" height="${stripH}" fill="currentColor" clip-path="url(#tci2Card${i})" />
    <rect x="${chipX}" y="${chipY}" width="${chipW}" height="${chipH}" rx="${chipH / 2}" fill="currentColor" opacity="0.12" />
    <text x="${chipX + chipW / 2}" y="${chipY + 25}" text-anchor="middle" fill="currentColor" font-size="19" font-weight="800" font-family="system-ui, sans-serif" letter-spacing="1">0${i + 1}</text>
    <line x1="${chipX + chipW + 16}" y1="${lineY}" x2="${x + cardW - textPad}" y2="${lineY}" stroke="currentColor" stroke-width="2" stroke-dasharray="2 10" stroke-linecap="round" opacity="0.35" />`
    })
    .join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="tci2Shadow" x="-8%" y="-6%" width="116%" height="120%">
        <feDropShadow dx="0" dy="16" stdDeviation="22" flood-color="#94A3B8" flood-opacity="0.24" />
      </filter>
    </defs>
    <path d="M0 1080 L0 560 C 480 500 1100 700 1920 480 L1920 1080 Z" fill="currentColor" opacity="0.05" />
    <circle cx="1760" cy="90" r="150" fill="currentColor" opacity="0.06" />
    <circle cx="1760" cy="90" r="86" fill="none" stroke="currentColor" stroke-width="2" opacity="0.16" />
    <rect x="${eyeX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
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

function buildElements({ canvasW, canvasH, eyebrow, cards, imageUrls, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const { cardXs, cardY, cardW, imgPad, imgH, imgR, textPad, titleDy, titleH, bodyDy, bodyH } = GEOM
  const textW = cardW - textPad * 2

  const cardEls = cardXs.flatMap((x, i) => {
    const n = i + 1
    const imgSlot = `COL_${n}_IMAGE`
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
        slotId: `COL_${n}_TITLE`,
        prev: prev[`COL_${n}_TITLE`],
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
        slotId: `COL_${n}_BODY`,
        prev: prev[`COL_${n}_BODY`],
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
        svg: buildTwoCardsImageTextChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    textEl({
      slotId: 'EYEBROW',
      prev: prev.EYEBROW,
      x: GEOM.eyeX,
      y: GEOM.eyeY,
      w: GEOM.eyeW,
      h: GEOM.eyeH,
      text: eyebrow,
      fontSize: TYPE.eyebrow.size,
      fontWeight: TYPE.eyebrow.weight,
      color: accent,
      lineHeight: TYPE.eyebrow.lh,
      maxLines: 1,
      role: 'eyebrow',
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

function layoutTwoCardsImageText(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const eyebrowEl = findEl(elements, ['EYEBROW', 'HEADING', 'TITLE'])
  const cardEl = findEl(elements, ['IMAGE_CARD_BG'])
  const prev = { IMAGE_CARD_BG: cardEl, EYEBROW: eyebrowEl }
  const cards = [1, 2].map((n, i) => {
    const titleEl = findEl(elements, [`COL_${n}_TITLE`, `CARD_${n}_TITLE`])
    const bodyEl = findEl(elements, [`COL_${n}_BODY`, `CARD_${n}_BODY`])
    prev[`COL_${n}_TITLE`] = titleEl
    prev[`COL_${n}_BODY`] = bodyEl
    return {
      title: textOf(titleEl, TWO_CARDS_IMAGE_TEXT_DEFAULTS.TITLES[i]),
      body: textOf(bodyEl, TWO_CARDS_IMAGE_TEXT_DEFAULTS.BODIES[i]),
    }
  })
  const imageEls = [1, 2].map((n) => findEl(elements, [`COL_${n}_IMAGE`, `IMAGE_${n}`]))
  imageEls.forEach((el, i) => { prev[`COL_${i + 1}_IMAGE`] = el })
  const out = buildElements({
    canvasW,
    canvasH,
    eyebrow: textOf(eyebrowEl, TWO_CARDS_IMAGE_TEXT_DEFAULTS.EYEBROW),
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

function buildTwoCardsImageTextCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  const urls = Array.isArray(content.imageUrls) ? content.imageUrls : []
  const items = Array.isArray(content.items) ? content.items : []
  const cards = [1, 2].map((n, i) => ({
    title: String(
      bySlot[`COL_${n}_TITLE`] || bySlot[`CARD_${n}_TITLE`] || items[i]?.title || TWO_CARDS_IMAGE_TEXT_DEFAULTS.TITLES[i]
    ).trim(),
    body: String(
      bySlot[`COL_${n}_BODY`] || bySlot[`CARD_${n}_BODY`] || items[i]?.body || items[i]?.description || TWO_CARDS_IMAGE_TEXT_DEFAULTS.BODIES[i]
    ).trim(),
  }))
  return buildElements({
    canvasW,
    canvasH,
    eyebrow: String(bySlot.EYEBROW || bySlot.HEADING || content.eyebrow || content.heading || TWO_CARDS_IMAGE_TEXT_DEFAULTS.EYEBROW).trim(),
    cards,
    imageUrls: [1, 2].map((n, i) =>
      bySlot[`COL_${n}_IMAGE__url`] ||
      bySlot[`COL_${n}_IMAGE_url`] ||
      bySlot[`IMAGE_${n}__url`] ||
      urls[i] ||
      null
    ),
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isTwoCardsImageTextLayout,
  layoutTwoCardsImageText,
  buildTwoCardsImageTextChromeSvg,
  TWO_CARDS_IMAGE_TEXT_DEFAULTS,
};
