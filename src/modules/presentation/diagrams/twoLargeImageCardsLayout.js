/**
 * Two Large Image Cards
 * Layout ID: two_large_image_cards_v1
 *
 * Two photo-forward cards filling the slide. Each has a large landscape image,
 * then a bold product title and a short supporting paragraph. No eyebrow.
 */

function isTwoLargeImageCardsLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'two_large_image_cards_v1' || id === 'two_large_image_cards'
}

const TWO_LARGE_IMAGE_CARDS_DEFAULTS = {
  TITLES: ['Product one', 'Product two'],
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  cardXs: [64, 988],
  cardY: 64,
  cardW: 868,
  cardH: 952,
  cardR: 36,
  imgPad: 16,
  imgH: 560,
  imgR: 24,
  accentDy: 596,
  accentW: 56,
  accentH: 6,
  textPad: 40,
  titleDy: 620,
  titleH: 100,
  bodyDy: 732,
  bodyH: 180,
  stripH: 8,
}

const TYPE = {
  title: { size: 24, weight: 800, lh: 1.2 },
  body: { size: 16, weight: 400, lh: 1.5 },
}

function buildTwoLargeImageCardsChromeSvg() {
  const {
    cardXs, cardY, cardW, cardH, cardR, textPad, accentDy, accentW, accentH, stripH,
  } = GEOM
  const cards = cardXs
    .map((x) => `
    <rect x="${x}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="#FFFFFF" filter="url(#tlicShadow)" />
    <clipPath id="tlicClip${x}"><rect x="${x}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" /></clipPath>
    <rect x="${x}" y="${cardY + cardH - stripH}" width="${cardW}" height="${stripH}" fill="currentColor" clip-path="url(#tlicClip${x})" />
    <rect x="${x + textPad}" y="${cardY + accentDy}" width="${accentW}" height="${accentH}" rx="${accentH / 2}" fill="currentColor" />`)
    .join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="tlicShadow" x="-8%" y="-6%" width="116%" height="120%">
        <feDropShadow dx="0" dy="18" stdDeviation="22" flood-color="#94A3B8" flood-opacity="0.24" />
      </filter>
    </defs>
    <rect width="1920" height="1080" fill="currentColor" opacity="0.04" />
    <circle cx="1840" cy="80" r="160" fill="currentColor" opacity="0.06" />
    <circle cx="80" cy="1000" r="120" fill="currentColor" opacity="0.05" />
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

function buildElements({ canvasW, canvasH, cards, imageUrls, accent, textColor, mutedColor, prev = {} }) {
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
        maxLines: 4,
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
        svg: buildTwoLargeImageCardsChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
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

function layoutTwoLargeImageCards(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const cardEl = findEl(elements, ['IMAGE_CARD_BG'])
  const prev = { IMAGE_CARD_BG: cardEl }
  const cards = [1, 2].map((n, i) => {
    const titleEl = findEl(elements, [`CARD_${n}_TITLE`, `COL_${n}_TITLE`])
    const bodyEl = findEl(elements, [`CARD_${n}_BODY`, `COL_${n}_BODY`])
    prev[`CARD_${n}_TITLE`] = titleEl
    prev[`CARD_${n}_BODY`] = bodyEl
    return {
      title: textOf(titleEl, TWO_LARGE_IMAGE_CARDS_DEFAULTS.TITLES[i]),
      body: textOf(bodyEl, TWO_LARGE_IMAGE_CARDS_DEFAULTS.BODY),
    }
  })
  const imageEls = [1, 2].map((n) => findEl(elements, [`IMAGE_${n}`, `COL_${n}_IMAGE`]))
  imageEls.forEach((el, i) => { prev[`IMAGE_${i + 1}`] = el })
  const out = buildElements({
    canvasW,
    canvasH,
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

function buildTwoLargeImageCardsCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  const urls = Array.isArray(content.imageUrls) ? content.imageUrls : []
  const items = Array.isArray(content.items) ? content.items : []
  const cards = [1, 2].map((n, i) => ({
    title: String(bySlot[`CARD_${n}_TITLE`] || items[i]?.title || TWO_LARGE_IMAGE_CARDS_DEFAULTS.TITLES[i]).trim(),
    body: String(bySlot[`CARD_${n}_BODY`] || items[i]?.body || items[i]?.description || TWO_LARGE_IMAGE_CARDS_DEFAULTS.BODY).trim(),
  }))
  return buildElements({
    canvasW,
    canvasH,
    cards,
    imageUrls: [1, 2].map((n, i) =>
      bySlot[`IMAGE_${n}__url`] || bySlot[`IMAGE_${n}_url`] || urls[i] || null
    ),
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isTwoLargeImageCardsLayout,
  layoutTwoLargeImageCards,
  buildTwoLargeImageCardsChromeSvg,
  TWO_LARGE_IMAGE_CARDS_DEFAULTS,
};
