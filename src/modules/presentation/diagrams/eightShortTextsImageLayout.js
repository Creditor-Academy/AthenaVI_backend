/**
 * Eight Short Texts Image — tall photo + 8 numbered points.
 * Layout IDs: eight_short_texts_image_v1, eight_short_texts_image_right_v1
 */

const EIGHT_SHORT_TEXTS_IMAGE_GEOM = {
  viewW: 1000,
  viewH: 560,
  badgeX: 404,
  badgeY: 22,
  badgeW: 220,
  badgeH: 18,
  headingX: 404,
  headingY: 44,
  headingW: 560,
  headingH: 32,
  subtitleX: 404,
  subtitleY: 78,
  subtitleW: 560,
  subtitleH: 20,
  gridStartX: 404,
  gridStartY: 108,
  cardW: 272,
  cardH: 100,
  colGap: 16,
  rowGap: 8,
  imageX: 28,
  imageY: 28,
  imageW: 352,
  imageH: 504,
  imageRadius: 18,
}

function resolveEightShortTextsGeom(isRight = false) {
  if (isRight) {
    return {
      ...EIGHT_SHORT_TEXTS_IMAGE_GEOM,
      badgeX: 28,
      headingX: 28,
      subtitleX: 28,
      gridStartX: 28,
      imageX: 620,
    }
  }
  return EIGHT_SHORT_TEXTS_IMAGE_GEOM
}

function isEightShortTextsRightVariant(layoutId, schema = {}) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  const variant = String(schema?.preview?.gridVariant || schema?.gridVariant || '').toLowerCase()
  return id.includes('right') || variant === 'right'
}

const EIGHT_SHORT_TEXTS_IMAGE_PALETTE = { primary: '#148A80', accent: '#148A80' }

const EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS = {
  BADGE: 'CORE CAPABILITIES',
  HEADING: 'Eight key points',
  SUBTITLE: 'Strategic operational framework and execution architecture',
  POINT_1_TITLE: 'Strategic Vision',
  POINT_1_DESC: 'Clear milestones aligned with long-term company objectives.',
  POINT_2_TITLE: 'Scalable Engine',
  POINT_2_DESC: 'High-concurrency infrastructure engineered for rapid growth.',
  POINT_3_TITLE: 'Automated Pipelines',
  POINT_3_DESC: 'Continuous integration driving frictionless deployment.',
  POINT_4_TITLE: 'Data Intelligence',
  POINT_4_DESC: 'Actionable real-time telemetry across distributed nodes.',
  POINT_5_TITLE: 'Enterprise Security',
  POINT_5_DESC: 'End-to-end encryption with granular compliance protocols.',
  POINT_6_TITLE: 'Customer Centricity',
  POINT_6_DESC: 'Intuitive user journeys backed by proactive feedback loops.',
  POINT_7_TITLE: 'Operational Agility',
  POINT_7_DESC: 'Rapid iteration cycles with resilient cross-functional teams.',
  POINT_8_TITLE: 'Global Reliability',
  POINT_8_DESC: '99.99% multi-region uptime with disaster recovery failover.',
}

function isEightShortTextsImageLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase()
  return (
    id === 'eight_short_texts_image_v1' ||
    id === 'eight_short_texts_image_right_v1' ||
    id === 'eight_short_texts'
  )
}

function buildPointCardSvg(w, h) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%">
    <rect width="${w}" height="${h}" fill="#FBFBFA" pointer-events="all" />
    <rect x="0" y="${h - 1}" width="${w}" height="1" fill="currentColor" fill-opacity="0.16" />
  </svg>`
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill
  if (fill && typeof fill === 'object' && fill.color) return fill.color
  return fallback
}

function layoutEightShortTextsImage(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const isRight = isEightShortTextsRightVariant(schema?.layout_id || schema?.id || schema?.layoutId, schema)
  const g = resolveEightShortTextsGeom(isRight)
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 560
  const scaleX = canvasW / g.viewW
  const scaleY = canvasH / g.viewH
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || EIGHT_SHORT_TEXTS_IMAGE_PALETTE.primary

  const prevBySlot = new Map()
  elements.forEach((el) => {
    const sid = String(el.slotId || '').toUpperCase()
    if (sid) prevBySlot.set(sid, el)
  })

  const getPrevText = (slotId, fallback) => {
    const prev = prevBySlot.get(slotId)
    const txt = prev?.content?.text || prev?.text
    if (txt && String(txt).trim()) return String(txt).trim()
    return fallback
  }

  const newElements = []
  const pushText = (config) => {
    const placement = {
      x: Math.round(config.x),
      y: Math.round(config.y),
      width: Math.max(1, Math.round(config.width)),
      height: Math.max(1, Math.round(config.height)),
      rotation: 0,
      opacity: 1,
    }
    newElements.push({
      id: config.id,
      type: 'text',
      slotId: config.slotId,
      role: config.role || 'body',
      layer: 10,
      placement,
      rect: { ...placement },
      content: {
        text: config.text,
        fontSize: config.fontSize,
        fontWeight: config.fontWeight || 500,
        color: config.color,
        align: 'left',
        lineHeight: config.lineHeight || 1.2,
        letterSpacing: config.letterSpacing || 'normal',
        clipToSlot: true,
        maxLines: config.maxLines || 2,
      },
    })
  }
  const pushGraphic = (config) => {
    const placement = {
      x: Math.round(config.x),
      y: Math.round(config.y),
      width: Math.max(1, Math.round(config.width)),
      height: Math.max(1, Math.round(config.height)),
      rotation: 0,
      opacity: 1,
    }
    newElements.push({
      id: config.id,
      type: 'graphic',
      slotId: config.slotId,
      role: 'decoration',
      layer: config.layer || 2,
      placement,
      rect: { ...placement },
      content: {
        svg: config.svg,
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: config.fill,
        stroke: config.fill,
      },
    })
  }

  pushText({
    id: prevBySlot.get('TAG_BADGE')?.id || 'est_badge',
    slotId: 'TAG_BADGE',
    role: 'caption',
    text: String(getPrevText('TAG_BADGE', EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS.BADGE)).toUpperCase(),
    x: g.badgeX * scaleX,
    y: g.badgeY * scaleY,
    width: g.badgeW * scaleX,
    height: g.badgeH * scaleY,
    fontSize: 11,
    fontWeight: 700,
    color: accent,
    letterSpacing: '0.16em',
    maxLines: 1,
  })
  pushText({
    id: prevBySlot.get('HEADING')?.id || 'est_heading',
    slotId: 'HEADING',
    role: 'heading',
    text: getPrevText('HEADING', '') || getPrevText('TITLE', '') || EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS.HEADING,
    x: g.headingX * scaleX,
    y: g.headingY * scaleY,
    width: g.headingW * scaleX,
    height: g.headingH * scaleY,
    fontSize: 24,
    fontWeight: 700,
    color: '#111827',
    maxLines: 1,
  })
  pushText({
    id: prevBySlot.get('SUBTITLE')?.id || 'est_sub',
    slotId: 'SUBTITLE',
    role: 'subheading',
    text: getPrevText('SUBTITLE', EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS.SUBTITLE),
    x: g.subtitleX * scaleX,
    y: g.subtitleY * scaleY,
    width: g.subtitleW * scaleX,
    height: g.subtitleH * scaleY,
    fontSize: 13,
    fontWeight: 400,
    color: '#6B7280',
    maxLines: 1,
  })

  for (let i = 1; i <= 8; i += 1) {
    const colIdx = (i - 1) % 2
    const rowIdx = Math.floor((i - 1) / 2)
    const cardX = g.gridStartX + colIdx * (g.cardW + g.colGap)
    const cardY = g.gridStartY + rowIdx * (g.cardH + g.rowGap)
    const numStr = String(i).padStart(2, '0')
    const cardSlotId = `POINT_${i}_CARD`
    const prevCard = prevBySlot.get(cardSlotId)
    const rowColor = resolveStoredColor(prevCard, accent)

    pushGraphic({
      id: prevCard?.id || `est_c${i}`,
      slotId: cardSlotId,
      layer: 2,
      x: cardX * scaleX,
      y: cardY * scaleY,
      width: g.cardW * scaleX,
      height: g.cardH * scaleY,
      fill: rowColor,
      svg: buildPointCardSvg(g.cardW, g.cardH),
    })
    pushText({
      id: `est_n${i}`,
      slotId: `POINT_${i}_NUM`,
      role: 'caption',
      text: numStr,
      x: (cardX + 4) * scaleX,
      y: (cardY + 14) * scaleY,
      width: 36 * scaleX,
      height: 22 * scaleY,
      fontSize: 13,
      fontWeight: 700,
      color: rowColor,
      maxLines: 1,
    })
    pushText({
      id: prevBySlot.get(`POINT_${i}_TITLE`)?.id || `est_t${i}`,
      slotId: `POINT_${i}_TITLE`,
      role: 'heading',
      text:
        getPrevText(`POINT_${i}_TITLE`, '') ||
        getPrevText(`POINT_${i}_LABEL`, '') ||
        EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS[`POINT_${i}_TITLE`],
      x: (cardX + 42) * scaleX,
      y: (cardY + 12) * scaleY,
      width: (g.cardW - 50) * scaleX,
      height: 22 * scaleY,
      fontSize: 14,
      fontWeight: 700,
      color: '#111827',
      maxLines: 1,
    })
    pushText({
      id: prevBySlot.get(`POINT_${i}_DESC`)?.id || `est_d${i}`,
      slotId: `POINT_${i}_DESC`,
      role: 'body',
      text: getPrevText(`POINT_${i}_DESC`, EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS[`POINT_${i}_DESC`]),
      x: (cardX + 42) * scaleX,
      y: (cardY + 36) * scaleY,
      width: (g.cardW - 50) * scaleX,
      height: 52 * scaleY,
      fontSize: 12,
      fontWeight: 400,
      color: '#6B7280',
      lineHeight: 1.35,
      maxLines: 2,
    })
  }

  const prevImage = prevBySlot.get('HERO_IMAGE') || prevBySlot.get('IMAGE_1')
  const imageUrl = prevImage?.content?.url || prevImage?.content?.src || null
  const imgPlace = {
    x: Math.round(g.imageX * scaleX),
    y: Math.round(g.imageY * scaleY),
    width: Math.max(1, Math.round(g.imageW * scaleX)),
    height: Math.max(1, Math.round(g.imageH * scaleY)),
    rotation: 0,
    opacity: 1,
  }
  newElements.push({
    id: prevImage?.id || 'est_hero',
    type: 'image',
    slotId: 'HERO_IMAGE',
    role: 'image',
    layer: 4,
    placement: imgPlace,
    rect: { ...imgPlace },
    content: {
      ...(imageUrl ? { url: imageUrl, src: imageUrl } : {}),
      fit: 'cover',
      borderRadius: Math.round(g.imageRadius * Math.min(scaleX, scaleY)),
    },
  })

  if (Array.isArray(docOrElements)) return newElements
  return { ...docOrElements, elements: newElements }
}

module.exports = {
  EIGHT_SHORT_TEXTS_IMAGE_GEOM,
  EIGHT_SHORT_TEXTS_IMAGE_PALETTE,
  EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS,
  isEightShortTextsImageLayout,
  isEightShortTextsRightVariant,
  resolveEightShortTextsGeom,
  buildPointCardSvg,
  layoutEightShortTextsImage,
}
