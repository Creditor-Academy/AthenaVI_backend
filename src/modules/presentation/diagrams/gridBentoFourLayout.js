/**
 * Grid Bento Four Layout Engine (Backend Server-Side Compiler)
 * Layout IDs:
 *  - grid_bento_four_v1
 *  - grid_bento_four
 *
 * Executive Hero-Left Bento Showcase:
 *  - Top Slide Header:
 *    - Main Heading ("Executive visual showcase")
 *    - Subtitle ("A structured visual collection across creative focus areas.")
 *  - 4 Bento Image Cards:
 *    - Card 1 (IMAGE_1): Tall Hero Left portrait card spanning full grid height
 *    - Card 2 (IMAGE_2): Wide Landscape card on top-right
 *    - Card 3 (IMAGE_3): Square-ish card on bottom-right (left)
 *    - Card 4 (IMAGE_4): Square-ish card on bottom-right (right) — strictly equal width to Card 3
 *  - Heading shifted up with clipToSlot: false and generous box height so text never clips
 *  - Preserves existing image URLs/src
 *  - Full placement schema compliance ({ x, y, width, height, rotation: 0, opacity: 1 })
 */

const GRID_BENTO_FOUR_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Slide Header Area: Shifted up comfortably with ample box height so text never clips
  headingX: 48,
  headingY: 18,
  headingW: 904,
  headingH: 56,

  subtitleX: 48,
  subtitleY: 66,
  subtitleW: 904,
  subtitleH: 34,

  // Bento Image Area: Starts at y: 126 (y = 243px on 1080p canvas), total height 410
  card1: {
    x: 48,
    y: 126,
    w: 396,
    h: 410,
    radius: 14,
  },
  card2: {
    x: 456,
    y: 126,
    w: 496,
    h: 198,
    radius: 14,
  },
  card3: {
    x: 456,
    y: 338,
    w: 242,
    h: 198,
    radius: 14,
  },
  card4: {
    x: 710,
    y: 338,
    w: 242,
    h: 198,
    radius: 14,
  },
}

const GRID_BENTO_FOUR_THEMES = [
  {
    primary: '#4F46E5', // Indigo
    accent: '#818CF8',
    tint: '#EEF2FF',
    border: '#C7D2FE',
    visualGradStart: '#EEF2FF',
    visualGradEnd: '#E0E7FF',
  },
  {
    primary: '#0D9488', // Teal
    accent: '#14B8A6',
    tint: '#F0FDFA',
    border: '#CCFBF1',
    visualGradStart: '#F0FDFA',
    visualGradEnd: '#CCFBF1',
  },
  {
    primary: '#0284C7', // Sky Blue
    accent: '#38BDF8',
    tint: '#F0F9FF',
    border: '#BAE6FD',
    visualGradStart: '#F0F9FF',
    visualGradEnd: '#E0F2FE',
  },
  {
    primary: '#D97706', // Amber
    accent: '#FBBF24',
    tint: '#FFFBEB',
    border: '#FDE68A',
    visualGradStart: '#FFFBEB',
    visualGradEnd: '#FEF3C7',
  },
]

const GRID_BENTO_FOUR_DEFAULTS = {
  HEADING: 'Executive visual showcase',
  SUBTITLE: 'A structured visual collection across creative focus areas.',
}

function isGridBentoFourLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return (
    id === 'grid_bento_four_v1' ||
    id === 'grid_bento_four'
  )
}

function buildBentoFourPlaceholderSvg(cardIdx, width, height, radius = 14) {
  const theme = GRID_BENTO_FOUR_THEMES[cardIdx] || GRID_BENTO_FOUR_THEMES[0]
  const { primary, border, visualGradStart, visualGradEnd } = theme

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="b4grad-be-${cardIdx}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${visualGradStart}" />
        <stop offset="100%" stop-color="${visualGradEnd}" />
      </linearGradient>
    </defs>
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="${radius}" fill="url(#b4grad-be-${cardIdx})" stroke="${border}" stroke-width="1.2" />
    <g transform="translate(${width / 2 - 18}, ${height / 2 - 16})" opacity="0.4">
      <rect x="2" y="5" width="32" height="24" rx="4" fill="none" stroke="${primary}" stroke-width="2" />
      <circle cx="18" cy="17" r="6" fill="none" stroke="${primary}" stroke-width="2" />
      <path d="M 11 5 L 14 2 L 22 2 L 25 5 Z" fill="none" stroke="${primary}" stroke-width="2" />
    </g>
  </svg>`
}

function layoutGridBentoFour(elements, schema, palette = {}, canvas = {}) {
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const geom = GRID_BENTO_FOUR_GEOM

  const scaleX = canvasW / geom.viewW
  const scaleY = canvasH / geom.viewH

  // 1. Extract existing text content
  const findText = (matcher, fallback) => {
    const el = elements.find((e) => {
      const sid = String(e.slotId || '').toUpperCase()
      const role = String(e.role || '').toUpperCase()
      return matcher(sid, role)
    })
    const txt = el?.content?.text || el?.text || el?.content?.heading || el?.content?.title
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const headingText = findText(
    (s, r) => s === 'HEADING' || s.includes('TITLE') || r === 'HEADING',
    GRID_BENTO_FOUR_DEFAULTS.HEADING
  )

  const subtitleText = findText(
    (s, r) => s === 'SUBTITLE' || s.includes('SUB') || s.includes('BODY') || r === 'SUBHEADING',
    GRID_BENTO_FOUR_DEFAULTS.SUBTITLE
  )

  // 2. Extract existing images
  const existingImages = elements.filter(
    (e) => e.type === 'image' || /^IMAGE_\d+$/i.test(String(e.slotId || ''))
  )

  const getImageContent = (slotNum) => {
    const el =
      elements.find((e) => String(e.slotId || '').toUpperCase() === `IMAGE_${slotNum}`) ||
      existingImages[slotNum - 1]

    const url = el?.content?.url || el?.content?.src || el?.url || el?.src || null
    return {
      url,
      fit: el?.content?.fit || 'cover',
      borderRadius: 16,
      name: el?.content?.name || `Image ${slotNum}`,
    }
  }

  const outElements = []

  const pushElement = (config) => {
    const x = Math.round(config.x)
    const y = Math.round(config.y)
    const width = Math.max(1, Math.round(config.width))
    const height = Math.max(1, Math.round(config.height))

    const basePlacement = {
      x,
      y,
      width,
      height,
      rotation: 0,
      opacity: config.opacity !== undefined ? config.opacity : 1,
    }

    if (config.type === 'text') {
      outElements.push({
        id: config.id,
        type: 'text',
        slotId: config.slotId,
        role: config.role || 'text',
        layer: config.layer || 10,
        placement: basePlacement,
        rect: { ...basePlacement },
        content: {
          text: config.text,
          fontSize: Math.round(config.fontSize * Math.min(scaleX, scaleY)),
          fontWeight: config.fontWeight || 600,
          color: config.color || '#0F172A',
          align: config.align || 'left',
          lineHeight: config.lineHeight || 1.25,
          letterSpacing: config.letterSpacing || 'normal',
          clipToSlot: false, // Ensures overflow: visible so font ascenders/descenders are never clipped
        },
      })
    } else if (config.type === 'image') {
      const imgData = config.imgData || {}
      outElements.push({
        id: config.id,
        type: 'image',
        slotId: config.slotId,
        role: 'image',
        layer: config.layer || 2,
        placement: basePlacement,
        rect: { ...basePlacement },
        content: {
          url: imgData.url || null,
          src: imgData.url || null,
          fit: imgData.fit || 'cover',
          borderRadius: imgData.borderRadius || 16,
          name: imgData.name || config.slotId,
          ...(imgData.url ? {} : {
            placeholderSvg: buildBentoFourPlaceholderSvg(config.cardIdx, width, height, 16),
          }),
        },
      })
    } else if (config.type === 'shape') {
      outElements.push({
        id: config.id,
        type: 'shape',
        slotId: config.slotId,
        role: config.role || 'decoration',
        layer: config.layer || 1,
        placement: basePlacement,
        rect: { ...basePlacement },
        content: {
          shape: 'rect',
          fill: config.fill || 'transparent',
          svgContent: config.svgContent || null,
        },
      })
    }
  }

  // 1. Bento Images FIRST in DOM order (layer: 2)
  const cards = [
    { slotId: 'IMAGE_1', cardIdx: 0, geom: geom.card1 },
    { slotId: 'IMAGE_2', cardIdx: 1, geom: geom.card2 },
    { slotId: 'IMAGE_3', cardIdx: 2, geom: geom.card3 },
    { slotId: 'IMAGE_4', cardIdx: 3, geom: geom.card4 },
  ]

  cards.forEach((card, idx) => {
    const imgData = getImageContent(idx + 1)
    pushElement({
      id: `bento4_img_${idx + 1}`,
      type: 'image',
      slotId: card.slotId,
      cardIdx: card.cardIdx,
      layer: 2,
      imgData,
      x: card.geom.x * scaleX,
      y: card.geom.y * scaleY,
      width: card.geom.w * scaleX,
      height: card.geom.h * scaleY,
    })
  })

  // 2. Heading element (layer: 10) - Shifted up with clipToSlot: false
  pushElement({
    id: 'bento4_heading',
    type: 'text',
    slotId: 'HEADING',
    role: 'heading',
    layer: 10,
    text: headingText,
    x: geom.headingX * scaleX,
    y: geom.headingY * scaleY,
    width: geom.headingW * scaleX,
    height: geom.headingH * scaleY,
    fontSize: 23,
    fontWeight: 800,
    color: '#0F172A',
    lineHeight: 1.2,
  })

  // 3. Subtitle element (layer: 10)
  pushElement({
    id: 'bento4_subtitle',
    type: 'text',
    slotId: 'SUBTITLE',
    role: 'subheading',
    layer: 10,
    text: subtitleText,
    x: geom.subtitleX * scaleX,
    y: geom.subtitleY * scaleY,
    width: geom.subtitleW * scaleX,
    height: geom.subtitleH * scaleY,
    fontSize: 12,
    fontWeight: 400,
    color: '#64748B',
    lineHeight: 1.35,
  })

  return outElements
}

module.exports = {
  GRID_BENTO_FOUR_GEOM,
  GRID_BENTO_FOUR_THEMES,
  GRID_BENTO_FOUR_DEFAULTS,
  isGridBentoFourLayout,
  buildBentoFourPlaceholderSvg,
  layoutGridBentoFour,
}
