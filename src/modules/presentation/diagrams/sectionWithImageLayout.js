'use strict'
/** Custom canvas layout for section_with_image_v1 (backend, CJS) */

function isSectionWithImageLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').trim()
  return id === 'section_with_image_v1' || id === 'section_with_image'
}

/**
 * Organic wave CSS polygon for a right-half container (x: 880..1920, y: 0..1080).
 * Bleeds cleanly to the top, right, and bottom edges, with an organic sweeping wave on the left.
 */
const ORGANIC_WAVE_POLYGON =
  'polygon(35% 0%, 100% 0%, 100% 100%, 40% 100%, 25% 90%, 12% 76%, 4% 62%, 0% 48%, 2% 35%, 8% 23%, 18% 13%, 26% 6%)'

function sectionWithImageGeom(canvasW, canvasH) {
  canvasW = canvasW || 1920
  canvasH = canvasH || 1080
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const s = Math.min(sx, sy)

  const contentX = Math.round(100 * sx)
  const contentW = Math.round(720 * sx)

  const eyebrowY = Math.round(110 * sy)
  const eyebrowW = Math.round(175 * sx)
  const eyebrowH = Math.round(32 * sy)

  const lineX = Math.round(contentX + 185 * sx)
  const lineY = Math.round(eyebrowY + 14 * sy)
  const lineW = Math.round(72 * sx)
  const lineH = Math.max(2, Math.round(2 * s))

  const headingY = Math.round(170 * sy)
  const headingH = Math.round(80 * sy)

  const bodyY = Math.round(275 * sy)
  const bodyW = Math.round(640 * sx)
  const bodyH = Math.round(150 * sy)

  const badgeY = Math.round(490 * sy)
  const badgeD = Math.round(64 * s)
  const badgeR = Math.round(badgeD / 2)

  const b1Cx = Math.round(contentX + 50 * sx)
  const b2Cx = Math.round(contentX + 210 * sx)
  const b3Cx = Math.round(contentX + 370 * sx)

  const labelY = Math.round(badgeY + badgeD + 16 * sy)
  const labelW = Math.round(120 * sx)
  const labelH = Math.round(28 * sy)

  const imgX = Math.round(880 * sx)
  const imgY = 0
  const imgW = Math.round(1040 * sx)
  const imgH = Math.round(1080 * sy)

  return {
    canvasW: canvasW, canvasH: canvasH, sx: sx, sy: sy, s: s,
    contentX: contentX, contentW: contentW,
    eyebrow: { x: contentX, y: eyebrowY, w: eyebrowW, h: eyebrowH },
    eyebrowLine: { x: lineX, y: lineY, w: lineW, h: lineH },
    heading: { x: contentX, y: headingY, w: contentW, h: headingH },
    body: { x: contentX, y: bodyY, w: contentW, h: bodyH },
    badges: {
      y: badgeY, d: badgeD, r: badgeR,
      b1: { cx: b1Cx, cy: badgeY + badgeR, labelX: Math.round(b1Cx - labelW / 2), labelY: labelY, labelW: labelW, labelH: labelH },
      b2: { cx: b2Cx, cy: badgeY + badgeR, labelX: Math.round(b2Cx - labelW / 2), labelY: labelY, labelW: labelW, labelH: labelH },
      b3: { cx: b3Cx, cy: badgeY + badgeR, labelX: Math.round(b3Cx - labelW / 2), labelY: labelY, labelW: labelW, labelH: labelH },
    },
    image: { x: imgX, y: imgY, w: imgW, h: imgH },
  }
}

function renderSectionWithImageDecorSvg(g, palette, labels) {
  palette = palette || {}
  labels = labels || {}
  const W = g.canvasW
  const H = g.canvasH
  const eyebrowLine = g.eyebrowLine
  const badges = g.badges

  const accent     = palette.accent     || palette.primary    || '#6366F1'
  const accentSoft = palette.accentSoft || palette.accentLight || '#EEF2FF'

  const b1 = badges.b1
  const b2 = badges.b2
  const b3 = badges.b3
  const bR = badges.r

  const l1 = labels.b1 || 'Clarity'
  const l2 = labels.b2 || 'Alignment'
  const l3 = labels.b3 || 'Momentum'

  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '">' +
  '<defs>' +
    '<linearGradient id="swiBackdropGrad" x1="0%" y1="0%" x2="100%" y2="100%">' +
      '<stop offset="0%" stop-color="' + accentSoft + '" stop-opacity="0.8"/>' +
      '<stop offset="100%" stop-color="' + accentSoft + '" stop-opacity="0.35"/>' +
    '</linearGradient>' +
  '</defs>' +
  '<rect x="' + eyebrowLine.x + '" y="' + eyebrowLine.y + '" width="' + eyebrowLine.w + '" height="' + eyebrowLine.h + '" rx="' + eyebrowLine.h + '" fill="' + accent + '" opacity="0.85"/>' +
  '<path d="M 1200 0 L 1920 0 L 1920 1080 L 1260 1080 C 1080 1080, 920 940, 840 760 C 760 580, 780 400, 840 260 C 900 120, 1060 0, 1200 0 Z" fill="url(#swiBackdropGrad)"/>' +
  '<path d="M 1300 0 C 1120 40, 940 160, 840 340 C 760 500, 780 700, 860 840 C 940 980, 1100 1060, 1280 1080" fill="none" stroke="' + accent + '" stroke-width="2.5" opacity="0.45" stroke-linecap="round"/>' +
  '<circle cx="' + b1.cx + '" cy="' + b1.cy + '" r="' + bR + '" fill="#EDE9FE"/>' +
  '<g transform="translate(' + (b1.cx - 14) + ', ' + (b1.cy - 14) + ') scale(1.16)" stroke="' + accent + '" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M 9 18 L 15 18 M 10 21 L 14 21 M 12 3 C 7.5 3 5 6.5 5 10.5 C 5 13 6.5 15 8 16.5 L 16 16.5 C 17.5 15 19 13 19 10.5 C 19 6.5 16.5 3 12 3 Z"/>' +
  '</g>' +
  '<text x="' + b1.cx + '" y="' + (b1.labelY + 16) + '" fill="#1E293B" font-size="18" font-weight="600" text-anchor="middle" font-family="system-ui, sans-serif">' + l1 + '</text>' +
  '<circle cx="' + b2.cx + '" cy="' + b2.cy + '" r="' + bR + '" fill="#E0F2FE"/>' +
  '<g transform="translate(' + (b2.cx - 14) + ', ' + (b2.cy - 14) + ') scale(1.16)" stroke="#0284C7" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M 17 21 V 19 C 17 17.3 15.7 16 14 16 H 6 C 4.3 16 3 17.3 3 19 V 21 M 10 12 A 4 4 0 1 0 10 4 A 4 4 0 0 0 10 12 Z M 21 21 V 19 C 20.9 17.7 20.1 16.6 18.9 16.2 M 16 4.2 C 17.2 4.6 18 5.7 18 7 C 18 8.3 17.2 9.4 16 9.8"/>' +
  '</g>' +
  '<text x="' + b2.cx + '" y="' + (b2.labelY + 16) + '" fill="#1E293B" font-size="18" font-weight="600" text-anchor="middle" font-family="system-ui, sans-serif">' + l2 + '</text>' +
  '<circle cx="' + b3.cx + '" cy="' + b3.cy + '" r="' + bR + '" fill="#FCE7F3"/>' +
  '<g transform="translate(' + (b3.cx - 14) + ', ' + (b3.cy - 14) + ') scale(1.16)" stroke="#E11D48" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M 22 7 L 13.5 15.5 L 8.5 10.5 L 2 17 M 16 7 H 22 V 13"/>' +
  '</g>' +
  '<text x="' + b3.cx + '" y="' + (b3.labelY + 16) + '" fill="#1E293B" font-size="18" font-weight="600" text-anchor="middle" font-family="system-ui, sans-serif">' + l3 + '</text>' +
'</svg>'
}

function layoutSectionWithImage(docOrElements, schema, palette, canvas) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  palette = palette || {}
  canvas = canvas || {}

  const canvasW = canvas.width  || 1920
  const canvasH = canvas.height || 1080
  const g = sectionWithImageGeom(canvasW, canvasH)

  const accent = palette.accent || palette.primary || '#6366F1'
  const textDark = '#0F172A'
  const textMuted = '#64748B'

  let headingEl = null
  let bodyEl = null
  let eyebrowEl = null
  let imageEl = null
  const otherEls = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    const role   = String(el.role || '').toLowerCase()

    if (slotId === 'HEADING' || role === 'heading' || role === 'title') {
      headingEl = el
    } else if (slotId === 'BODY' || role === 'body' || role === 'paragraph') {
      bodyEl = el
    } else if (slotId === 'EYEBROW' || slotId === 'TRACKER' || slotId === 'CATEGORY' || (role === 'subheading' && !bodyEl)) {
      eyebrowEl = el
    } else if (slotId === 'HERO_IMAGE' || slotId === 'IMAGE' || role === 'image') {
      imageEl = el
    } else if (slotId !== 'DECOR' && !String(el.id || '').includes('decor') && !/^BADGE_\d+_LABEL$/i.test(slotId)) {
      otherEls.push(el)
    }
  })

  const out = []

  // 1. Decorative SVG layer
  out.push({
    id: 'shp-section-with-image-decor',
    type: 'graphic',
    layer: 1,
    role: 'decoration',
    slotId: 'DECOR',
    placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
    content: {
      svg: renderSectionWithImageDecorSvg(g, palette),
      colorMode: 'preserve',
    },
  })

  // 2. Eyebrow Text Element
  const eyebrowText = eyebrowEl?.content?.text || 'OUR APPROACH'
  out.push(Object.assign({}, eyebrowEl || {}, {
    id: eyebrowEl?.id || 'slot-EYEBROW',
    slotId: 'EYEBROW',
    type: 'text',
    role: 'eyebrow',
    layer: 10,
    placement: {
      x: g.eyebrow.x,
      y: g.eyebrow.y,
      width: g.eyebrow.w,
      height: g.eyebrow.h,
      rotation: 0,
      opacity: 1,
    },
    content: Object.assign({}, eyebrowEl?.content || {}, {
      text: eyebrowText,
      fontSize: 18,
      fontWeight: 700,
      bold: true,
      textTransform: 'uppercase',
      letterSpacing: '0.1em',
      align: 'left',
      verticalAlign: 'center',
      color: accent,
      colorRole: 'accent',
      wrap: 'nowrap',
      clipToSlot: false,
    }),
  }))

  // 3. Heading Text Element (Single line width to prevent wrapping)
  const headingText = headingEl?.content?.text || 'Section title'
  out.push(Object.assign({}, headingEl || {}, {
    id: headingEl?.id || 'slot-HEADING',
    slotId: 'HEADING',
    type: 'text',
    role: 'heading',
    layer: 10,
    placement: {
      x: g.heading.x,
      y: g.heading.y,
      width: g.heading.w,
      height: g.heading.h,
      rotation: 0,
      opacity: 1,
    },
    content: Object.assign({}, headingEl?.content || {}, {
      text: headingText,
      fontSize: 54,
      fontWeight: 800,
      bold: true,
      align: 'left',
      verticalAlign: 'center',
      lineHeight: 1.15,
      color: textDark,
      wrap: 'nowrap',
      clipToSlot: false,
    }),
  }))

  // 4. Body Text Element
  const bodyText =
    bodyEl?.content?.text ||
    'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.'
  out.push(Object.assign({}, bodyEl || {}, {
    id: bodyEl?.id || 'slot-BODY',
    slotId: 'BODY',
    type: 'text',
    role: 'body',
    layer: 10,
    placement: {
      x: g.body.x,
      y: g.body.y,
      width: g.body.w,
      height: g.body.h,
      rotation: 0,
      opacity: 1,
    },
    content: Object.assign({}, bodyEl?.content || {}, {
      text: bodyText,
      fontSize: 22,
      fontWeight: 400,
      align: 'left',
      verticalAlign: 'top',
      lineHeight: 1.55,
      color: textMuted,
      wrap: 'pre-wrap',
      clipToSlot: false,
    }),
  }))

  // 5. Hero Image
  const existingImgContent = imageEl?.content || {}
  out.push(Object.assign({}, imageEl || {}, {
    id: imageEl?.id || 'slot-HERO_IMAGE',
    slotId: 'HERO_IMAGE',
    type: 'image',
    role: 'image',
    layer: 6,
    placement: {
      x: g.image.x,
      y: g.image.y,
      width: g.image.w,
      height: g.image.h,
      rotation: 0,
      opacity: 1,
    },
    content: Object.assign({}, existingImgContent, {
      url: existingImgContent.url || null,
      src: existingImgContent.src || null,
      fit: 'cover',
      clipPath: ORGANIC_WAVE_POLYGON,
      placeholderKind: 'clean',
      placeholderType: 'neutral',
      imageMask: { type: 'blob', side: 'right' },
    }),
  }))

  otherEls.forEach((el) => out.push(el))

  if (Array.isArray(docOrElements)) return out
  return Object.assign({}, docOrElements, { elements: out })
}

module.exports = {
  isSectionWithImageLayout: isSectionWithImageLayout,
  layoutSectionWithImage: layoutSectionWithImage,
  sectionWithImageGeom: sectionWithImageGeom,
  ORGANIC_WAVE_POLYGON: ORGANIC_WAVE_POLYGON,
}
