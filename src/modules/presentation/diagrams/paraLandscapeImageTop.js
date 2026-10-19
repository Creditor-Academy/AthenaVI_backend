'use strict'
/**
 * Para Landscape Image Top Layout (backend, CJS)
 * 
 * Structure:
 * - Large landscape image at top
 * - Eyebrow text below image
 * - Main heading
 * - Body paragraph
 */

function isParaLandscapeImageTopLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').trim()
  return id === 'para_landscape_image_top' || id === 'para_landscape_top' || id === 'para_landscape_image_top_v1'
}

/**
 * Geometry definitions on a 1920×1080 canvas
 */
function paraLandscapeImageTopGeom(canvasW, canvasH) {
  canvasW = canvasW || 1920
  canvasH = canvasH || 1080
  const sx = canvasW / 1920
  const sy = canvasH / 1080

  const contentX = Math.round(80 * sx)
  const contentW = Math.round(1200 * sx)

  // Landscape image at top
  const imgX = Math.round(80 * sx)
  const imgY = Math.round(60 * sy)
  const imgW = Math.round(1760 * sx)
  const imgH = Math.round(320 * sy)

  // Eyebrow below image
  const eyebrowY = Math.round(420 * sy)
  const eyebrowW = Math.round(320 * sx)
  const eyebrowH = Math.round(28 * sy)

  const lineX = Math.round(contentX + 330 * sx)
  const lineY = Math.round(eyebrowY + 12 * sy)
  const lineW = Math.round(80 * sx)
  const lineH = Math.max(3, Math.round(3 * sy))

  // Heading below eyebrow - single line
  const headingY = Math.round(470 * sy)
  const headingH = Math.round(72 * sy)

  // Body paragraph - moved much lower to avoid overlap
  const bodyY = Math.round(660 * sy)
  const bodyW = Math.round(1600 * sx)
  const bodyH = Math.round(120 * sy)

  return {
    canvasW: canvasW,
    canvasH: canvasH,
    sx: sx,
    sy: sy,
    contentX: contentX,
    contentW: contentW,
    image: { x: imgX, y: imgY, w: imgW, h: imgH },
    eyebrow: { x: contentX, y: eyebrowY, w: eyebrowW, h: eyebrowH },
    eyebrowLine: { x: lineX, y: lineY, w: lineW, h: lineH },
    heading: { x: contentX, y: headingY, w: contentW, h: headingH },
    body: { x: contentX, y: bodyY, w: bodyW, h: bodyH },
  }
}

/**
 * Decorative SVG (eyebrow line only)
 */
function renderParaLandscapeTopDecorSvg(g, palette) {
  palette = palette || {}
  const W = g.canvasW
  const H = g.canvasH
  const eyebrowLine = g.eyebrowLine
  const accent = palette.accent || palette.primary || '#8B5CF6'

  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '">' +
    '<!-- Eyebrow accent line -->' +
    '<rect x="' + eyebrowLine.x + '" y="' + eyebrowLine.y + '" width="' + eyebrowLine.w + '" height="' + eyebrowLine.h + '" rx="' + (eyebrowLine.h / 2) + '" fill="' + accent + '" opacity="0.85"/>' +
    '</svg>'
}

/**
 * Enhanced landscape image placeholder - same as bottom version
 */
function landscapeImagePlaceholderSvg(w, h) {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + w + ' ' + h + '" width="100%" height="100%" preserveAspectRatio="xMidYMid slice">' +
    '<defs>' +
    '<linearGradient id="plitSkyGrad" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#A5D8FF;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#D0EBFF;stop-opacity:1" />' +
    '</linearGradient>' +
    '<linearGradient id="plitHillGrad1" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#8CE99A;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#69DB7C;stop-opacity:1" />' +
    '</linearGradient>' +
    '<linearGradient id="plitHillGrad2" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#51CF66;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#37B24D;stop-opacity:1" />' +
    '</linearGradient>' +
    '<linearGradient id="plitHillGrad3" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#2F9E44;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#2B8A3E;stop-opacity:1" />' +
    '</linearGradient>' +
    '</defs>' +
    '<rect x="0" y="0" width="' + w + '" height="' + h + '" fill="url(#plitSkyGrad)"/>' +
    '<g opacity="0.95">' +
    '<ellipse cx="' + (w * 0.15) + '" cy="' + (h * 0.22) + '" rx="' + (w * 0.14) + '" ry="' + (h * 0.14) + '" fill="white"/>' +
    '<ellipse cx="' + (w * 0.21) + '" cy="' + (h * 0.2) + '" rx="' + (w * 0.11) + '" ry="' + (h * 0.11) + '" fill="white"/>' +
    '<ellipse cx="' + (w * 0.18) + '" cy="' + (h * 0.26) + '" rx="' + (w * 0.09) + '" ry="' + (h * 0.09) + '" fill="white"/>' +
    '<ellipse cx="' + (w * 0.12) + '" cy="' + (h * 0.25) + '" rx="' + (w * 0.08) + '" ry="' + (h * 0.08) + '" fill="white"/>' +
    '</g>' +
    '<g opacity="0.9">' +
    '<ellipse cx="' + (w * 0.78) + '" cy="' + (h * 0.18) + '" rx="' + (w * 0.12) + '" ry="' + (h * 0.12) + '" fill="white"/>' +
    '<ellipse cx="' + (w * 0.83) + '" cy="' + (h * 0.16) + '" rx="' + (w * 0.1) + '" ry="' + (h * 0.1) + '" fill="white"/>' +
    '<ellipse cx="' + (w * 0.8) + '" cy="' + (h * 0.22) + '" rx="' + (w * 0.08) + '" ry="' + (h * 0.08) + '" fill="white"/>' +
    '</g>' +
    '<ellipse cx="' + (w * 0.08) + '" cy="' + (h * 0.58) + '" rx="' + (w * 0.04) + '" ry="' + (h * 0.12) + '" fill="#40C057" opacity="0.6"/>' +
    '<ellipse cx="' + (w * 0.12) + '" cy="' + (h * 0.6) + '" rx="' + (w * 0.035) + '" ry="' + (h * 0.1) + '" fill="#2F9E44" opacity="0.7"/>' +
    '<ellipse cx="' + (w * 0.92) + '" cy="' + (h * 0.6) + '" rx="' + (w * 0.045) + '" ry="' + (h * 0.13) + '" fill="#40C057" opacity="0.6"/>' +
    '<ellipse cx="' + (w * 0.88) + '" cy="' + (h * 0.62) + '" rx="' + (w * 0.04) + '" ry="' + (h * 0.11) + '" fill="#2F9E44" opacity="0.7"/>' +
    '<path d="M0 ' + (h * 0.52) + ' Q' + (w * 0.15) + ' ' + (h * 0.42) + ' ' + (w * 0.3) + ' ' + (h * 0.48) + ' Q' + (w * 0.5) + ' ' + (h * 0.44) + ' ' + (w * 0.7) + ' ' + (h * 0.5) + ' Q' + (w * 0.85) + ' ' + (h * 0.46) + ' ' + w + ' ' + (h * 0.52) + ' L' + w + ' ' + h + ' L0 ' + h + ' Z" fill="url(#plitHillGrad1)" opacity="0.7"/>' +
    '<path d="M0 ' + (h * 0.62) + ' Q' + (w * 0.2) + ' ' + (h * 0.52) + ' ' + (w * 0.4) + ' ' + (h * 0.58) + ' Q' + (w * 0.6) + ' ' + (h * 0.54) + ' ' + (w * 0.8) + ' ' + (h * 0.6) + ' Q' + (w * 0.9) + ' ' + (h * 0.57) + ' ' + w + ' ' + (h * 0.63) + ' L' + w + ' ' + h + ' L0 ' + h + ' Z" fill="url(#plitHillGrad2)"/>' +
    '<path d="M0 ' + (h * 0.73) + ' Q' + (w * 0.25) + ' ' + (h * 0.65) + ' ' + (w * 0.5) + ' ' + (h * 0.7) + ' Q' + (w * 0.75) + ' ' + (h * 0.66) + ' ' + w + ' ' + (h * 0.74) + ' L' + w + ' ' + h + ' L0 ' + h + ' Z" fill="url(#plitHillGrad3)"/>' +
    '</svg>'
}

/**
 * Layout entry point
 */
function layoutParaLandscapeImageTop(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements

  canvas = canvas || {}
  palette = palette || {}

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = paraLandscapeImageTopGeom(canvasW, canvasH)

  const accent = palette.accent || palette.primary || '#8B5CF6'
  const textDark = '#1E293B'

  let headingEl = null
  let bodyEl = null
  let eyebrowEl = null
  let imageEl = null
  const otherEls = []

  elements.forEach(function (el) {
    const slotId = String(el.slotId || '').toUpperCase()
    const role = String(el.role || '').toLowerCase()

    if (slotId === 'HEADING' || role === 'heading' || role === 'title') {
      headingEl = el
    } else if (slotId === 'BODY' || role === 'body' || role === 'paragraph') {
      bodyEl = el
    } else if (slotId === 'EYEBROW' || slotId === 'TRACKER' || slotId === 'CATEGORY' || role === 'subheading') {
      eyebrowEl = el
    } else if (slotId === 'IMAGE' || slotId === 'LANDSCAPE_IMAGE' || slotId === 'HERO_IMAGE' || role === 'image') {
      imageEl = el
    } else if (slotId !== 'DECOR' && !String(el.id || '').includes('decor') && !/^BADGE_\d+_LABEL$/i.test(slotId)) {
      otherEls.push(el)
    }
  })

  const out = []

  // 1. Landscape image at top
  const existingImgContent = (imageEl && imageEl.content) || {}
  const hasImage = !!(existingImgContent.url || existingImgContent.src)
  const imgPlaceholder = hasImage ? {} : { placeholderSvg: landscapeImagePlaceholderSvg(g.image.w, g.image.h) }
  
  out.push(Object.assign({}, imageEl || {}, {
    id: (imageEl && imageEl.id) || 'slot-LANDSCAPE_IMAGE',
    slotId: 'LANDSCAPE_IMAGE',
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
      borderRadius: 20,
    }, imgPlaceholder),
  }))

  // 2. Decorative SVG layer
  out.push({
    id: 'shp-para-landscape-top-decor',
    type: 'graphic',
    layer: 1,
    role: 'decoration',
    slotId: 'DECOR',
    placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
    content: {
      svg: renderParaLandscapeTopDecorSvg(g, palette),
      colorMode: 'preserve',
    },
  })

  // 3. Eyebrow
  const eyebrowText = (eyebrowEl && eyebrowEl.content && eyebrowEl.content.text) || 'OUR APPROACH'
  out.push(Object.assign({}, eyebrowEl || {}, {
    id: (eyebrowEl && eyebrowEl.id) || 'slot-EYEBROW',
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
    content: Object.assign({}, (eyebrowEl && eyebrowEl.content) || {}, {
      text: eyebrowText,
      fontSize: 14,
      fontWeight: 700,
      bold: true,
      textTransform: 'uppercase',
      letterSpacing: '0.15em',
      align: 'left',
      verticalAlign: 'center',
      color: accent,
      colorRole: 'accent',
      wrap: 'nowrap',
      clipToSlot: true,
    }),
  }))

  // 4. Heading
  const headingText = (headingEl && headingEl.content && headingEl.content.text) || 'Describe this slide'
  out.push(Object.assign({}, headingEl || {}, {
    id: (headingEl && headingEl.id) || 'slot-HEADING',
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
    content: Object.assign({}, (headingEl && headingEl.content) || {}, {
      text: headingText,
      fontSize: 60,
      fontWeight: 800,
      bold: true,
      align: 'left',
      verticalAlign: 'top',
      lineHeight: 1.0,
      color: textDark,
      wrap: 'nowrap',
      clipToSlot: true,
    }),
  }))

  // 5. Body paragraph
  const bodyText =
    (bodyEl && bodyEl.content && bodyEl.content.text) ||
    'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.'
  out.push(Object.assign({}, bodyEl || {}, {
    id: (bodyEl && bodyEl.id) || 'slot-BODY',
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
    content: Object.assign({}, (bodyEl && bodyEl.content) || {}, {
      text: bodyText,
      fontSize: 18,
      fontWeight: 400,
      align: 'left',
      verticalAlign: 'top',
      lineHeight: 1.5,
      color: '#9CA3AF',
      wrap: 'normal',
      clipToSlot: true,
    }),
  }))

  otherEls.forEach(function (el) {
    out.push(el)
  })

  return out
}

module.exports = {
  isParaLandscapeImageTopLayout: isParaLandscapeImageTopLayout,
  layoutParaLandscapeImageTop: layoutParaLandscapeImageTop,
  paraLandscapeImageTopGeom: paraLandscapeImageTopGeom,
}
