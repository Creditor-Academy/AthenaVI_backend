'use strict'
/**
 * Para Landscape Image Bottom Layout (backend, CJS)
 * 
 * Structure:
 * - Eyebrow text at top
 * - Main heading
 * - Body paragraph
 * - Wide landscape image at bottom with rounded corners
 */

function isParaLandscapeImageBottomLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').trim()
  return id === 'para_landscape_image_bottom' || id === 'para_landscape_bottom' || id === 'para_landscape_image_bottom_v1'
}

/**
 * Geometry definitions on a 1920×1080 canvas
 */
function paraLandscapeImageBottomGeom(canvasW, canvasH) {
  canvasW = canvasW || 1920
  canvasH = canvasH || 1080
  const sx = canvasW / 1920
  const sy = canvasH / 1080

  const contentX = Math.round(80 * sx)
  const contentW = Math.round(1760 * sx)

  // Eyebrow at top with line - extra wide to fit full "OUR APPROACH"
  const eyebrowY = Math.round(80 * sy)
  const eyebrowW = Math.round(320 * sx)
  const eyebrowH = Math.round(28 * sy)

  const lineX = Math.round(contentX + 330 * sx)
  const lineY = Math.round(eyebrowY + 12 * sy)
  const lineW = Math.round(80 * sx)
  const lineH = Math.max(3, Math.round(3 * sy))

  // Heading - large and bold
  const headingY = Math.round(130 * sy)
  const headingH = Math.round(80 * sy)

  // Body paragraph - moved down more to avoid overlap
  const bodyY = Math.round(260 * sy)
  const bodyW = Math.round(1400 * sx)
  const bodyH = Math.round(70 * sy)

  // Landscape image at bottom - smaller height, moved down more
  const imgX = Math.round(80 * sx)
  const imgY = Math.round(400 * sy)
  const imgW = Math.round(1760 * sx)
  const imgH = Math.round(560 * sy)

  // Decorative circles on right
  const circle1 = { cx: Math.round(1800 * sx), cy: Math.round(100 * sy), r: Math.round(40 * sx) }
  const circle2 = { cx: Math.round(1750 * sx), cy: Math.round(80 * sy), r: Math.round(25 * sx) }

  return {
    canvasW: canvasW,
    canvasH: canvasH,
    sx: sx,
    sy: sy,
    contentX: contentX,
    contentW: contentW,
    eyebrow: { x: contentX, y: eyebrowY, w: eyebrowW, h: eyebrowH },
    eyebrowLine: { x: lineX, y: lineY, w: lineW, h: lineH },
    heading: { x: contentX, y: headingY, w: contentW, h: headingH },
    body: { x: contentX, y: bodyY, w: bodyW, h: bodyH },
    image: { x: imgX, y: imgY, w: imgW, h: imgH },
    circle1: circle1,
    circle2: circle2,
  }
}

/**
 * Decorative SVG (eyebrow accent line + decorative circles)
 */
function renderParaLandscapeDecorSvg(g, palette) {
  palette = palette || {}
  const W = g.canvasW
  const H = g.canvasH
  const eyebrowLine = g.eyebrowLine
  const circle1 = g.circle1
  const circle2 = g.circle2
  const accent = palette.accent || palette.primary || '#8B5CF6'

  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '">' +
    '<!-- Eyebrow accent line -->' +
    '<rect x="' + eyebrowLine.x + '" y="' + eyebrowLine.y + '" width="' + eyebrowLine.w + '" height="' + eyebrowLine.h + '" rx="' + (eyebrowLine.h / 2) + '" fill="' + accent + '" opacity="0.85"/>' +
    '<!-- Decorative circles on right -->' +
    '<circle cx="' + circle1.cx + '" cy="' + circle1.cy + '" r="' + circle1.r + '" fill="' + accent + '" opacity="0.15"/>' +
    '<circle cx="' + circle2.cx + '" cy="' + circle2.cy + '" r="' + circle2.r + '" fill="' + accent + '" opacity="0.25"/>' +
    '</svg>'
}

/**
 * Image placeholder SVG
 */
function landscapeImagePlaceholderSvg(w, h) {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + w + ' ' + h + '" width="100%" height="100%" preserveAspectRatio="xMidYMid slice">' +
    '<defs>' +
    '<linearGradient id="plibSkyGrad" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#A5B4FC;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#DDD6FE;stop-opacity:1" />' +
    '</linearGradient>' +
    '<linearGradient id="plibHillGrad1" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#86EFAC;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#4ADE80;stop-opacity:1" />' +
    '</linearGradient>' +
    '<linearGradient id="plibHillGrad2" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#6EE7B7;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#34D399;stop-opacity:1" />' +
    '</linearGradient>' +
    '<linearGradient id="plibHillGrad3" x1="0%" y1="0%" x2="0%" y2="100%">' +
    '<stop offset="0%" style="stop-color:#5EEAD4;stop-opacity:1" />' +
    '<stop offset="100%" style="stop-color:#2DD4BF;stop-opacity:1" />' +
    '</linearGradient>' +
    '</defs>' +
    '<!-- Sky -->' +
    '<rect x="0" y="0" width="' + w + '" height="' + h + '" fill="url(#plibSkyGrad)"/>' +
    '<!-- Clouds -->' +
    '<g opacity="0.9">' +
    '<ellipse cx="' + (w * 0.15) + '" cy="' + (h * 0.2) + '" rx="' + (w * 0.12) + '" ry="' + (h * 0.12) + '" fill="white" opacity="0.9"/>' +
    '<ellipse cx="' + (w * 0.2) + '" cy="' + (h * 0.18) + '" rx="' + (w * 0.09) + '" ry="' + (h * 0.09) + '" fill="white" opacity="0.9"/>' +
    '<ellipse cx="' + (w * 0.17) + '" cy="' + (h * 0.24) + '" rx="' + (w * 0.07) + '" ry="' + (h * 0.07) + '" fill="white" opacity="0.85"/>' +
    '</g>' +
    '<g opacity="0.85">' +
    '<ellipse cx="' + (w * 0.75) + '" cy="' + (h * 0.15) + '" rx="' + (w * 0.1) + '" ry="' + (h * 0.1) + '" fill="white" opacity="0.9"/>' +
    '<ellipse cx="' + (w * 0.79) + '" cy="' + (h * 0.13) + '" rx="' + (w * 0.08) + '" ry="' + (h * 0.08) + '" fill="white" opacity="0.9"/>' +
    '</g>' +
    '<!-- Distant hills -->' +
    '<path d="M0 ' + (h * 0.55) + ' Q' + (w * 0.2) + ' ' + (h * 0.45) + ' ' + (w * 0.4) + ' ' + (h * 0.52) + ' Q' + (w * 0.6) + ' ' + (h * 0.48) + ' ' + (w * 0.8) + ' ' + (h * 0.54) + ' Q' + (w * 0.9) + ' ' + (h * 0.5) + ' ' + w + ' ' + (h * 0.55) + ' L' + w + ' ' + h + ' L0 ' + h + ' Z" fill="url(#plibHillGrad1)" opacity="0.6"/>' +
    '<!-- Mid hills -->' +
    '<path d="M0 ' + (h * 0.65) + ' Q' + (w * 0.25) + ' ' + (h * 0.55) + ' ' + (w * 0.5) + ' ' + (h * 0.63) + ' Q' + (w * 0.75) + ' ' + (h * 0.58) + ' ' + w + ' ' + (h * 0.67) + ' L' + w + ' ' + h + ' L0 ' + h + ' Z" fill="url(#plibHillGrad2)" opacity="0.85"/>' +
    '<!-- Foreground hills -->' +
    '<path d="M0 ' + (h * 0.75) + ' Q' + (w * 0.3) + ' ' + (h * 0.65) + ' ' + (w * 0.6) + ' ' + (h * 0.73) + ' Q' + (w * 0.85) + ' ' + (h * 0.68) + ' ' + w + ' ' + (h * 0.77) + ' L' + w + ' ' + h + ' L0 ' + h + ' Z" fill="url(#plibHillGrad3)"/>' +
    '<!-- Trees/vegetation silhouettes -->' +
    '<ellipse cx="' + (w * 0.08) + '" cy="' + (h * 0.78) + '" rx="' + (w * 0.025) + '" ry="' + (h * 0.08) + '" fill="#059669" opacity="0.7"/>' +
    '<ellipse cx="' + (w * 0.15) + '" cy="' + (h * 0.82) + '" rx="' + (w * 0.03) + '" ry="' + (h * 0.1) + '" fill="#047857" opacity="0.6"/>' +
    '<ellipse cx="' + (w * 0.88) + '" cy="' + (h * 0.8) + '" rx="' + (w * 0.028) + '" ry="' + (h * 0.09) + '" fill="#059669" opacity="0.7"/>' +
    '<ellipse cx="' + (w * 0.93) + '" cy="' + (h * 0.83) + '" rx="' + (w * 0.032) + '" ry="' + (h * 0.11) + '" fill="#047857" opacity="0.65"/>' +
    '</svg>'
}

/**
 * Layout entry point
 */
function layoutParaLandscapeImageBottom(elements, schema, palette, canvas) {
  if (!Array.isArray(elements)) return elements

  canvas = canvas || {}
  palette = palette || {}

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = paraLandscapeImageBottomGeom(canvasW, canvasH)

  const accent = palette.accent || palette.primary || '#8B5CF6'
  const textDark = '#1E293B'
  const textMuted = '#64748B'

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
    } else if (slotId === 'IMAGE' || slotId === 'LANDSCAPE_IMAGE' || role === 'image') {
      imageEl = el
    } else if (slotId !== 'DECOR' && !String(el.id || '').includes('decor')) {
      otherEls.push(el)
    }
  })

  const out = []

  // 1. Decorative SVG layer (eyebrow line)
  out.push({
    id: 'shp-para-landscape-decor',
    type: 'graphic',
    layer: 1,
    role: 'decoration',
    slotId: 'DECOR',
    placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
    content: {
      svg: renderParaLandscapeDecorSvg(g, palette),
      colorMode: 'preserve',
    },
  })

  // 2. Eyebrow - visible with accent color
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

  // 3. Heading - large, bold, dark
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
      lineHeight: 1.15,
      color: '#1E293B',
      wrap: 'normal',
      clipToSlot: true,
    }),
  }))

  // 4. Body paragraph - lighter, more subtle
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

  // 5. Landscape image at bottom - larger, more prominent
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

  otherEls.forEach(function (el) {
    out.push(el)
  })

  return out
}

module.exports = {
  isParaLandscapeImageBottomLayout: isParaLandscapeImageBottomLayout,
  layoutParaLandscapeImageBottom: layoutParaLandscapeImageBottom,
  paraLandscapeImageBottomGeom: paraLandscapeImageBottomGeom,
}
