/**
 * Grid three images text — Badge, heading, subheading, three images, three text columns.
 * Layout id: grid_three_images_text_v1.
 */

const GTIT_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Badge at top left
  badgeX: 50,
  badgeY: 40,
  badgeW: 140,
  badgeH: 20,
  
  // Heading (left side)
  headingX: 50,
  headingY: 70,
  headingW: 380,
  headingH: 80,
  
  // Subheading (right side)
  subheadingX: 460,
  subheadingY: 70,
  subheadingW: 490,
  subheadingH: 80,
  
  // Three images in a row
  image1X: 50,
  image2X: 350,
  image3X: 650,
  imageY: 165,
  imageW: 280,
  imageH: 130,
  imageGap: 20,
  
  // Three text columns below images
  col1X: 50,
  col2X: 350,
  col3X: 650,
  colY: 320,
  colW: 280,
  colH: 200,
  
  // Inside each column
  numberY: 0,
  numberH: 30,
  
  titleY: 40,
  titleH: 32,
  
  descY: 78,
  descH: 122,
}

const GTIT_COLORS = {
  badge: '#E5E7EB',
  badgeText: '#9CA3AF',
  col1: '#10B981',  // Green
  col2: '#3B82F6',  // Blue
  col3: '#8B5CF6',  // Purple
  imagePlaceholder: '#E0F2FE',
}

const GTIT_DEFAULTS = {
  BADGE: 'OUR APPROACH',
  HEADING: 'Turning ideas into real impact',
  SUBHEADING: 'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.',
  
  NUMBER1: '01',
  TITLE1: 'Clear strategy',
  DESC1: 'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.',
  
  NUMBER2: '02',
  TITLE2: 'Thoughtful execution',
  DESC2: 'Our approach combines research, design, and storytelling so every slide earns attention and every message lands with precision.',
  
  NUMBER3: '03',
  TITLE3: 'Lasting results',
  DESC3: 'From first draft to final delivery, we keep copy concise, visual, and aligned to your audience and goals.',
}

function isGridThreeImagesTextLayout(layoutId) {
  return /grid_three_images_text_v1$/i.test(String(layoutId || ''))
}

function isGridThreeImagesTextSlot(slotId) {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'NUMBER1'
    || sid === 'TITLE1'
    || sid === 'DESC1'
    || sid === 'NUMBER2'
    || sid === 'TITLE2'
    || sid === 'DESC2'
    || sid === 'NUMBER3'
    || sid === 'TITLE3'
    || sid === 'DESC3'
}

function badgeSvg() {
  const g = GTIT_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.badgeW} ${g.badgeH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.badgeW}" height="${g.badgeH}" fill="${GTIT_COLORS.badge}" rx="4"/>
  </svg>`
}

function imagePlaceholderSvg() {
  const g = GTIT_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.imageW} ${g.imageH}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="imgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:#E0F2FE;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#BAE6FD;stop-opacity:1" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${g.imageW}" height="${g.imageH}" fill="url(#imgGrad)" rx="12"/>
    <!-- Clouds -->
    <ellipse cx="80" cy="30" rx="35" ry="15" fill="white" opacity="0.7"/>
    <ellipse cx="120" cy="35" rx="25" ry="12" fill="white" opacity="0.6"/>
    <ellipse cx="200" cy="25" rx="30" ry="14" fill="white" opacity="0.7"/>
    <ellipse cx="240" cy="30" rx="20" ry="10" fill="white" opacity="0.6"/>
    <!-- Hills -->
    <path d="M0 90 Q70 60 140 90 Q210 60 280 90 L280 130 L0 130 Z" fill="#86EFAC" opacity="0.8"/>
    <path d="M0 100 Q90 75 180 100 Q270 75 360 100 L360 130 L0 130 Z" fill="#6EE7B7" opacity="0.9"/>
  </svg>`
}

function hexLum(hex) {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4))
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette = {}) {
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#1E293B'
}

function gridThreeImagesTextChromeSpecs() {
  const g = GTIT_GEOM
  const specs = []
  
  // Badge
  specs.push({
    slotId: 'GTIT_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: GTIT_COLORS.badge,
    layer: 3,
    kind: 'badge',
  })
  
  return specs
}

function gridThreeImagesTextOverlay(gx, gy, gw, gh) {
  const g = GTIT_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const overlays = {
    badge: box(g.badgeX, g.badgeY, g.badgeW, g.badgeH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subheadingX, g.subheadingY, g.subheadingW, g.subheadingH),
  }
  
  // Three columns
  const colXs = [g.col1X, g.col2X, g.col3X]
  colXs.forEach((colX, i) => {
    const num = i + 1
    overlays[`number${num}`] = box(colX, g.colY + g.numberY, g.colW, g.numberH)
    overlays[`title${num}`] = box(colX, g.colY + g.titleY, g.colW, g.titleH)
    overlays[`desc${num}`] = box(colX, g.colY + g.descY, g.colW, g.descH)
  })
  
  return overlays
}

function specToGridThreeImagesTextContent(spec) {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  return null
}

function plainTextFromContent(content = {}) {
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map((r) => r.text || '').join('')
    if (joined.trim()) return joined
  }
  return ''
}

function filledContent(el, slotId, style) {
  const sid = String(slotId || '')
  const existing = plainTextFromContent(el?.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (GTIT_DEFAULTS[sid] || existing)
  return {
    ...(el?.content || {}),
    ...style,
    text,
    runs: null,
    listType: null,
    letterSpacing: style.letterSpacing !== undefined ? style.letterSpacing : '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  }
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutGridThreeImagesText(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GTIT_GEOM.viewW
  const sy = canvasH / GTIT_GEOM.viewH
  const overlay = gridThreeImagesTextOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GTIT_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridThreeImagesTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))
  
  // Get existing image elements
  const imageSlots = elements.filter((el) => el.type === 'image' && /^IMAGE_[123]$/.test(String(el.slotId || '')))
  const imageBySlot = new Map(imageSlots.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gtit'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }
  
  const placeImage = (slotId, x, y, w, h) => {
    const prev = imageBySlot.get(slotId)
    const hasImage = prev?.content?.url || prev?.content?.src
    return {
      id: prev?.id || newId('img-gtit'),
      type: 'image',
      slotId,
      role: 'image',
      layer: 5,
      placement: {
        x: Math.round(x * sx),
        y: Math.round(y * sy),
        width: Math.round(w * sx),
        height: Math.round(h * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        url: prev?.content?.url || null,
        src: prev?.content?.src || null,
        fit: 'cover',
        borderRadius: 12,
        name: prev?.content?.name || slotId,
        ...(hasImage ? {} : {
          placeholderSvg: imagePlaceholderSvg(),
        }),
      },
    }
  }

  const next = [
    placeText('BADGE', overlay.badge, {
      align: 'center', verticalAlign: 'center', fontSize: 9, fontWeight: 600, color: GTIT_COLORS.badgeText, clipToSlot: true, lineHeight: 1, letterSpacing: '1.5px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 36, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.15, wrap: 'wrap',
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'subheading'),
    
    // Three image elements
    placeImage('IMAGE_1', GTIT_GEOM.image1X, GTIT_GEOM.imageY, GTIT_GEOM.imageW, GTIT_GEOM.imageH),
    placeImage('IMAGE_2', GTIT_GEOM.image2X, GTIT_GEOM.imageY, GTIT_GEOM.imageW, GTIT_GEOM.imageH),
    placeImage('IMAGE_3', GTIT_GEOM.image3X, GTIT_GEOM.imageY, GTIT_GEOM.imageW, GTIT_GEOM.imageH),
  ]
  
  // Three columns
  const colors = [GTIT_COLORS.col1, GTIT_COLORS.col2, GTIT_COLORS.col3]
  for (let i = 1; i <= 3; i++) {
    next.push(
      placeText(`NUMBER${i}`, overlay[`number${i}`], {
        align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 600, color: colors[i-1], clipToSlot: true, lineHeight: 1.2,
      }, 'caption'),
      placeText(`TITLE${i}`, overlay[`title${i}`], {
        align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.3,
      }, 'heading'),
      placeText(`DESC${i}`, overlay[`desc${i}`], {
        align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
      }, 'body')
    )
  }

  const chrome = gridThreeImagesTextChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridThreeImagesTextContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gtit'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement: {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.max(4, Math.round(spec.w * sx)),
        height: Math.max(4, Math.round(spec.h * sy)),
        rotation: 0,
        opacity: 1,
      },
      content: { svg: graphic.svg, colorMode: graphic.colorMode, fill: graphic.fill, alt: spec.slotId },
      role: 'decoration',
      slotId: spec.slotId,
    }
  }).filter(Boolean)
  
  return [...chrome, ...next]
}

module.exports = {
  isGridThreeImagesTextLayout,
  layoutGridThreeImagesText,
  GTIT_GEOM,
  GTIT_DEFAULTS,
}
