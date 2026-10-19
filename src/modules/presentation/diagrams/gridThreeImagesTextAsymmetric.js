/**
 * Grid three images text asymmetric — Badge, heading, subheading, three images (middle larger), three text columns (middle lower).
 * Layout id: grid_three_images_text_asymmetric_v1.
 */

const GTITA_GEOM = {
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
  
  // Three images in a row (asymmetric - middle is larger and starts at top)
  image1X: 30,
  image1Y: 165,
  image1W: 240,
  image1H: 100,
  
  image2X: 290,   // Middle image
  image2Y: 165,
  image2W: 420,   // WIDER
  image2H: 100,
  
  image3X: 730,
  image3Y: 165,
  image3W: 240,
  image3H: 100,
  
  // Three text columns below images (middle column starts lower)
  col1X: 30,
  col1Y: 280,     // Column 1 starts here
  
  col2X: 290,     // Middle column
  col2Y: 310,     // Starts LOWER (30px down)
  
  col3X: 730,
  col3Y: 280,     // Column 3 starts at same level as column 1
  
  col1W: 240,
  col2W: 420,     // Middle column is wider
  col3W: 240,
  
  colH: 240,
  
  // Inside each column
  numberY: 0,
  numberH: 30,
  
  titleY: 40,
  titleH: 32,
  
  descY: 78,
  descH: 122,
}

const GTITA_COLORS = {
  badge: '#E5E7EB',
  badgeText: '#9CA3AF',
  col1: '#10B981',  // Green
  col2: '#3B82F6',  // Blue
  col3: '#8B5CF6',  // Purple
  imagePlaceholder: '#E0F2FE',
}

const GTITA_DEFAULTS = {
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

const isGridThreeImagesTextAsymmetricLayout = (layoutId) => {
  return /grid_three_images_text_asymmetric_v1$/i.test(String(layoutId || ''))
}

const isGridThreeImagesTextAsymmetricSlot = (slotId) => {
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

const badgeSvg = () => {
  const g = GTITA_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.badgeW} ${g.badgeH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.badgeW}" height="${g.badgeH}" fill="${GTITA_COLORS.badge}" rx="4"/>
  </svg>`
}

const imagePlaceholderSvg = (w, h) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="imgGradAsym" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:#E0F2FE;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#BAE6FD;stop-opacity:1" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${w}" height="${h}" fill="url(#imgGradAsym)" rx="12"/>
    <!-- Clouds -->
    <ellipse cx="${w * 0.2}" cy="${h * 0.3}" rx="${w * 0.12}" ry="${h * 0.15}" fill="white" opacity="0.7"/>
    <ellipse cx="${w * 0.35}" cy="${h * 0.35}" rx="${w * 0.08}" ry="${h * 0.12}" fill="white" opacity="0.6"/>
    <ellipse cx="${w * 0.5}" cy="${h * 0.25}" rx="${w * 0.1}" ry="${h * 0.14}" fill="white" opacity="0.7"/>
    <ellipse cx="${w * 0.7}" cy="${h * 0.3}" rx="${w * 0.12}" ry="${h * 0.15}" fill="white" opacity="0.6"/>
    <ellipse cx="${w * 0.85}" cy="${h * 0.28}" rx="${w * 0.07}" ry="${h * 0.1}" fill="white" opacity="0.6"/>
    <!-- Hills -->
    <path d="M0 ${h * 0.7} Q${w * 0.25} ${h * 0.6} ${w * 0.5} ${h * 0.7} Q${w * 0.75} ${h * 0.6} ${w} ${h * 0.7} L${w} ${h} L0 ${h} Z" fill="#86EFAC" opacity="0.8"/>
    <path d="M0 ${h * 0.78} Q${w * 0.3} ${h * 0.68} ${w * 0.6} ${h * 0.78} Q${w * 0.9} ${h * 0.68} ${w} ${h * 0.78} L${w} ${h} L0 ${h} Z" fill="#6EE7B7" opacity="0.9"/>
  </svg>`
}

const hexLum = (hex) => {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4))
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

const headingInk = (palette = {}) => {
  const bg = palette.bg || palette.background || palette.slideBg
    || (palette.colors && (palette.colors.bg || palette.colors.background)) || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#1E293B'
}

const gridThreeImagesTextAsymmetricChromeSpecs = () => {
  const g = GTITA_GEOM
  const specs = []
  
  // Badge
  specs.push({
    slotId: 'GTITA_BADGE_BG',
    x: g.badgeX,
    y: g.badgeY,
    w: g.badgeW,
    h: g.badgeH,
    color: GTITA_COLORS.badge,
    layer: 3,
    kind: 'badge',
  })
  
  return specs
}

const gridThreeImagesTextAsymmetricOverlay = (gx, gy, gw, gh) => {
  const g = GTITA_GEOM
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
  
  // Three columns (asymmetric positions and widths)
  overlays.number1 = box(g.col1X, g.col1Y + g.numberY, g.col1W, g.numberH)
  overlays.title1 = box(g.col1X, g.col1Y + g.titleY, g.col1W, g.titleH)
  overlays.desc1 = box(g.col1X, g.col1Y + g.descY, g.col1W, g.descH)
  
  overlays.number2 = box(g.col2X, g.col2Y + g.numberY, g.col2W, g.numberH)
  overlays.title2 = box(g.col2X, g.col2Y + g.titleY, g.col2W, g.titleH)
  overlays.desc2 = box(g.col2X, g.col2Y + g.descY, g.col2W, g.descH)
  
  overlays.number3 = box(g.col3X, g.col3Y + g.numberY, g.col3W, g.numberH)
  overlays.title3 = box(g.col3X, g.col3Y + g.titleY, g.col3W, g.titleH)
  overlays.desc3 = box(g.col3X, g.col3Y + g.descY, g.col3W, g.descH)
  
  return overlays
}

const specToGridThreeImagesTextAsymmetricContent = (spec) => {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  return null
}

const plainTextFromContent = (content = {}) => {
  if (typeof content.text === 'string' && content.text.trim()) return content.text
  if (Array.isArray(content.runs)) {
    const joined = content.runs.map((r) => r.text || '').join('')
    if (joined.trim()) return joined
  }
  return ''
}

const filledContent = (el, slotId, style) => {
  const sid = String(slotId || '')
  const existing = plainTextFromContent(el?.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (GTITA_DEFAULTS[sid] || existing)
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

const newId = (prefix) => {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

const layoutGridThreeImagesTextAsymmetric = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GTITA_GEOM.viewW
  const sy = canvasH / GTITA_GEOM.viewH
  const overlay = gridThreeImagesTextAsymmetricOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GTITA_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridThreeImagesTextAsymmetricSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))
  
  // Get existing image elements
  const imageSlots = elements.filter((el) => el.type === 'image' && /^IMAGE_[123]$/.test(String(el.slotId || '')))
  const imageBySlot = new Map(imageSlots.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gtita'),
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
      id: prev?.id || newId('img-gtita'),
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
          placeholderSvg: imagePlaceholderSvg(w, h),
        }),
      },
    }
  }

  const next = [
    placeText('BADGE', overlay.badge, {
      align: 'center', verticalAlign: 'center', fontSize: 9, fontWeight: 600, color: GTITA_COLORS.badgeText, clipToSlot: true, lineHeight: 1, letterSpacing: '1.5px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 36, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.15, wrap: 'wrap',
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'subheading'),
    
    // Three image elements (asymmetric sizing)
    placeImage('IMAGE_1', GTITA_GEOM.image1X, GTITA_GEOM.image1Y, GTITA_GEOM.image1W, GTITA_GEOM.image1H),
    placeImage('IMAGE_2', GTITA_GEOM.image2X, GTITA_GEOM.image2Y, GTITA_GEOM.image2W, GTITA_GEOM.image2H),
    placeImage('IMAGE_3', GTITA_GEOM.image3X, GTITA_GEOM.image3Y, GTITA_GEOM.image3W, GTITA_GEOM.image3H),
    
    // Three columns (asymmetric positions)
    placeText('NUMBER1', overlay.number1, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 600, color: GTITA_COLORS.col1, clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('TITLE1', overlay.title1, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.3,
    }, 'heading'),
    placeText('DESC1', overlay.desc1, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    placeText('NUMBER2', overlay.number2, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 600, color: GTITA_COLORS.col2, clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('TITLE2', overlay.title2, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.3,
    }, 'heading'),
    placeText('DESC2', overlay.desc2, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    placeText('NUMBER3', overlay.number3, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 600, color: GTITA_COLORS.col3, clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('TITLE3', overlay.title3, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.3,
    }, 'heading'),
    placeText('DESC3', overlay.desc3, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
  ]

  const chrome = gridThreeImagesTextAsymmetricChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridThreeImagesTextAsymmetricContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gtita'),
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
  isGridThreeImagesTextAsymmetricLayout,
  layoutGridThreeImagesTextAsymmetric,
  GTITA_GEOM,
  GTITA_DEFAULTS,
};
