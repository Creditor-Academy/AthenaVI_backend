/**
 * Grid images text cards — Three columns with images and text, each in a card container.
 * Layout id: grid_images_text_cards_v1.
 */

const GITC_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Three card containers
  card1X: 30,
  card2X: 350,
  card3X: 670,
  cardY: 40,
  cardW: 300,
  cardH: 500,
  cardGap: 20,
  cardRadius: 16,
  cardPadding: 20,
  
  // Inside each card
  imageY: 20,      // From top of card
  imageH: 180,
  imageRadius: 12,
  
  titleY: 220,     // From top of card
  titleH: 36,
  
  bodyY: 266,      // From top of card
  bodyH: 214,
}

const GITC_COLORS = {
  card: '#FFFFFF',
  cardBorder: '#E2E8F0',
  cardShadow: '0 4px 20px rgba(15, 23, 42, 0.08)',
  imagePlaceholder: '#E0F2FE',
}

const GITC_DEFAULTS = {
  COL_1_TITLE: 'Feature A',
  COL_1_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  
  COL_2_TITLE: 'Feature B',
  COL_2_BODY: 'Clear and concise description that helps the audience understand the core value proposition at a glance.',
  
  COL_3_TITLE: 'Feature C',
  COL_3_BODY: 'Essential highlights and benefits presented in a way that builds momentum and reinforces the narrative.',
}

const isGridImagesTextCardsLayout = (layoutId) => {
  return /grid_images_text_cards_v1$/i.test(String(layoutId || ''))
}

const isGridImagesTextCardsSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'COL_1_TITLE'
    || sid === 'COL_1_BODY'
    || sid === 'COL_2_TITLE'
    || sid === 'COL_2_BODY'
    || sid === 'COL_3_TITLE'
    || sid === 'COL_3_BODY'
}

const cardSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="cardShadow" x="-50%" y="-50%" width="200%" height="200%">
        <feGaussianBlur in="SourceAlpha" stdDeviation="3"/>
        <feOffset dx="0" dy="2" result="offsetblur"/>
        <feComponentTransfer>
          <feFuncA type="linear" slope="0.15"/>
        </feComponentTransfer>
        <feMerge>
          <feMergeNode/>
          <feMergeNode in="SourceGraphic"/>
        </feMerge>
      </filter>
    </defs>
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GITC_COLORS.card}" stroke="${GITC_COLORS.cardBorder}" stroke-width="1" rx="${radius}" filter="url(#cardShadow)"/>
  </svg>`
}

const imagePlaceholderSvg = (w, h) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="imgGradCards" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:#E0F2FE;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#BAE6FD;stop-opacity:1" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${w}" height="${h}" fill="url(#imgGradCards)" rx="12"/>
    <!-- Clouds -->
    <ellipse cx="${w * 0.2}" cy="${h * 0.25}" rx="${w * 0.12}" ry="${h * 0.1}" fill="white" opacity="0.7"/>
    <ellipse cx="${w * 0.4}" cy="${h * 0.3}" rx="${w * 0.08}" ry="${h * 0.08}" fill="white" opacity="0.6"/>
    <ellipse cx="${w * 0.6}" cy="${h * 0.2}" rx="${w * 0.1}" ry="${h * 0.09}" fill="white" opacity="0.7"/>
    <ellipse cx="${w * 0.8}" cy="${h * 0.25}" rx="${w * 0.07}" ry="${h * 0.07}" fill="white" opacity="0.6"/>
    <!-- Hills -->
    <path d="M0 ${h * 0.65} Q${w * 0.25} ${h * 0.55} ${w * 0.5} ${h * 0.65} Q${w * 0.75} ${h * 0.55} ${w} ${h * 0.65} L${w} ${h} L0 ${h} Z" fill="#86EFAC" opacity="0.8"/>
    <path d="M0 ${h * 0.75} Q${w * 0.3} ${h * 0.65} ${w * 0.6} ${h * 0.75} Q${w * 0.9} ${h * 0.65} ${w} ${h * 0.75} L${w} ${h} L0 ${h} Z" fill="#6EE7B7" opacity="0.9"/>
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

const gridImagesTextCardsChromeSpecs = () => {
  const g = GITC_GEOM
  const specs = []
  
  // Three card containers
  const cardXs = [g.card1X, g.card2X, g.card3X]
  cardXs.forEach((x, i) => {
    specs.push({
      slotId: `GITC_CARD${i+1}_BG`,
      x: x,
      y: g.cardY,
      w: g.cardW,
      h: g.cardH,
      color: GITC_COLORS.card,
      layer: 2,
      kind: 'card',
    })
  })
  
  return specs
}

const gridImagesTextCardsOverlay = (gx, gy, gw, gh) => {
  const g = GITC_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const overlays = {}
  
  // Three columns
  const cardXs = [g.card1X, g.card2X, g.card3X]
  const imageW = g.cardW - (g.cardPadding * 2)
  
  cardXs.forEach((cardX, i) => {
    const num = i + 1
    const innerX = cardX + g.cardPadding
    const cardTopY = g.cardY
    
    overlays[`title${num}`] = box(innerX, cardTopY + g.titleY, imageW, g.titleH)
    overlays[`body${num}`] = box(innerX, cardTopY + g.bodyY, imageW, g.bodyH)
  })
  
  return overlays
}

const specToGridImagesTextCardsContent = (spec) => {
  if (spec.kind === 'card') {
    return {
      svg: cardSvg(spec.w, spec.h, GITC_GEOM.cardRadius),
      colorMode: 'fixed',
      fill: spec.color,
    }
  }
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
    : (GITC_DEFAULTS[sid] || existing)
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

const layoutGridImagesTextCards = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GITC_GEOM.viewW
  const sy = canvasH / GITC_GEOM.viewH
  const overlay = gridImagesTextCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GITC_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridImagesTextCardsSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))
  
  // Get existing image elements
  const imageSlots = elements.filter((el) => el.type === 'image' && /^COL_[123]_IMAGE$/.test(String(el.slotId || '')))
  const imageBySlot = new Map(imageSlots.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gitc'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }
  
  const placeImage = (slotId, cardX, cardY, imageW, imageH) => {
    const prev = imageBySlot.get(slotId)
    const hasImage = prev?.content?.url || prev?.content?.src
    const g = GITC_GEOM
    const innerX = cardX + g.cardPadding
    const innerY = cardY + g.imageY
    
    return {
      id: prev?.id || newId('img-gitc'),
      type: 'image',
      slotId,
      role: 'image',
      layer: 5,
      placement: {
        x: Math.round(innerX * sx),
        y: Math.round(innerY * sy),
        width: Math.round(imageW * sx),
        height: Math.round(imageH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        url: prev?.content?.url || null,
        src: prev?.content?.src || null,
        fit: 'cover',
        borderRadius: g.imageRadius,
        name: prev?.content?.name || slotId,
        ...(hasImage ? {} : {
          placeholderSvg: imagePlaceholderSvg(imageW, imageH),
        }),
      },
    }
  }

  const g = GITC_GEOM
  const cardXs = [g.card1X, g.card2X, g.card3X]
  const imageW = g.cardW - (g.cardPadding * 2)
  
  const next = []
  
  // Three cards with images and text
  cardXs.forEach((cardX, i) => {
    const num = i + 1
    
    // Image
    next.push(placeImage(`COL_${num}_IMAGE`, cardX, g.cardY, imageW, g.imageH))
    
    // Title
    next.push(placeText(`COL_${num}_TITLE`, overlay[`title${num}`], {
      align: 'left', verticalAlign: 'top', fontSize: 22, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2, wrap: 'wrap',
    }, 'heading'))
    
    // Body
    next.push(placeText(`COL_${num}_BODY`, overlay[`body${num}`], {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'))
  })

  const chrome = gridImagesTextCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridImagesTextCardsContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gitc'),
      type: 'graphic',
      layer: spec.layer || 2,
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
  isGridImagesTextCardsLayout,
  layoutGridImagesTextCards,
  GITC_GEOM,
  GITC_DEFAULTS,
};
