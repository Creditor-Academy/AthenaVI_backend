/**
 * Grid metrics asymmetric — Asymmetric grid with heading, feature cards, metrics, and phone mockup.
 * Layout id: grid_metrics_asymmetric_v1.
 */

const GMAS_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Main heading at top
  headingX: 80,
  headingY: 50,
  headingW: 840,
  headingH: 60,
  
  // Top left - Feature card (large)
  topLeftX: 80,
  topLeftY: 140,
  topLeftW: 380,
  topLeftH: 160,
  topLeftRadius: 14,
  topLeftPadding: 20,
  
  // Top left title and desc
  topLeftTitleY: 155,
  topLeftTitleH: 32,
  topLeftDescY: 195,
  topLeftDescH: 90,
  
  // Top center - Metric value (95)
  topCenterX: 490,
  topCenterY: 150,
  topCenterW: 140,
  topCenterH: 90,
  topCenterRadius: 14,
  
  // Inside top center metric
  topCenterValueY: 165,
  topCenterValueH: 60,
  
  // Top right - Metric label card
  topRightX: 650,
  topRightY: 150,
  topRightW: 270,
  topRightH: 90,
  topRightRadius: 14,
  topRightPadding: 18,
  
  // Top right label text
  topRightLabelY: 165,
  topRightLabelH: 60,
  
  // Bottom left - Metric value (100k)
  bottomLeftX: 80,
  bottomLeftY: 330,
  bottomLeftW: 240,
  bottomLeftH: 110,
  bottomLeftRadius: 14,
  bottomLeftPadding: 20,
  
  // Inside bottom left metric
  bottomLeftValueY: 355,
  bottomLeftValueH: 60,
  
  // Bottom center-left - Metric label
  bottomCenterX: 340,
  bottomCenterY: 340,
  bottomCenterW: 320,
  bottomCenterH: 100,
  bottomCenterRadius: 14,
  bottomCenterPadding: 20,
  
  // Bottom center label text
  bottomCenterLabelY: 355,
  bottomCenterLabelH: 70,
  
  // Phone mockup (center-right)
  phoneX: 490,
  phoneY: 270,
  phoneW: 150,
  phoneH: 210,
  phoneBorder: 5,
  phoneRadius: 28,
  
  // Phone screen
  screenPadding: 8,
  screenRadius: 23,
  
  // Bottom right - Feature card
  bottomRightX: 660,
  bottomRightY: 260,
  bottomRightW: 260,
  bottomRightH: 180,
  bottomRightRadius: 14,
  bottomRightPadding: 18,
  
  // Bottom right title and desc
  bottomRightTitleY: 275,
  bottomRightTitleH: 32,
  bottomRightDescY: 320,
  bottomRightDescH: 105,
}

const GMAS_COLORS = {
  cardBg: '#E2E8F0',
  cardBorder: '#CBD5E1',
  metricValue: '#1E293B', // Dark slate
  phoneBorder: '#94A3B8',
  screenBg: '#DBEAFE',
  imagePlaceholder: '#93C5FD',
}

const GMAS_DEFAULTS = {
  HEADING: 'Performance highlights',
  TOP_LEFT_TITLE: 'Describe this feature',
  TOP_LEFT_DESC: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  TOP_CENTER_VALUE: '95',
  TOP_RIGHT_LABEL: 'Explain the meaning of this metric',
  BOTTOM_LEFT_VALUE: '100k',
  BOTTOM_CENTER_LABEL: 'Explain the meaning of this metric',
  BOTTOM_RIGHT_TITLE: 'Describe this feature',
  BOTTOM_RIGHT_DESC: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const isGridMetricsAsymmetricLayout = (layoutId) => {
  return /grid_metrics_asymmetric_v1$/i.test(String(layoutId || ''))
}

const isGridMetricsAsymmetricSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'TOP_LEFT_TITLE'
    || sid === 'TOP_LEFT_DESC'
    || sid === 'TOP_CENTER_VALUE'
    || sid === 'TOP_RIGHT_LABEL'
    || sid === 'BOTTOM_LEFT_VALUE'
    || sid === 'BOTTOM_CENTER_LABEL'
    || sid === 'PHONE_IMAGE'
    || sid === 'BOTTOM_RIGHT_TITLE'
    || sid === 'BOTTOM_RIGHT_DESC'
}

const cardSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMAS_COLORS.cardBg}" stroke="${GMAS_COLORS.cardBorder}" stroke-width="1.5" rx="${radius}"/>
  </svg>`
}

const phoneFrameSvg = (w, h, border, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="white" stroke="${GMAS_COLORS.phoneBorder}" stroke-width="2.5" rx="${radius}"/>
  </svg>`
}

const imagePlaceholderForPhone = (w, h) => {
  const iconSize = Math.min(w, h) * 0.18
  const iconX = (w - iconSize) / 2
  const iconY = (h - iconSize) / 2
  const rectW = iconSize * 0.7
  const rectH = iconSize * 0.5
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="imgGradAsym" x1="0%" y1="0%" x2="0%" y2="100%">
        <stop offset="0%" style="stop-color:#DBEAFE;stop-opacity:1" />
        <stop offset="50%" style="stop-color:#93C5FD;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#60A5FA;stop-opacity:1" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${w}" height="${h}" fill="url(#imgGradAsym)" rx="6"/>
    <g transform="translate(${iconX}, ${iconY})">
      <rect x="${iconSize * 0.15}" y="${iconSize * 0.25}" width="${rectW}" height="${rectH}" fill="white" opacity="0.5" rx="2"/>
      <circle cx="${iconSize * 0.3}" cy="${iconSize * 0.4}" r="${iconSize * 0.08}" fill="white" opacity="0.5"/>
      <path d="M${iconSize * 0.15} ${iconSize * 0.75} L${iconSize * 0.35} ${iconSize * 0.55} L${iconSize * 0.5} ${iconSize * 0.65} L${iconSize * 0.7} ${iconSize * 0.45} L${iconSize * 0.85} ${iconSize * 0.75} Z" fill="white" opacity="0.5"/>
    </g>
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

const gridMetricsAsymmetricChromeSpecs = () => {
  const g = GMAS_GEOM
  const specs = []
  
  // Top left feature card
  specs.push({
    slotId: 'GMAS_TOP_LEFT',
    x: g.topLeftX,
    y: g.topLeftY,
    w: g.topLeftW,
    h: g.topLeftH,
    layer: 2,
    kind: 'card',
  })
  
  // Top center metric card
  specs.push({
    slotId: 'GMAS_TOP_CENTER',
    x: g.topCenterX,
    y: g.topCenterY,
    w: g.topCenterW,
    h: g.topCenterH,
    layer: 2,
    kind: 'card',
  })
  
  // Top right label card
  specs.push({
    slotId: 'GMAS_TOP_RIGHT',
    x: g.topRightX,
    y: g.topRightY,
    w: g.topRightW,
    h: g.topRightH,
    layer: 2,
    kind: 'card',
  })
  
  // Bottom left metric card
  specs.push({
    slotId: 'GMAS_BOTTOM_LEFT',
    x: g.bottomLeftX,
    y: g.bottomLeftY,
    w: g.bottomLeftW,
    h: g.bottomLeftH,
    layer: 2,
    kind: 'card',
  })
  
  // Bottom center label card
  specs.push({
    slotId: 'GMAS_BOTTOM_CENTER',
    x: g.bottomCenterX,
    y: g.bottomCenterY,
    w: g.bottomCenterW,
    h: g.bottomCenterH,
    layer: 2,
    kind: 'card',
  })
  
  // Phone frame
  specs.push({
    slotId: 'GMAS_PHONE_FRAME',
    x: g.phoneX,
    y: g.phoneY,
    w: g.phoneW,
    h: g.phoneH,
    layer: 3,
    kind: 'phoneFrame',
  })
  
  // Bottom right feature card
  specs.push({
    slotId: 'GMAS_BOTTOM_RIGHT',
    x: g.bottomRightX,
    y: g.bottomRightY,
    w: g.bottomRightW,
    h: g.bottomRightH,
    layer: 2,
    kind: 'card',
  })
  
  return specs
}

const gridMetricsAsymmetricOverlay = (gx, gy, gw, gh) => {
  const g = GMAS_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    topLeftTitle: box(g.topLeftX + g.topLeftPadding, g.topLeftTitleY, g.topLeftW - g.topLeftPadding * 2, g.topLeftTitleH),
    topLeftDesc: box(g.topLeftX + g.topLeftPadding, g.topLeftDescY, g.topLeftW - g.topLeftPadding * 2, g.topLeftDescH),
    topCenterValue: box(g.topCenterX + 10, g.topCenterValueY, g.topCenterW - 20, g.topCenterValueH),
    topRightLabel: box(g.topRightX + g.topRightPadding, g.topRightLabelY, g.topRightW - g.topRightPadding * 2, g.topRightLabelH),
    bottomLeftValue: box(g.bottomLeftX + g.bottomLeftPadding, g.bottomLeftValueY, g.bottomLeftW - g.bottomLeftPadding * 2, g.bottomLeftValueH),
    bottomCenterLabel: box(g.bottomCenterX + g.bottomCenterPadding, g.bottomCenterLabelY, g.bottomCenterW - g.bottomCenterPadding * 2, g.bottomCenterLabelH),
    bottomRightTitle: box(g.bottomRightX + g.bottomRightPadding, g.bottomRightTitleY, g.bottomRightW - g.bottomRightPadding * 2, g.bottomRightTitleH),
    bottomRightDesc: box(g.bottomRightX + g.bottomRightPadding, g.bottomRightDescY, g.bottomRightW - g.bottomRightPadding * 2, g.bottomRightDescH),
  }
}

const specToGridMetricsAsymmetricContent = (spec) => {
  if (spec.kind === 'card') {
    return { svg: cardSvg(spec.w, spec.h, GMAS_GEOM.topLeftRadius), colorMode: 'fixed', fill: GMAS_COLORS.cardBg }
  }
  if (spec.kind === 'phoneFrame') {
    return { svg: phoneFrameSvg(spec.w, spec.h, GMAS_GEOM.phoneBorder, GMAS_GEOM.phoneRadius), colorMode: 'fixed', fill: 'white' }
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
    : (GMAS_DEFAULTS[sid] || existing)
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

const layoutGridMetricsAsymmetric = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GMAS_GEOM.viewW
  const sy = canvasH / GMAS_GEOM.viewH
  const overlay = gridMetricsAsymmetricOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GMAS_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridMetricsAsymmetricSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))
  
  // Get existing image element
  const imageSlots = elements.filter((el) => el.type === 'image' && el.slotId === 'PHONE_IMAGE')
  const imageBySlot = new Map(imageSlots.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gmas'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }
  
  const placeImage = (slotId, x, y, w, h, radius) => {
    const prev = imageBySlot.get(slotId)
    const hasImage = prev?.content?.url || prev?.content?.src
    
    return {
      id: prev?.id || newId('img-gmas'),
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
        borderRadius: radius,
        name: prev?.content?.name || slotId,
        ...(hasImage ? {} : {
          placeholderSvg: imagePlaceholderForPhone(w, h),
        }),
      },
    }
  }

  const g = GMAS_GEOM
  
  // Calculate phone screen position
  const screenX = g.phoneX + g.phoneBorder + g.screenPadding
  const screenY = g.phoneY + g.phoneBorder + g.screenPadding
  const screenW = g.phoneW - (g.phoneBorder + g.screenPadding) * 2
  const screenH = g.phoneH - (g.phoneBorder + g.screenPadding) * 2

  const next = [
    // Main heading
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'center', fontSize: 48, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    
    // Top left feature
    placeText('TOP_LEFT_TITLE', overlay.topLeftTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('TOP_LEFT_DESC', overlay.topLeftDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    // Top center metric
    placeText('TOP_CENTER_VALUE', overlay.topCenterValue, {
      align: 'center', verticalAlign: 'center', fontSize: 60, fontWeight: 700, color: GMAS_COLORS.metricValue, clipToSlot: true, lineHeight: 1.0,
    }, 'stat'),
    
    // Top right label
    placeText('TOP_RIGHT_LABEL', overlay.topRightLabel, {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'stat_label'),
    
    // Bottom left metric
    placeText('BOTTOM_LEFT_VALUE', overlay.bottomLeftValue, {
      align: 'left', verticalAlign: 'center', fontSize: 56, fontWeight: 700, color: GMAS_COLORS.metricValue, clipToSlot: true, lineHeight: 1.0,
    }, 'stat'),
    
    // Bottom center label
    placeText('BOTTOM_CENTER_LABEL', overlay.bottomCenterLabel, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'stat_label'),
    
    // Phone image
    placeImage('PHONE_IMAGE', screenX, screenY, screenW, screenH, g.screenRadius),
    
    // Bottom right feature
    placeText('BOTTOM_RIGHT_TITLE', overlay.bottomRightTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 18, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('BOTTOM_RIGHT_DESC', overlay.bottomRightDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
  ]

  const chrome = gridMetricsAsymmetricChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridMetricsAsymmetricContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gmas'),
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
  GMAS_GEOM,
  GMAS_COLORS,
  GMAS_DEFAULTS,
  isGridMetricsAsymmetricLayout,
  isGridMetricsAsymmetricSlot,
  gridMetricsAsymmetricChromeSpecs,
  gridMetricsAsymmetricOverlay,
  specToGridMetricsAsymmetricContent,
  layoutGridMetricsAsymmetric,
};