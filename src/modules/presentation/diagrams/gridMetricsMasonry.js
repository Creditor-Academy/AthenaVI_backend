/**
 * Grid metrics masonry — Asymmetric masonry layout with main heading, feature cards, metric, and phone mockup.
 * Layout id: grid_metrics_masonry_v1.
 */

const GMMA_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Main heading at top
  headingX: 40,
  headingY: 50,
  headingW: 920,
  headingH: 70,
  
  // Left column (tall) - Feature card
  leftX: 40,
  leftY: 140,
  leftW: 440,
  leftH: 180,
  leftRadius: 16,
  leftPadding: 24,
  
  // Left feature title and desc
  leftTitleY: 160,
  leftTitleH: 35,
  leftDescY: 205,
  leftDescH: 95,
  
  // Left metric card (below feature)
  metricX: 40,
  metricY: 340,
  metricW: 440,
  metricH: 140,
  metricRadius: 16,
  metricPadding: 24,
  
  // Metric value and label
  metricValueY: 365,
  metricValueH: 60,
  metricLabelY: 435,
  metricLabelH: 35,
  
  // Center - Phone mockup
  phoneX: 500,
  phoneY: 180,
  phoneW: 200,
  phoneH: 320,
  phoneBorder: 6,
  phoneRadius: 32,
  
  // Phone caption above
  phoneCaptionX: 500,
  phoneCaptionY: 140,
  phoneCaptionW: 200,
  phoneCaptionH: 30,
  
  // Phone screen
  screenPadding: 10,
  screenRadius: 26,
  
  // Right column (tall) - Feature card
  rightX: 720,
  rightY: 200,
  rightW: 240,
  rightH: 280,
  rightRadius: 16,
  rightPadding: 20,
  
  // Right feature title and desc
  rightTitleY: 220,
  rightTitleH: 35,
  rightDescY: 270,
  rightDescH: 190,
}

const GMMA_COLORS = {
  cardBg: '#F1F5F9',
  cardBorder: '#E2E8F0',
  metricValue: '#6366F1', // Indigo
  phoneBorder: '#CBD5E1',
  screenBg: '#E0E7FF',
  imagePlaceholder: '#C4B5FD',
}

const GMMA_DEFAULTS = {
  HEADING: 'Performance highlights',
  LEFT_FEATURE_TITLE: 'Describe this feature',
  LEFT_FEATURE_DESC: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  METRIC_VALUE: '100k',
  METRIC_LABEL: 'Explain the meaning of this metric',
  PHONE_CAPTION: 'Explain the meaning of this',
  RIGHT_FEATURE_TITLE: 'Describe this feature',
  RIGHT_FEATURE_DESC: 'Supporting paragraph with three to four lines of scannable copy',
}

const isGridMetricsMasonryLayout = (layoutId) => {
  return /grid_metrics_masonry_v1$/i.test(String(layoutId || ''))
}

const isGridMetricsMasonrySlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'HEADING'
    || sid === 'LEFT_FEATURE_TITLE'
    || sid === 'LEFT_FEATURE_DESC'
    || sid === 'METRIC_VALUE'
    || sid === 'METRIC_LABEL'
    || sid === 'PHONE_CAPTION'
    || sid === 'PHONE_IMAGE'
    || sid === 'RIGHT_FEATURE_TITLE'
    || sid === 'RIGHT_FEATURE_DESC'
}

const featureCardSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMMA_COLORS.cardBg}" stroke="${GMMA_COLORS.cardBorder}" stroke-width="1.5" rx="${radius}"/>
  </svg>`
}

const metricCardSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMMA_COLORS.cardBg}" stroke="${GMMA_COLORS.cardBorder}" stroke-width="1.5" rx="${radius}"/>
  </svg>`
}

const phoneFrameSvg = (w, h, border, radius) => {
  const innerR = radius - border
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="white" stroke="${GMMA_COLORS.phoneBorder}" stroke-width="3" rx="${radius}"/>
  </svg>`
}

const imagePlaceholderForPhone = (w, h) => {
  const iconSize = Math.min(w, h) * 0.18
  const iconX = (w - iconSize) / 2
  const iconY = (h - iconSize) / 2
  const rectW = iconSize * 0.7
  const rectH = iconSize * 0.5
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMMA_COLORS.screenBg}" rx="8"/>
    <g transform="translate(${iconX}, ${iconY})">
      <rect x="${iconSize * 0.15}" y="${iconSize * 0.25}" width="${rectW}" height="${rectH}" fill="${GMMA_COLORS.imagePlaceholder}" opacity="0.5" rx="2"/>
      <circle cx="${iconSize * 0.3}" cy="${iconSize * 0.4}" r="${iconSize * 0.08}" fill="${GMMA_COLORS.imagePlaceholder}" opacity="0.5"/>
      <path d="M${iconSize * 0.15} ${iconSize * 0.75} L${iconSize * 0.35} ${iconSize * 0.55} L${iconSize * 0.5} ${iconSize * 0.65} L${iconSize * 0.7} ${iconSize * 0.45} L${iconSize * 0.85} ${iconSize * 0.75} Z" fill="${GMMA_COLORS.imagePlaceholder}" opacity="0.5"/>
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

const gridMetricsMasonryChromeSpecs = () => {
  const g = GMMA_GEOM
  const specs = []
  
  // Left feature card
  specs.push({
    slotId: 'GMMA_LEFT_CARD',
    x: g.leftX,
    y: g.leftY,
    w: g.leftW,
    h: g.leftH,
    color: GMMA_COLORS.cardBg,
    layer: 2,
    kind: 'featureCard',
  })
  
  // Metric card
  specs.push({
    slotId: 'GMMA_METRIC_CARD',
    x: g.metricX,
    y: g.metricY,
    w: g.metricW,
    h: g.metricH,
    color: GMMA_COLORS.cardBg,
    layer: 2,
    kind: 'metricCard',
  })
  
  // Phone frame
  specs.push({
    slotId: 'GMMA_PHONE_FRAME',
    x: g.phoneX,
    y: g.phoneY,
    w: g.phoneW,
    h: g.phoneH,
    color: GMMA_COLORS.phoneBorder,
    layer: 2,
    kind: 'phoneFrame',
  })
  
  // Right feature card
  specs.push({
    slotId: 'GMMA_RIGHT_CARD',
    x: g.rightX,
    y: g.rightY,
    w: g.rightW,
    h: g.rightH,
    color: GMMA_COLORS.cardBg,
    layer: 2,
    kind: 'featureCard',
  })
  
  return specs
}

const gridMetricsMasonryOverlay = (gx, gy, gw, gh) => {
  const g = GMMA_GEOM
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
    leftFeatureTitle: box(g.leftX + g.leftPadding, g.leftTitleY, g.leftW - g.leftPadding * 2, g.leftTitleH),
    leftFeatureDesc: box(g.leftX + g.leftPadding, g.leftDescY, g.leftW - g.leftPadding * 2, g.leftDescH),
    metricValue: box(g.metricX + g.metricPadding, g.metricValueY, g.metricW - g.metricPadding * 2, g.metricValueH),
    metricLabel: box(g.metricX + g.metricPadding, g.metricLabelY, g.metricW - g.metricPadding * 2, g.metricLabelH),
    phoneCaption: box(g.phoneCaptionX, g.phoneCaptionY, g.phoneCaptionW, g.phoneCaptionH),
    rightFeatureTitle: box(g.rightX + g.rightPadding, g.rightTitleY, g.rightW - g.rightPadding * 2, g.rightTitleH),
    rightFeatureDesc: box(g.rightX + g.rightPadding, g.rightDescY, g.rightW - g.rightPadding * 2, g.rightDescH),
  }
}

const specToGridMetricsMasonryContent = (spec) => {
  if (spec.kind === 'featureCard') {
    return { svg: featureCardSvg(spec.w, spec.h, GMMA_GEOM.leftRadius), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'metricCard') {
    return { svg: metricCardSvg(spec.w, spec.h, GMMA_GEOM.metricRadius), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'phoneFrame') {
    return { svg: phoneFrameSvg(spec.w, spec.h, GMMA_GEOM.phoneBorder, GMMA_GEOM.phoneRadius), colorMode: 'fixed', fill: spec.color }
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
    : (GMMA_DEFAULTS[sid] || existing)
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

const layoutGridMetricsMasonry = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GMMA_GEOM.viewW
  const sy = canvasH / GMMA_GEOM.viewH
  const overlay = gridMetricsMasonryOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GMMA_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridMetricsMasonrySlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))
  
  // Get existing image element
  const imageSlots = elements.filter((el) => el.type === 'image' && el.slotId === 'PHONE_IMAGE')
  const imageBySlot = new Map(imageSlots.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gmma'),
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
      id: prev?.id || newId('img-gmma'),
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

  const g = GMMA_GEOM
  
  // Calculate phone screen position
  const screenX = g.phoneX + g.phoneBorder + g.screenPadding
  const screenY = g.phoneY + g.phoneBorder + g.screenPadding
  const screenW = g.phoneW - (g.phoneBorder + g.screenPadding) * 2
  const screenH = g.phoneH - (g.phoneBorder + g.screenPadding) * 2

  const next = [
    // Main heading
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'center', fontSize: 52, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    
    // Left feature card
    placeText('LEFT_FEATURE_TITLE', overlay.leftFeatureTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 22, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('LEFT_FEATURE_DESC', overlay.leftFeatureDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    // Metric card
    placeText('METRIC_VALUE', overlay.metricValue, {
      align: 'left', verticalAlign: 'center', fontSize: 56, fontWeight: 700, color: GMMA_COLORS.metricValue, clipToSlot: true, lineHeight: 1.1,
    }, 'stat'),
    placeText('METRIC_LABEL', overlay.metricLabel, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }, 'stat_label'),
    
    // Phone caption and image
    placeText('PHONE_CAPTION', overlay.phoneCaption, {
      align: 'center', verticalAlign: 'center', fontSize: 12, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeImage('PHONE_IMAGE', screenX, screenY, screenW, screenH, g.screenRadius),
    
    // Right feature card
    placeText('RIGHT_FEATURE_TITLE', overlay.rightFeatureTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('RIGHT_FEATURE_DESC', overlay.rightFeatureDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
  ]

  const chrome = gridMetricsMasonryChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridMetricsMasonryContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gmma'),
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
  GMMA_GEOM,
  GMMA_COLORS,
  GMMA_DEFAULTS,
  isGridMetricsMasonryLayout,
  isGridMetricsMasonrySlot,
  gridMetricsMasonryChromeSpecs,
  gridMetricsMasonryOverlay,
  specToGridMetricsMasonryContent,
  layoutGridMetricsMasonry,
};