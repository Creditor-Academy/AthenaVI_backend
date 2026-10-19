/**
 * Grid metrics mobile — Feature title + description + 2 metric cards + phone mockup.
 * Layout id: grid_metrics_mobile_v1.
 */

const GMM_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Left side content area
  leftX: 40,
  leftY: 40,
  leftW: 580,
  
  // Feature title and description
  titleY: 60,
  titleH: 80,
  descY: 180,
  descW: 540,
  descH: 85,
  
  // Two metric cards (side by side)
  metric1X: 40,
  metric2X: 310,
  metricY: 280,
  metricW: 250,
  metricH: 130,
  metricGap: 20,
  metricRadius: 12,
  
  // Inside each metric card
  metricValueY: 35,
  metricValueH: 55,
  metricLabelY: 95,
  metricLabelH: 25,
  
  // Phone mockup (right side)
  phoneX: 680,
  phoneY: 80,
  phoneW: 260,
  phoneH: 420,
  phoneBorder: 8,
  phoneRadius: 36,
  
  // Phone screen (inside frame)
  screenPadding: 12,
  screenRadius: 28,
}

const GMM_COLORS = {
  metricBg: '#F8FAFC',
  metricBorder: '#E2E8F0',
  metricValue: '#6366F1', // Indigo
  metricLabel: '#94A3B8',
  phoneBorder: '#1E293B',
  screenBg: '#DDD6FE', // Light purple
  imagePlaceholder: '#C4B5FD',
}

const GMM_DEFAULTS = {
  FEATURE_TITLE: 'Describe this feature',
  FEATURE_DESC: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  METRIC_1_VALUE: '100k',
  METRIC_1_LABEL: 'Metric',
  METRIC_2_VALUE: '95%',
  METRIC_2_LABEL: 'Metric',
}

const isGridMetricsMobileLayout = (layoutId) => {
  return /grid_metrics_mobile_v1$/i.test(String(layoutId || ''))
}

const isGridMetricsMobileSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'FEATURE_TITLE'
    || sid === 'FEATURE_DESC'
    || sid === 'METRIC_1_VALUE'
    || sid === 'METRIC_1_LABEL'
    || sid === 'METRIC_2_VALUE'
    || sid === 'METRIC_2_LABEL'
    || sid === 'PHONE_IMAGE'
}

const metricCardSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMM_COLORS.metricBg}" stroke="${GMM_COLORS.metricBorder}" stroke-width="1" rx="${radius}"/>
  </svg>`
}

const phoneFrameSvg = (w, h, border, radius) => {
  const innerR = radius - border
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <!-- Outer frame -->
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMM_COLORS.phoneBorder}" rx="${radius}"/>
    <!-- Inner cutout for screen -->
    <rect x="${border}" y="${border}" width="${w - border * 2}" height="${h - border * 2}" fill="white" rx="${innerR}"/>
  </svg>`
}

const phoneScreenSvg = (w, h, radius) => {
  const iconSize = Math.min(w, h) * 0.25
  const iconX = (w - iconSize) / 2
  const iconY = (h - iconSize) / 2
  const rectW = iconSize * 0.7
  const rectH = iconSize * 0.5
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMM_COLORS.screenBg}" rx="${radius}"/>
    <!-- Image placeholder icon -->
    <g transform="translate(${iconX}, ${iconY})">
      <rect x="${iconSize * 0.15}" y="${iconSize * 0.25}" width="${rectW}" height="${rectH}" fill="${GMM_COLORS.imagePlaceholder}" opacity="0.6" rx="4"/>
      <circle cx="${iconSize * 0.3}" cy="${iconSize * 0.4}" r="${iconSize * 0.08}" fill="${GMM_COLORS.imagePlaceholder}" opacity="0.6"/>
      <path d="M${iconSize * 0.15} ${iconSize * 0.75} L${iconSize * 0.35} ${iconSize * 0.55} L${iconSize * 0.5} ${iconSize * 0.65} L${iconSize * 0.7} ${iconSize * 0.45} L${iconSize * 0.85} ${iconSize * 0.75} Z" fill="${GMM_COLORS.imagePlaceholder}" opacity="0.6"/>
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

const gridMetricsMobileChromeSpecs = () => {
  const g = GMM_GEOM
  const specs = []
  
  // Two metric cards
  const metricXs = [g.metric1X, g.metric2X]
  metricXs.forEach((x, i) => {
    specs.push({
      slotId: `GMM_METRIC${i+1}_BG`,
      x: x,
      y: g.metricY,
      w: g.metricW,
      h: g.metricH,
      color: GMM_COLORS.metricBg,
      layer: 2,
      kind: 'metricCard',
    })
  })
  
  // Phone frame only (screen will be a real image)
  specs.push({
    slotId: 'GMM_PHONE_FRAME',
    x: g.phoneX,
    y: g.phoneY,
    w: g.phoneW,
    h: g.phoneH,
    color: GMM_COLORS.phoneBorder,
    layer: 2,
    kind: 'phoneFrame',
  })
  
  return specs
}

const gridMetricsMobileOverlay = (gx, gy, gw, gh) => {
  const g = GMM_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const overlays = {}
  
  // Feature title and description
  overlays.featureTitle = box(g.leftX, g.titleY, g.leftW, g.titleH)
  overlays.featureDesc = box(g.leftX, g.descY, g.descW, g.descH)
  
  // Metric cards
  const metricXs = [g.metric1X, g.metric2X]
  metricXs.forEach((x, i) => {
    overlays[`metric${i+1}Value`] = box(
      x + 20,
      g.metricY + g.metricValueY,
      g.metricW - 40,
      g.metricValueH
    )
    overlays[`metric${i+1}Label`] = box(
      x + 20,
      g.metricY + g.metricLabelY,
      g.metricW - 40,
      g.metricLabelH
    )
  })
  
  return overlays
}

const specToGridMetricsMobileContent = (spec) => {
  if (spec.kind === 'metricCard') {
    return { svg: metricCardSvg(spec.w, spec.h, GMM_GEOM.metricRadius), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'phoneFrame') {
    return { svg: phoneFrameSvg(spec.w, spec.h, GMM_GEOM.phoneBorder, GMM_GEOM.phoneRadius), colorMode: 'fixed', fill: spec.color }
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
    : (GMM_DEFAULTS[sid] || existing)
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

const imagePlaceholderForPhone = (w, h) => {
  const iconSize = Math.min(w, h) * 0.2
  const iconX = (w - iconSize) / 2
  const iconY = (h - iconSize) / 2
  const rectW = iconSize * 0.7
  const rectH = iconSize * 0.5
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GMM_COLORS.screenBg}" rx="8"/>
    <g transform="translate(${iconX}, ${iconY})">
      <rect x="${iconSize * 0.15}" y="${iconSize * 0.25}" width="${rectW}" height="${rectH}" fill="${GMM_COLORS.imagePlaceholder}" opacity="0.6" rx="3"/>
      <circle cx="${iconSize * 0.3}" cy="${iconSize * 0.4}" r="${iconSize * 0.08}" fill="${GMM_COLORS.imagePlaceholder}" opacity="0.6"/>
      <path d="M${iconSize * 0.15} ${iconSize * 0.75} L${iconSize * 0.35} ${iconSize * 0.55} L${iconSize * 0.5} ${iconSize * 0.65} L${iconSize * 0.7} ${iconSize * 0.45} L${iconSize * 0.85} ${iconSize * 0.75} Z" fill="${GMM_COLORS.imagePlaceholder}" opacity="0.6"/>
    </g>
  </svg>`
}

const layoutGridMetricsMobile = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GMM_GEOM.viewW
  const sy = canvasH / GMM_GEOM.viewH
  const overlay = gridMetricsMobileOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GMM_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridMetricsMobileSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))
  
  // Get existing image element
  const imageSlots = elements.filter((el) => el.type === 'image' && el.slotId === 'PHONE_IMAGE')
  const imageBySlot = new Map(imageSlots.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gmm'),
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
      id: prev?.id || newId('img-gmm'),
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

  const g = GMM_GEOM
  
  // Calculate phone screen position
  const screenX = g.phoneX + g.phoneBorder + g.screenPadding
  const screenY = g.phoneY + g.phoneBorder + g.screenPadding
  const screenW = g.phoneW - (g.phoneBorder + g.screenPadding) * 2
  const screenH = g.phoneH - (g.phoneBorder + g.screenPadding) * 2

  const next = [
    // Feature title and description
    placeText('FEATURE_TITLE', overlay.featureTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 48, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('FEATURE_DESC', overlay.featureDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 16, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    // Metric 1
    placeText('METRIC_1_VALUE', overlay.metric1Value, {
      align: 'center', verticalAlign: 'center', fontSize: 44, fontWeight: 700, color: GMM_COLORS.metricValue, clipToSlot: true, lineHeight: 1.1,
    }, 'stat'),
    placeText('METRIC_1_LABEL', overlay.metric1Label, {
      align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 500, color: GMM_COLORS.metricLabel, clipToSlot: true, lineHeight: 1.2,
    }, 'stat_label'),
    
    // Metric 2
    placeText('METRIC_2_VALUE', overlay.metric2Value, {
      align: 'center', verticalAlign: 'center', fontSize: 44, fontWeight: 700, color: GMM_COLORS.metricValue, clipToSlot: true, lineHeight: 1.1,
    }, 'stat'),
    placeText('METRIC_2_LABEL', overlay.metric2Label, {
      align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 500, color: GMM_COLORS.metricLabel, clipToSlot: true, lineHeight: 1.2,
    }, 'stat_label'),
    
    // Phone screen image
    placeImage('PHONE_IMAGE', screenX, screenY, screenW, screenH, g.screenRadius),
  ]

  const chrome = gridMetricsMobileChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridMetricsMobileContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gmm'),
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
  GMM_GEOM,
  GMM_COLORS,
  GMM_DEFAULTS,
  isGridMetricsMobileLayout,
  isGridMetricsMobileSlot,
  gridMetricsMobileChromeSpecs,
  gridMetricsMobileOverlay,
  specToGridMetricsMobileContent,
  layoutGridMetricsMobile,
};