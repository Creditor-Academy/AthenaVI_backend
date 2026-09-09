/**
 * Metric single split — Single metric on left, context panel on right.
 * Layout id: metric_single_split_v1.
 */

const MSS_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Left side - Metric
  leftBadgeX: 40,
  leftBadgeY: 40,
  leftBadgeW: 130,
  leftBadgeH: 24,
  leftBadgeIconSize: 14,
  
  leftHeadingX: 40,
  leftHeadingY: 85,
  leftHeadingW: 480,
  leftHeadingH: 42,
  
  leftSubheadingX: 40,
  leftSubheadingY: 135,
  leftSubheadingW: 480,
  leftSubheadingH: 50,
  
  leftMetricX: 40,
  leftMetricY: 205,
  leftMetricW: 300,
  leftMetricH: 95,
  
  leftTrendX: 50,
  leftTrendY: 315,
  leftTrendW: 130,
  leftTrendH: 24,
  leftTrendArrowX: 50,
  leftTrendArrowY: 320,
  
  leftCompareX: 185,
  leftCompareY: 315,
  leftCompareW: 150,
  leftCompareH: 24,
  
  // Circle icon (right of metric)
  circleX: 380,
  circleY: 180,
  circleDiameter: 160,
  circleStrokeWidth: 12,
  
  circleIconX: 420,
  circleIconY: 220,
  circleIconSize: 48,
  
  // Right side - Context panel
  panelX: 600,
  panelY: 60,
  panelW: 360,
  panelH: 440,
  
  panelIconX: 640,
  panelIconY: 80,
  panelIconSize: 32,
  panelIconBgSize: 48,
  
  panelHeadingX: 700,
  panelHeadingY: 80,
  panelHeadingW: 230,
  panelHeadingH: 40,
  
  panelDescX: 640,
  panelDescY: 140,
  panelDescW: 300,
  panelDescH: 115,
  
  // Context items in panel
  item1Y: 280,
  item2Y: 355,
  item3Y: 430,
  itemIconX: 640,
  itemIconSize: 24,
  itemIconBgSize: 36,
  itemLabelX: 690,
  itemLabelW: 250,
  itemLabelH: 18,
  itemValueX: 690,
  itemValueW: 250,
  itemValueH: 24,
  
  // Decorative circles (bottom left)
  decoX: 0,
  decoY: 440,
  decoW: 200,
  decoH: 120,
}

const MSS_COLORS = {
  primary: '#3B82F6',
  badge: '#DBEAFE',
  badgeText: '#3B82F6',
  trend: '#10B981',
  panelBg: '#F8FAFC',
  panelIcon: '#3B82F6',
  deco: '#DBEAFE',
}

const MSS_DEFAULTS = {
  BADGE: 'KEY METRIC',
  HEADING: 'Customer satisfaction',
  SUBHEADING: "Shows how well we're meeting customer expectations and delivering value.",
  METRIC_VALUE: '98%',
  TREND: '+12%',
  COMPARE: 'vs. last quarter',
  
  PANEL_HEADING: 'Context',
  PANEL_DESC: 'This metric reflects customer feedback and support interactions over the last quarter. It highlights the continued improvement in customer experience and satisfaction levels.',
  
  ITEM1_LABEL: 'Time Period',
  ITEM1_VALUE: 'Q2 - Q4 2025',
  
  ITEM2_LABEL: 'Change',
  ITEM2_VALUE: '+12% vs. last quarter',
  
  ITEM3_LABEL: 'Source',
  ITEM3_VALUE: 'Customer feedback & support tickets',
}

const isMetricSingleSplitLayout = (layoutId) => {
  return /metric_single_split_v1$/i.test(String(layoutId || ''))
}

const isMetricSingleSplitTextSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'METRIC_VALUE'
    || sid === 'TREND'
    || sid === 'COMPARE'
    || sid === 'PANEL_HEADING'
    || sid === 'PANEL_DESC'
    || sid === 'ITEM1_LABEL'
    || sid === 'ITEM1_VALUE'
    || sid === 'ITEM2_LABEL'
    || sid === 'ITEM2_VALUE'
    || sid === 'ITEM3_LABEL'
    || sid === 'ITEM3_VALUE'
}

const badgeSvg = () => {
  const g = MSS_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.leftBadgeW} ${g.leftBadgeH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.leftBadgeW}" height="${g.leftBadgeH}" fill="${MSS_COLORS.badge}" rx="7"/>
  </svg>`
}

const badgeIconSvg = () => {
  const size = MSS_GEOM.leftBadgeIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="1" y="4" width="3" height="7" rx="0.5" fill="${MSS_COLORS.badgeText}"/>
    <rect x="5" y="2" width="3" height="9" rx="0.5" fill="${MSS_COLORS.badgeText}"/>
    <rect x="9" y="5" width="3" height="6" rx="0.5" fill="${MSS_COLORS.badgeText}"/>
  </svg>`
}

const circleSvg = () => {
  const g = MSS_GEOM
  const r = g.circleDiameter / 2
  const cx = r
  const cy = r
  const viewBox = g.circleDiameter
  const strokeR = r - g.circleStrokeWidth / 2
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewBox} ${viewBox}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <defs>
      <linearGradient id="mssCircleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:${MSS_COLORS.primary};stop-opacity:0.15" />
        <stop offset="100%" style="stop-color:${MSS_COLORS.primary};stop-opacity:0.05" />
      </linearGradient>
    </defs>
    <circle cx="${cx}" cy="${cy}" r="${strokeR}" fill="url(#mssCircleGrad)" stroke="${MSS_COLORS.primary}" stroke-width="${g.circleStrokeWidth}" stroke-opacity="0.6"/>
  </svg>`
}

const circleIconSvg = () => {
  const size = MSS_GEOM.circleIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="16" cy="14" r="7" fill="none" stroke="currentColor" stroke-width="2.5"/>
    <circle cx="32" cy="14" r="7" fill="none" stroke="currentColor" stroke-width="2.5"/>
    <path d="M9 32 Q12 28 16 28 Q20 28 24 28 Q28 28 32 28 Q36 28 39 32 L39 38 L9 38 Z" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/>
  </svg>`
}

const trendArrowSvg = () => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16">
    <path d="M4 10 L8 5 L12 10" fill="none" stroke="${MSS_COLORS.trend}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`
}

const panelBgSvg = () => {
  const g = MSS_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.panelW} ${g.panelH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.panelW}" height="${g.panelH}" fill="${MSS_COLORS.panelBg}" rx="20"/>
  </svg>`
}

const panelIconBgSvg = () => {
  const size = MSS_GEOM.panelIconBgSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="0" y="0" width="${size}" height="${size}" fill="${MSS_COLORS.primary}" fill-opacity="0.12" rx="10"/>
  </svg>`
}

const panelIconSvg = () => {
  const size = MSS_GEOM.panelIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="6" y="4" width="20" height="24" rx="2" fill="none" stroke="currentColor" stroke-width="2"/>
    <line x1="10" y1="10" x2="22" y2="10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="10" y1="15" x2="22" y2="15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="10" y1="20" x2="18" y2="20" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  </svg>`
}

const itemIconBgSvg = (color) => {
  const size = MSS_GEOM.itemIconBgSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="0" y="0" width="${size}" height="${size}" fill="${color}" fill-opacity="0.1" rx="8"/>
  </svg>`
}

const item1IconSvg = () => {
  const size = MSS_GEOM.itemIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="4" y="6" width="16" height="14" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <line x1="4" y1="10" x2="20" y2="10" stroke="currentColor" stroke-width="1.8"/>
    <line x1="9" y1="4" x2="9" y2="8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
    <line x1="15" y1="4" x2="15" y2="8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  </svg>`
}

const item2IconSvg = () => {
  const size = MSS_GEOM.itemIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <path d="M6 16 L10 10 L14 13 L18 7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="15,7 18,7 18,10" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`
}

const item3IconSvg = () => {
  const size = MSS_GEOM.itemIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="1.8"/>
    <circle cx="12" cy="12" r="3" fill="currentColor"/>
    <line x1="12" y1="4" x2="12" y2="7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
    <line x1="12" y1="17" x2="12" y2="20" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
    <line x1="4" y1="12" x2="7" y2="12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
    <line x1="17" y1="12" x2="20" y2="12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
  </svg>`
}

const decoCirclesSvg = () => {
  const w = 200
  const h = 120
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <circle cx="30" cy="60" r="80" fill="${MSS_COLORS.deco}" opacity="0.3"/>
    <circle cx="80" cy="90" r="60" fill="${MSS_COLORS.deco}" opacity="0.5"/>
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
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#111827'
}

const metricSingleSplitChromeSpecs = () => {
  const g = MSS_GEOM
  const specs = []
  
  // Badge
  specs.push({
    slotId: 'MSS_BADGE_BG',
    x: g.leftBadgeX,
    y: g.leftBadgeY,
    w: g.leftBadgeW,
    h: g.leftBadgeH,
    color: MSS_COLORS.badge,
    layer: 3,
    kind: 'badge',
  })
  
  specs.push({
    slotId: 'MSS_BADGE_ICON',
    x: g.leftBadgeX + 10,
    y: g.leftBadgeY + 5,
    w: g.leftBadgeIconSize,
    h: g.leftBadgeIconSize,
    color: MSS_COLORS.badgeText,
    layer: 10,
    kind: 'badgeIcon',
  })
  
  // Circle with icon
  specs.push({
    slotId: 'MSS_CIRCLE',
    x: g.circleX,
    y: g.circleY,
    w: g.circleDiameter,
    h: g.circleDiameter,
    color: MSS_COLORS.primary,
    layer: 5,
    kind: 'circle',
  })
  
  specs.push({
    slotId: 'MSS_CIRCLE_ICON',
    x: g.circleIconX,
    y: g.circleIconY,
    w: g.circleIconSize,
    h: g.circleIconSize,
    color: MSS_COLORS.primary,
    layer: 10,
    kind: 'circleIcon',
  })
  
  // Trend arrow
  specs.push({
    slotId: 'MSS_TREND_ARROW',
    x: g.leftTrendArrowX,
    y: g.leftTrendArrowY,
    w: 16,
    h: 16,
    color: MSS_COLORS.trend,
    layer: 10,
    kind: 'trendArrow',
  })
  
  // Context panel
  specs.push({
    slotId: 'MSS_PANEL_BG',
    x: g.panelX,
    y: g.panelY,
    w: g.panelW,
    h: g.panelH,
    color: MSS_COLORS.panelBg,
    layer: 3,
    kind: 'panelBg',
  })
  
  specs.push({
    slotId: 'MSS_PANEL_ICON_BG',
    x: g.panelIconX,
    y: g.panelIconY,
    w: g.panelIconBgSize,
    h: g.panelIconBgSize,
    color: MSS_COLORS.panelIcon,
    layer: 5,
    kind: 'panelIconBg',
  })
  
  specs.push({
    slotId: 'MSS_PANEL_ICON',
    x: g.panelIconX + (g.panelIconBgSize - g.panelIconSize) / 2,
    y: g.panelIconY + (g.panelIconBgSize - g.panelIconSize) / 2,
    w: g.panelIconSize,
    h: g.panelIconSize,
    color: MSS_COLORS.panelIcon,
    layer: 10,
    kind: 'panelIcon',
  })
  
  // Context items
  const items = [
    { y: g.item1Y, id: 1, color: MSS_COLORS.primary },
    { y: g.item2Y, id: 2, color: MSS_COLORS.primary },
    { y: g.item3Y, id: 3, color: MSS_COLORS.primary },
  ]
  
  items.forEach(item => {
    specs.push({
      slotId: `MSS_ITEM${item.id}_ICON_BG`,
      x: g.itemIconX,
      y: item.y,
      w: g.itemIconBgSize,
      h: g.itemIconBgSize,
      color: item.color,
      layer: 5,
      kind: 'itemIconBg',
    })
    
    specs.push({
      slotId: `MSS_ITEM${item.id}_ICON`,
      x: g.itemIconX + (g.itemIconBgSize - g.itemIconSize) / 2,
      y: item.y + (g.itemIconBgSize - g.itemIconSize) / 2,
      w: g.itemIconSize,
      h: g.itemIconSize,
      color: item.color,
      layer: 10,
      kind: `item${item.id}Icon`,
    })
  })
  
  // Decorative circles
  specs.push({
    slotId: 'MSS_DECO_CIRCLES',
    x: g.decoX,
    y: g.decoY,
    w: g.decoW,
    h: g.decoH,
    color: MSS_COLORS.deco,
    layer: 2,
    kind: 'decoCircles',
  })
  
  return specs
}

const metricSingleSplitOverlay = (gx, gy, gw, gh) => {
  const g = MSS_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  return {
    badge: box(g.leftBadgeX + g.leftBadgeIconSize + 14, g.leftBadgeY, g.leftBadgeW - g.leftBadgeIconSize - 18, g.leftBadgeH),
    heading: box(g.leftHeadingX, g.leftHeadingY, g.leftHeadingW, g.leftHeadingH),
    subheading: box(g.leftSubheadingX, g.leftSubheadingY, g.leftSubheadingW, g.leftSubheadingH),
    metricValue: box(g.leftMetricX, g.leftMetricY, g.leftMetricW, g.leftMetricH),
    trend: box(g.leftTrendX + 20, g.leftTrendY, g.leftTrendW - 20, g.leftTrendH),
    compare: box(g.leftCompareX, g.leftCompareY, g.leftCompareW, g.leftCompareH),
    panelHeading: box(g.panelHeadingX, g.panelHeadingY, g.panelHeadingW, g.panelHeadingH),
    panelDesc: box(g.panelDescX, g.panelDescY, g.panelDescW, g.panelDescH),
    item1Label: box(g.itemLabelX, g.item1Y, g.itemLabelW, g.itemLabelH),
    item1Value: box(g.itemValueX, g.item1Y + 20, g.itemValueW, g.itemValueH),
    item2Label: box(g.itemLabelX, g.item2Y, g.itemLabelW, g.itemLabelH),
    item2Value: box(g.itemValueX, g.item2Y + 20, g.itemValueW, g.itemValueH),
    item3Label: box(g.itemLabelX, g.item3Y, g.itemLabelW, g.itemLabelH),
    item3Value: box(g.itemValueX, g.item3Y + 20, g.itemValueW, g.itemValueH),
  }
}

const specToMetricSingleSplitContent = (spec) => {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'circle') return { svg: circleSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'circleIcon') return { svg: circleIconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'trendArrow') return { svg: trendArrowSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelBg') return { svg: panelBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIconBg') return { svg: panelIconBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIcon') return { svg: panelIconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'itemIconBg') return { svg: itemIconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'item1Icon') return { svg: item1IconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'item2Icon') return { svg: item2IconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'item3Icon') return { svg: item3IconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'decoCircles') return { svg: decoCirclesSvg(), colorMode: 'fixed', fill: spec.color }
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
    : (MSS_DEFAULTS[sid] || existing)
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

const layoutMetricSingleSplit = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / MSS_GEOM.viewW
  const sy = canvasH / MSS_GEOM.viewH
  const overlay = metricSingleSplitOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^MSS_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricSingleSplitTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-mss'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    placeText('BADGE', overlay.badge, {
      align: 'center', verticalAlign: 'center', fontSize: 9, fontWeight: 700, color: MSS_COLORS.badgeText, clipToSlot: true, lineHeight: 1, letterSpacing: '1.5px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 38, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'subheading'),
    placeText('METRIC_VALUE', overlay.metricValue, {
      align: 'left', verticalAlign: 'center', fontSize: 88, fontWeight: 900, color: MSS_COLORS.primary, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('TREND', overlay.trend, {
      align: 'left', verticalAlign: 'center', fontSize: 16, fontWeight: 700, color: MSS_COLORS.trend, clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('COMPARE', overlay.compare, {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('PANEL_HEADING', overlay.panelHeading, {
      align: 'left', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: '#1E293B', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('PANEL_DESC', overlay.panelDesc, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
  ]
  
  // Context items
  for (let i = 1; i <= 3; i++) {
    next.push(
      placeText(`ITEM${i}_LABEL`, overlay[`item${i}Label`], {
        align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 500, color: '#94A3B8', clipToSlot: true, lineHeight: 1.3,
      }, 'caption'),
      placeText(`ITEM${i}_VALUE`, overlay[`item${i}Value`], {
        align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 600, color: '#1E293B', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
      }, 'body')
    )
  }

  const chrome = metricSingleSplitChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToMetricSingleSplitContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-mss'),
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
  isMetricSingleSplitLayout: isMetricSingleSplitLayout,
  layoutMetricSingleSplit: layoutMetricSingleSplit,
  MSS_GEOM: MSS_GEOM,
  MSS_DEFAULTS: MSS_DEFAULTS,
};