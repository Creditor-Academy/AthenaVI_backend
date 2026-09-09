/**
 * Metric two split — Two metrics on left, context panel on right.
 * Layout id: metric_two_split_v1.
 */

const MTS_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Left side - Badge and heading
  leftBadgeX: 40,
  leftBadgeY: 70,
  leftBadgeW: 140,
  leftBadgeH: 24,
  leftBadgeIconSize: 14,
  
  leftHeadingX: 40,
  leftHeadingY: 110,
  leftHeadingW: 480,
  leftHeadingH: 50,
  
  leftSubheadingX: 40,
  leftSubheadingY: 165,
  leftSubheadingW: 480,
  leftSubheadingH: 40,
  
  // Two metric cards on left (stacked vertically in a light background)
  leftCardX: 40,
  leftCardY: 220,
  leftCardW: 480,
  leftCardH: 230,
  
  // First metric (top)
  metric1X: 60,
  metric1Y: 240,
  metric1W: 220,
  
  metric1IconX: 20,
  metric1IconY: 0,
  metric1IconSize: 40,
  metric1IconBgSize: 56,
  
  metric1LabelX: 0,
  metric1LabelY: 70,
  metric1LabelW: 220,
  metric1LabelH: 26,
  
  metric1ValueX: 0,
  metric1ValueY: 100,
  metric1ValueW: 220,
  metric1ValueH: 68,
  
  metric1TrendX: 0,
  metric1TrendY: 175,
  metric1TrendW: 80,
  metric1TrendH: 20,
  metric1TrendArrowX: 0,
  metric1TrendArrowY: 177,
  
  metric1CompareX: 85,
  metric1CompareY: 175,
  metric1CompareW: 135,
  metric1CompareH: 20,
  
  metric1UnderlineX: 0,
  metric1UnderlineY: 203,
  metric1UnderlineW: 150,
  metric1UnderlineH: 4,
  
  // Second metric (bottom)
  metric2X: 300,
  metric2Y: 240,
  metric2W: 220,
  
  metric2IconX: 20,
  metric2IconY: 0,
  metric2IconSize: 40,
  metric2IconBgSize: 56,
  
  metric2LabelX: 0,
  metric2LabelY: 70,
  metric2LabelW: 220,
  metric2LabelH: 26,
  
  metric2ValueX: 0,
  metric2ValueY: 100,
  metric2ValueW: 220,
  metric2ValueH: 68,
  
  metric2TrendX: 0,
  metric2TrendY: 175,
  metric2TrendW: 80,
  metric2TrendH: 20,
  metric2TrendArrowX: 0,
  metric2TrendArrowY: 177,
  
  metric2CompareX: 85,
  metric2CompareY: 175,
  metric2CompareW: 135,
  metric2CompareH: 20,
  
  metric2UnderlineX: 0,
  metric2UnderlineY: 203,
  metric2UnderlineW: 150,
  metric2UnderlineH: 4,
  
  // Right side - Context panel
  panelX: 560,
  panelY: 70,
  panelW: 400,
  panelH: 380,
  
  panelIconX: 595,
  panelIconY: 95,
  panelIconSize: 32,
  panelIconBgSize: 48,
  
  panelHeadingX: 655,
  panelHeadingY: 95,
  panelHeadingW: 270,
  panelHeadingH: 40,
  
  panelDotsX: 915,
  panelDotsY: 95,
  panelDotsW: 40,
  panelDotsH: 14,
  
  // Context items in panel
  item1Y: 160,
  item2Y: 280,
  itemDotX: 595,
  itemDotSize: 10,
  
  itemHeadingX: 620,
  itemHeadingW: 320,
  itemHeadingH: 24,
  
  itemDescX: 620,
  itemDescW: 320,
  itemDescH: 95,
  
  // Decorative circles (bottom left)
  decoX: 0,
  decoY: 440,
  decoW: 200,
  decoH: 120,
}

const MTS_COLORS = {
  metric1: '#3B82F6',  // Blue
  metric2: '#8B5CF6',  // Purple
  trend: '#10B981',
  badge: '#DBEAFE',
  badgeText: '#3B82F6',
  leftCardBg: '#F8FAFC',
  panelBg: '#F8FAFC',
  panelIcon: '#3B82F6',
  panelDots: '#3B82F6',
  deco: '#DBEAFE',
}

const MTS_DEFAULTS = {
  BADGE: 'KEY METRICS',
  HEADING: 'Customer performance',
  SUBHEADING: 'Key indicators that reflect customer satisfaction and engagement with our services.',
  
  METRIC1_LABEL: 'Customer satisfaction',
  METRIC1_VALUE: '98%',
  METRIC1_TREND: '+12%',
  METRIC1_COMPARE: 'vs. last quarter',
  
  METRIC2_LABEL: 'Average ROI',
  METRIC2_VALUE: '3.2x',
  METRIC2_TREND: '+12%',
  METRIC2_COMPARE: 'vs. last quarter',
  
  PANEL_HEADING: 'Context',
  
  ITEM1_HEADING: 'Customer satisfaction',
  ITEM1_DESC: 'Customer satisfaction remains strong, reflecting consistent service delivery and positive feedback across key touchpoints. This highlights the continued trust and loyalty of our customers.',
  
  ITEM2_HEADING: 'Average ROI',
  ITEM2_DESC: 'The average ROI shows steady growth, indicating improved efficiency and higher value delivery from our services. This suggests our investments are driving strong returns and long-term impact.',
}

const isMetricTwoSplitLayout = (layoutId) => {
  return /metric_two_split_v1$/i.test(String(layoutId || ''))
}

const isMetricTwoSplitTextSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'BADGE'
    || sid === 'HEADING'
    || sid === 'SUBHEADING'
    || sid === 'METRIC1_LABEL'
    || sid === 'METRIC1_VALUE'
    || sid === 'METRIC1_TREND'
    || sid === 'METRIC1_COMPARE'
    || sid === 'METRIC2_LABEL'
    || sid === 'METRIC2_VALUE'
    || sid === 'METRIC2_TREND'
    || sid === 'METRIC2_COMPARE'
    || sid === 'PANEL_HEADING'
    || sid === 'ITEM1_HEADING'
    || sid === 'ITEM1_DESC'
    || sid === 'ITEM2_HEADING'
    || sid === 'ITEM2_DESC'
}

const badgeSvg = () => {
  const g = MTS_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.leftBadgeW} ${g.leftBadgeH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.leftBadgeW}" height="${g.leftBadgeH}" fill="${MTS_COLORS.badge}" rx="7"/>
  </svg>`
}

const badgeIconSvg = () => {
  const size = MTS_GEOM.leftBadgeIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="1" y="4" width="3" height="7" rx="0.5" fill="${MTS_COLORS.badgeText}"/>
    <rect x="5" y="2" width="3" height="9" rx="0.5" fill="${MTS_COLORS.badgeText}"/>
    <rect x="9" y="5" width="3" height="6" rx="0.5" fill="${MTS_COLORS.badgeText}"/>
  </svg>`
}

const leftCardBgSvg = () => {
  const g = MTS_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.leftCardW} ${g.leftCardH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.leftCardW}" height="${g.leftCardH}" fill="${MTS_COLORS.leftCardBg}" rx="18"/>
  </svg>`
}

const iconBgSvg = (color) => {
  const size = MTS_GEOM.metric1IconBgSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size/2}" cy="${size/2}" r="${size/2}" fill="${color}" fill-opacity="0.12"/>
  </svg>`
}

const icon1Svg = () => {
  const size = MTS_GEOM.metric1IconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="13" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2.5"/>
    <circle cx="27" cy="12" r="6" fill="none" stroke="currentColor" stroke-width="2.5"/>
    <path d="M7 27 Q10 24 13 24 Q16 24 20 24 Q24 24 27 24 Q30 24 33 27 L33 34 L7 34 Z" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/>
  </svg>`
}

const icon2Svg = () => {
  const size = MTS_GEOM.metric2IconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <path d="M7 28 L14 14 L21 21 L33 9" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    <polyline points="26,9 33,9 33,16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`
}

const underlineSvg = (color) => {
  const g = MTS_GEOM
  const w = g.metric1UnderlineW
  const h = g.metric1UnderlineH
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${color}" rx="2"/>
  </svg>`
}

const trendArrowSvg = () => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 14 14" width="14" height="14">
    <path d="M3 9 L7 4 L11 9" fill="none" stroke="${MTS_COLORS.trend}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`
}

const panelBgSvg = () => {
  const g = MTS_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.panelW} ${g.panelH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${g.panelW}" height="${g.panelH}" fill="${MTS_COLORS.panelBg}" rx="20"/>
  </svg>`
}

const panelIconBgSvg = () => {
  const size = MTS_GEOM.panelIconBgSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="0" y="0" width="${size}" height="${size}" fill="${MTS_COLORS.panelIcon}" fill-opacity="0.12" rx="10"/>
  </svg>`
}

const panelIconSvg = () => {
  const size = MTS_GEOM.panelIconSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <rect x="6" y="4" width="20" height="24" rx="2" fill="none" stroke="currentColor" stroke-width="2"/>
    <line x1="10" y1="10" x2="22" y2="10" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="10" y1="15" x2="22" y2="15" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <line x1="10" y1="20" x2="18" y2="20" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
  </svg>`
}

const panelDotsSvg = () => {
  const g = MTS_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.panelDotsW} ${g.panelDotsH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="7" cy="7" r="6" fill="${MTS_COLORS.panelDots}"/>
    <circle cx="20" cy="7" r="6" fill="${MTS_COLORS.panelDots}" opacity="0.5"/>
    <circle cx="33" cy="7" r="6" fill="${MTS_COLORS.panelDots}" opacity="0.3"/>
  </svg>`
}

const itemDotSvg = (color) => {
  const size = MTS_GEOM.itemDotSize
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${size/2}" cy="${size/2}" r="${size/2}" fill="${color}"/>
  </svg>`
}

const decoCirclesSvg = () => {
  const w = 200
  const h = 120
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <circle cx="30" cy="60" r="80" fill="${MTS_COLORS.deco}" opacity="0.25"/>
    <circle cx="80" cy="90" r="60" fill="${MTS_COLORS.deco}" opacity="0.4"/>
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

const metricTwoSplitChromeSpecs = () => {
  const g = MTS_GEOM
  const specs = []
  
  // Badge
  specs.push({
    slotId: 'MTS_BADGE_BG',
    x: g.leftBadgeX,
    y: g.leftBadgeY,
    w: g.leftBadgeW,
    h: g.leftBadgeH,
    color: MTS_COLORS.badge,
    layer: 3,
    kind: 'badge',
  })
  
  specs.push({
    slotId: 'MTS_BADGE_ICON',
    x: g.leftBadgeX + 10,
    y: g.leftBadgeY + 5,
    w: g.leftBadgeIconSize,
    h: g.leftBadgeIconSize,
    color: MTS_COLORS.badgeText,
    layer: 10,
    kind: 'badgeIcon',
  })
  
  // Left card background
  specs.push({
    slotId: 'MTS_LEFT_CARD_BG',
    x: g.leftCardX,
    y: g.leftCardY,
    w: g.leftCardW,
    h: g.leftCardH,
    color: MTS_COLORS.leftCardBg,
    layer: 3,
    kind: 'leftCardBg',
  })
  
  // Metric 1
  specs.push({
    slotId: 'MTS_METRIC1_ICON_BG',
    x: g.metric1X + g.metric1IconX,
    y: g.metric1Y + g.metric1IconY,
    w: g.metric1IconBgSize,
    h: g.metric1IconBgSize,
    color: MTS_COLORS.metric1,
    layer: 5,
    kind: 'iconBg',
  })
  
  specs.push({
    slotId: 'MTS_METRIC1_ICON',
    x: g.metric1X + g.metric1IconX + (g.metric1IconBgSize - g.metric1IconSize) / 2,
    y: g.metric1Y + g.metric1IconY + (g.metric1IconBgSize - g.metric1IconSize) / 2,
    w: g.metric1IconSize,
    h: g.metric1IconSize,
    color: MTS_COLORS.metric1,
    layer: 10,
    kind: 'icon1',
  })
  
  specs.push({
    slotId: 'MTS_METRIC1_UNDERLINE',
    x: g.metric1X + g.metric1UnderlineX,
    y: g.metric1Y + g.metric1UnderlineY,
    w: g.metric1UnderlineW,
    h: g.metric1UnderlineH,
    color: MTS_COLORS.metric1,
    layer: 10,
    kind: 'underline',
  })
  
  specs.push({
    slotId: 'MTS_METRIC1_TREND_ARROW',
    x: g.metric1X + g.metric1TrendArrowX,
    y: g.metric1Y + g.metric1TrendArrowY,
    w: 14,
    h: 14,
    color: MTS_COLORS.trend,
    layer: 10,
    kind: 'trendArrow',
  })
  
  // Metric 2
  specs.push({
    slotId: 'MTS_METRIC2_ICON_BG',
    x: g.metric2X + g.metric2IconX,
    y: g.metric2Y + g.metric2IconY,
    w: g.metric2IconBgSize,
    h: g.metric2IconBgSize,
    color: MTS_COLORS.metric2,
    layer: 5,
    kind: 'iconBg',
  })
  
  specs.push({
    slotId: 'MTS_METRIC2_ICON',
    x: g.metric2X + g.metric2IconX + (g.metric2IconBgSize - g.metric2IconSize) / 2,
    y: g.metric2Y + g.metric2IconY + (g.metric2IconBgSize - g.metric2IconSize) / 2,
    w: g.metric2IconSize,
    h: g.metric2IconSize,
    color: MTS_COLORS.metric2,
    layer: 10,
    kind: 'icon2',
  })
  
  specs.push({
    slotId: 'MTS_METRIC2_UNDERLINE',
    x: g.metric2X + g.metric2UnderlineX,
    y: g.metric2Y + g.metric2UnderlineY,
    w: g.metric2UnderlineW,
    h: g.metric2UnderlineH,
    color: MTS_COLORS.metric2,
    layer: 10,
    kind: 'underline',
  })
  
  specs.push({
    slotId: 'MTS_METRIC2_TREND_ARROW',
    x: g.metric2X + g.metric2TrendArrowX,
    y: g.metric2Y + g.metric2TrendArrowY,
    w: 14,
    h: 14,
    color: MTS_COLORS.trend,
    layer: 10,
    kind: 'trendArrow',
  })
  
  // Context panel
  specs.push({
    slotId: 'MTS_PANEL_BG',
    x: g.panelX,
    y: g.panelY,
    w: g.panelW,
    h: g.panelH,
    color: MTS_COLORS.panelBg,
    layer: 3,
    kind: 'panelBg',
  })
  
  specs.push({
    slotId: 'MTS_PANEL_ICON_BG',
    x: g.panelIconX,
    y: g.panelIconY,
    w: g.panelIconBgSize,
    h: g.panelIconBgSize,
    color: MTS_COLORS.panelIcon,
    layer: 5,
    kind: 'panelIconBg',
  })
  
  specs.push({
    slotId: 'MTS_PANEL_ICON',
    x: g.panelIconX + (g.panelIconBgSize - g.panelIconSize) / 2,
    y: g.panelIconY + (g.panelIconBgSize - g.panelIconSize) / 2,
    w: g.panelIconSize,
    h: g.panelIconSize,
    color: MTS_COLORS.panelIcon,
    layer: 10,
    kind: 'panelIcon',
  })
  
  specs.push({
    slotId: 'MTS_PANEL_DOTS',
    x: g.panelDotsX,
    y: g.panelDotsY,
    w: g.panelDotsW,
    h: g.panelDotsH,
    color: MTS_COLORS.panelDots,
    layer: 10,
    kind: 'panelDots',
  })
  
  // Context item dots
  specs.push({
    slotId: 'MTS_ITEM1_DOT',
    x: g.itemDotX,
    y: g.item1Y,
    w: g.itemDotSize,
    h: g.itemDotSize,
    color: MTS_COLORS.metric1,
    layer: 10,
    kind: 'itemDot',
  })
  
  specs.push({
    slotId: 'MTS_ITEM2_DOT',
    x: g.itemDotX,
    y: g.item2Y,
    w: g.itemDotSize,
    h: g.itemDotSize,
    color: MTS_COLORS.metric2,
    layer: 10,
    kind: 'itemDot',
  })
  
  // Decorative circles
  specs.push({
    slotId: 'MTS_DECO_CIRCLES',
    x: g.decoX,
    y: g.decoY,
    w: g.decoW,
    h: g.decoH,
    color: MTS_COLORS.deco,
    layer: 2,
    kind: 'decoCircles',
  })
  
  return specs
}

const metricTwoSplitOverlay = (gx, gy, gw, gh) => {
  const g = MTS_GEOM
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
    
    metric1Label: box(g.metric1X + g.metric1LabelX, g.metric1Y + g.metric1LabelY, g.metric1LabelW, g.metric1LabelH),
    metric1Value: box(g.metric1X + g.metric1ValueX, g.metric1Y + g.metric1ValueY, g.metric1ValueW, g.metric1ValueH),
    metric1Trend: box(g.metric1X + g.metric1TrendX + 18, g.metric1Y + g.metric1TrendY, g.metric1TrendW - 18, g.metric1TrendH),
    metric1Compare: box(g.metric1X + g.metric1CompareX, g.metric1Y + g.metric1CompareY, g.metric1CompareW, g.metric1CompareH),
    
    metric2Label: box(g.metric2X + g.metric2LabelX, g.metric2Y + g.metric2LabelY, g.metric2LabelW, g.metric2LabelH),
    metric2Value: box(g.metric2X + g.metric2ValueX, g.metric2Y + g.metric2ValueY, g.metric2ValueW, g.metric2ValueH),
    metric2Trend: box(g.metric2X + g.metric2TrendX + 18, g.metric2Y + g.metric2TrendY, g.metric2TrendW - 18, g.metric2TrendH),
    metric2Compare: box(g.metric2X + g.metric2CompareX, g.metric2Y + g.metric2CompareY, g.metric2CompareW, g.metric2CompareH),
    
    panelHeading: box(g.panelHeadingX, g.panelHeadingY, g.panelHeadingW, g.panelHeadingH),
    
    item1Heading: box(g.itemHeadingX, g.item1Y, g.itemHeadingW, g.itemHeadingH),
    item1Desc: box(g.itemDescX, g.item1Y + 28, g.itemDescW, g.itemDescH),
    
    item2Heading: box(g.itemHeadingX, g.item2Y, g.itemHeadingW, g.itemHeadingH),
    item2Desc: box(g.itemDescX, g.item2Y + 28, g.itemDescW, g.itemDescH),
  }
}

const specToMetricTwoSplitContent = (spec) => {
  if (spec.kind === 'badge') return { svg: badgeSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'badgeIcon') return { svg: badgeIconSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'leftCardBg') return { svg: leftCardBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'iconBg') return { svg: iconBgSvg(spec.color), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'icon1') return { svg: icon1Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'icon2') return { svg: icon2Svg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'underline') return { svg: underlineSvg(spec.color), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'trendArrow') return { svg: trendArrowSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelBg') return { svg: panelBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIconBg') return { svg: panelIconBgSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'panelIcon') return { svg: panelIconSvg(), colorMode: 'recolor', fill: spec.color }
  if (spec.kind === 'panelDots') return { svg: panelDotsSvg(), colorMode: 'fixed', fill: spec.color }
  if (spec.kind === 'itemDot') return { svg: itemDotSvg(spec.color), colorMode: 'fixed', fill: spec.color }
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
    : (MTS_DEFAULTS[sid] || existing)
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

const layoutMetricTwoSplit = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / MTS_GEOM.viewW
  const sy = canvasH / MTS_GEOM.viewH
  const overlay = metricTwoSplitOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^MTS_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isMetricTwoSplitTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-mts'),
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
      align: 'center', verticalAlign: 'center', fontSize: 9, fontWeight: 700, color: MTS_COLORS.badgeText, clipToSlot: true, lineHeight: 1, letterSpacing: '1.5px',
    }, 'caption'),
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'top', fontSize: 40, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('SUBHEADING', overlay.subheading, {
      align: 'left', verticalAlign: 'top', fontSize: 13, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'subheading'),
    
    placeText('METRIC1_LABEL', overlay.metric1Label, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#64748B', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('METRIC1_VALUE', overlay.metric1Value, {
      align: 'left', verticalAlign: 'center', fontSize: 58, fontWeight: 900, color: MTS_COLORS.metric1, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('METRIC1_TREND', overlay.metric1Trend, {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 700, color: MTS_COLORS.trend, clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('METRIC1_COMPARE', overlay.metric1Compare, {
      align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    
    placeText('METRIC2_LABEL', overlay.metric2Label, {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#64748B', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('METRIC2_VALUE', overlay.metric2Value, {
      align: 'left', verticalAlign: 'center', fontSize: 58, fontWeight: 900, color: MTS_COLORS.metric2, clipToSlot: true, lineHeight: 1,
    }, 'heading'),
    placeText('METRIC2_TREND', overlay.metric2Trend, {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 700, color: MTS_COLORS.trend, clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    placeText('METRIC2_COMPARE', overlay.metric2Compare, {
      align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1,
    }, 'caption'),
    
    placeText('PANEL_HEADING', overlay.panelHeading, {
      align: 'left', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: '#1E293B', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    
    placeText('ITEM1_HEADING', overlay.item1Heading, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('ITEM1_DESC', overlay.item1Desc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    placeText('ITEM2_HEADING', overlay.item2Heading, {
      align: 'left', verticalAlign: 'top', fontSize: 15, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.3,
    }, 'caption'),
    placeText('ITEM2_DESC', overlay.item2Desc, {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
  ]

  const chrome = metricTwoSplitChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToMetricTwoSplitContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-mts'),
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
  isMetricTwoSplitLayout: isMetricTwoSplitLayout,
  layoutMetricTwoSplit: layoutMetricTwoSplit,
  MTS_GEOM: MTS_GEOM,
  MTS_DEFAULTS: MTS_DEFAULTS,
};