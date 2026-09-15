/**
 * Grid insights chart — Three insight cards at top, large chart area on left, key takeaway panel on right.
 * Layout id: grid_insights_chart_v1.
 */

const GIC_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Three insight cards at top
  insight1X: 30,
  insight2X: 250,
  insight3X: 470,
  insightY: 30,
  insightW: 200,
  insightH: 120,
  insightGap: 20,
  insightRadius: 12,
  
  // Inside each insight card
  insightIconY: 20,
  insightIconSize: 60,
  insightLabelY: 90,
  insightLabelH: 20,
  
  // Chart area (large left area)
  chartX: 30,
  chartY: 170,
  chartW: 640,
  chartH: 360,
  chartRadius: 12,
  
  // Inside chart area
  chartTitleY: 20,
  chartTitleH: 40,
  chartBarsY: 180,
  chartBarsH: 140,
  chartCaptionY: 330,
  chartCaptionH: 20,
  
  // Key takeaway panel (right side)
  takeawayX: 690,
  takeawayY: 30,
  takeawayW: 280,
  takeawayH: 500,
  
  // Inside takeaway panel
  takeawayTitleY: 20,
  takeawayTitleH: 30,
  takeawayBodyY: 60,
  takeawayBodyH: 200,
  takeawayImageY: 280,
  takeawayImageW: 240,
  takeawayImageH: 200,
  takeawayImageRadius: 12,
}

const GIC_COLORS = {
  insightBg: '#F1F5F9',
  insightIcon: '#A5B4FC',
  chartBg: '#F8FAFC',
  bar: '#64748B',
  takeawayBg: '#FFFFFF',
  imagePlaceholder: '#E0E7FF',
}

const GIC_DEFAULTS = {
  INSIGHT_1: 'Insight 1',
  INSIGHT_2: 'Insight 2',
  INSIGHT_3: 'Insight 3',
  CHART_TITLE: 'Revenue growth',
  CHART_CAPTION: 'Monthly performance',
  TAKEAWAY_TITLE: 'Key takeaway',
  TAKEAWAY_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const isGridInsightsChartLayout = (layoutId) => {
  return /grid_insights_chart_v1$/i.test(String(layoutId || ''))
}

const isGridInsightsChartSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'INSIGHT_1'
    || sid === 'INSIGHT_2'
    || sid === 'INSIGHT_3'
    || sid === 'CHART_TITLE'
    || sid === 'CHART_CAPTION'
    || sid === 'TAKEAWAY_TITLE'
    || sid === 'TAKEAWAY_BODY'
}

const insightCardSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GIC_COLORS.insightBg}" rx="${radius}"/>
  </svg>`
}

const insightIconSvg = (size) => {
  const r = size / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <circle cx="${r}" cy="${r}" r="${r - 2}" fill="none" stroke="${GIC_COLORS.insightIcon}" stroke-width="3"/>
  </svg>`
}

const chartBgSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GIC_COLORS.chartBg}" rx="${radius}"/>
  </svg>`
}

const chartBarsSvg = (w, h) => {
  const barW = w / 7
  const gap = barW * 0.2
  const actualBarW = barW - gap
  
  const bars = [0.5, 0.7, 0.6, 0.8, 0.9] // Heights as percentage
  
  let barsSvg = ''
  bars.forEach((height, i) => {
    const x = (i + 1) * barW
    const barH = h * height
    const y = h - barH
    barsSvg += `<rect x="${x}" y="${y}" width="${actualBarW}" height="${barH}" fill="${GIC_COLORS.bar}" rx="4"/>`
  })
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    ${barsSvg}
  </svg>`
}

const imagePlaceholderSvg = (w, h) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="imgGradInsights" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:#E0E7FF;stop-opacity:1" />
        <stop offset="100%" style="stop-color:#C7D2FE;stop-opacity:1" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${w}" height="${h}" fill="url(#imgGradInsights)" rx="12"/>
    <!-- Image icon -->
    <rect x="${w*0.4}" y="${h*0.4}" width="${w*0.2}" height="${h*0.15}" fill="white" opacity="0.6" rx="2"/>
    <circle cx="${w*0.43}" cy="${h*0.45}" r="${w*0.025}" fill="white" opacity="0.6"/>
    <path d="M${w*0.4} ${h*0.55} L${w*0.45} ${h*0.48} L${w*0.52} ${h*0.53} L${w*0.6} ${h*0.45} L${w*0.6} ${h*0.55} Z" fill="white" opacity="0.6"/>
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

const gridInsightsChartChromeSpecs = () => {
  const g = GIC_GEOM
  const specs = []
  
  // Three insight cards
  const insightXs = [g.insight1X, g.insight2X, g.insight3X]
  insightXs.forEach((x, i) => {
    specs.push({
      slotId: `GIC_INSIGHT${i+1}_BG`,
      x: x,
      y: g.insightY,
      w: g.insightW,
      h: g.insightH,
      color: GIC_COLORS.insightBg,
      layer: 2,
      kind: 'insightCard',
    })
    
    specs.push({
      slotId: `GIC_INSIGHT${i+1}_ICON`,
      x: x + (g.insightW - g.insightIconSize) / 2,
      y: g.insightY + g.insightIconY,
      w: g.insightIconSize,
      h: g.insightIconSize,
      color: GIC_COLORS.insightIcon,
      layer: 3,
      kind: 'insightIcon',
    })
  })
  
  // Chart background
  specs.push({
    slotId: 'GIC_CHART_BG',
    x: g.chartX,
    y: g.chartY,
    w: g.chartW,
    h: g.chartH,
    color: GIC_COLORS.chartBg,
    layer: 2,
    kind: 'chartBg',
  })
  
  // Chart bars
  specs.push({
    slotId: 'GIC_CHART_BARS',
    x: g.chartX + 40,
    y: g.chartY + g.chartBarsY,
    w: g.chartW - 80,
    h: g.chartBarsH,
    color: GIC_COLORS.bar,
    layer: 3,
    kind: 'chartBars',
  })
  
  return specs
}

const gridInsightsChartOverlay = (gx, gy, gw, gh) => {
  const g = GIC_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const insightXs = [g.insight1X, g.insight2X, g.insight3X]
  
  const overlays = {}
  
  // Insight labels
  insightXs.forEach((x, i) => {
    overlays[`insight${i+1}`] = box(x + 10, g.insightY + g.insightLabelY, g.insightW - 20, g.insightLabelH)
  })
  
  // Chart title and caption
  overlays.chartTitle = box(g.chartX + 40, g.chartY + g.chartTitleY, g.chartW - 80, g.chartTitleH)
  overlays.chartCaption = box(g.chartX + 40, g.chartY + g.chartCaptionY, g.chartW - 80, g.chartCaptionH)
  
  // Takeaway panel
  overlays.takeawayTitle = box(g.takeawayX + 20, g.takeawayY + g.takeawayTitleY, g.takeawayW - 40, g.takeawayTitleH)
  overlays.takeawayBody = box(g.takeawayX + 20, g.takeawayY + g.takeawayBodyY, g.takeawayW - 40, g.takeawayBodyH)
  
  return overlays
}

const specToGridInsightsChartContent = (spec) => {
  if (spec.kind === 'insightCard') {
    return { svg: insightCardSvg(spec.w, spec.h, GIC_GEOM.insightRadius), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'insightIcon') {
    return { svg: insightIconSvg(spec.w), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'chartBg') {
    return { svg: chartBgSvg(spec.w, spec.h, GIC_GEOM.chartRadius), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'chartBars') {
    return { svg: chartBarsSvg(spec.w, spec.h), colorMode: 'fixed', fill: spec.color }
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
    : (GIC_DEFAULTS[sid] || existing)
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

const layoutGridInsightsChart = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GIC_GEOM.viewW
  const sy = canvasH / GIC_GEOM.viewH
  const overlay = gridInsightsChartOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GIC_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridInsightsChartSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))
  
  // Get existing image element
  const imageSlots = elements.filter((el) => el.type === 'image' && el.slotId === 'TAKEAWAY_IMAGE')
  const imageBySlot = new Map(imageSlots.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gic'),
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
    const g = GIC_GEOM
    
    return {
      id: prev?.id || newId('img-gic'),
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
        borderRadius: g.takeawayImageRadius,
        name: prev?.content?.name || slotId,
        ...(hasImage ? {} : {
          placeholderSvg: imagePlaceholderSvg(w, h),
        }),
      },
    }
  }

  const g = GIC_GEOM
  
  const next = [
    // Three insights
    placeText('INSIGHT_1', overlay.insight1, {
      align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#475569', clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('INSIGHT_2', overlay.insight2, {
      align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#475569', clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('INSIGHT_3', overlay.insight3, {
      align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 600, color: '#475569', clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    
    // Chart
    placeText('CHART_TITLE', overlay.chartTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 32, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('CHART_CAPTION', overlay.chartCaption, {
      align: 'center', verticalAlign: 'center', fontSize: 13, fontWeight: 400, color: '#94A3B8', clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    
    // Takeaway panel
    placeText('TAKEAWAY_TITLE', overlay.takeawayTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 24, fontWeight: 700, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('TAKEAWAY_BODY', overlay.takeawayBody, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    // Takeaway image
    placeImage('TAKEAWAY_IMAGE', g.takeawayX + 20, g.takeawayY + g.takeawayImageY, g.takeawayImageW, g.takeawayImageH),
  ]

  const chrome = gridInsightsChartChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridInsightsChartContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gic'),
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
  GIC_GEOM,
  GIC_COLORS,
  GIC_DEFAULTS,
  isGridInsightsChartLayout,
  isGridInsightsChartSlot,
  gridInsightsChartChromeSpecs,
  gridInsightsChartOverlay,
  specToGridInsightsChartContent,
  layoutGridInsightsChart,
}
