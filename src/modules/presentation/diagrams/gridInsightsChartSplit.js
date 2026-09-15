/**
 * Grid insights chart split — Left column with 3 insights + takeaway, right column with large chart.
 * Layout id: grid_insights_chart_split_v1.
 */

const GICS_GEOM = {
  viewW: 1000,
  viewH: 560,
  
  // Left column container
  leftX: 30,
  leftY: 40,
  leftW: 460,
  leftH: 480,
  leftRadius: 12,
  leftPadding: 20,
  
  // Three insight cards (stacked vertically in left column)
  insightW: 420,
  insightH: 52,
  insightGap: 14,
  insightRadius: 8,
  insight1Y: 60,
  insight2Y: 126,
  insight3Y: 192,
  
  // Key takeaway (in left column, below insights)
  takeawayY: 270,
  takeawayTitleH: 30,
  takeawayBodyY: 310,
  takeawayBodyH: 180,
  
  // Right column - chart area
  chartX: 510,
  chartY: 40,
  chartW: 460,
  chartH: 480,
  chartRadius: 12,
  chartPadding: 30,
  
  // Inside chart area
  chartTitleY: 70,
  chartTitleH: 40,
  chartBarsY: 180,
  chartBarsW: 400,
  chartBarsH: 280,
}

const GICS_COLORS = {
  leftBg: '#F1F5F9',
  insightBg: '#E2E8F0',
  chartBg: '#F1F5F9',
  bar: '#64748B',
}

const GICS_DEFAULTS = {
  INSIGHT_1: 'Insight 1',
  INSIGHT_2: 'Insight 2',
  INSIGHT_3: 'Insight 3',
  CHART_TITLE: 'Revenue growth',
  TAKEAWAY_TITLE: 'Key takeaway',
  TAKEAWAY_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const isGridInsightsChartSplitLayout = (layoutId) => {
  return /grid_insights_chart_split_v1$/i.test(String(layoutId || ''))
}

const isGridInsightsChartSplitSlot = (slotId) => {
  const sid = String(slotId || '')
  return sid === 'INSIGHT_1'
    || sid === 'INSIGHT_2'
    || sid === 'INSIGHT_3'
    || sid === 'CHART_TITLE'
    || sid === 'TAKEAWAY_TITLE'
    || sid === 'TAKEAWAY_BODY'
}

const leftColumnBgSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GICS_COLORS.leftBg}" rx="${radius}"/>
  </svg>`
}

const insightCardSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GICS_COLORS.insightBg}" rx="${radius}"/>
  </svg>`
}

const chartBgSvg = (w, h, radius) => {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${GICS_COLORS.chartBg}" rx="${radius}"/>
  </svg>`
}

const chartBarsSvg = (w, h) => {
  const barW = w / 7
  const gap = barW * 0.15
  const actualBarW = barW - gap
  
  const bars = [0.45, 0.65, 0.55, 0.75, 0.95] // Heights as percentage
  
  let barsSvg = ''
  bars.forEach((height, i) => {
    const x = (i + 1) * barW
    const barH = h * height
    const y = h - barH
    barsSvg += `<rect x="${x}" y="${y}" width="${actualBarW}" height="${barH}" fill="${GICS_COLORS.bar}" rx="4"/>`
  })
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    ${barsSvg}
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

const gridInsightsChartSplitChromeSpecs = () => {
  const g = GICS_GEOM
  const specs = []
  
  // Left column background
  specs.push({
    slotId: 'GICS_LEFT_BG',
    x: g.leftX,
    y: g.leftY,
    w: g.leftW,
    h: g.leftH,
    color: GICS_COLORS.leftBg,
    layer: 1,
    kind: 'leftBg',
  })
  
  // Three insight cards (stacked)
  const insightYs = [g.insight1Y, g.insight2Y, g.insight3Y]
  insightYs.forEach((y, i) => {
    specs.push({
      slotId: `GICS_INSIGHT${i+1}_BG`,
      x: g.leftX + g.leftPadding,
      y: y,
      w: g.insightW,
      h: g.insightH,
      color: GICS_COLORS.insightBg,
      layer: 2,
      kind: 'insightCard',
    })
  })
  
  // Chart background
  specs.push({
    slotId: 'GICS_CHART_BG',
    x: g.chartX,
    y: g.chartY,
    w: g.chartW,
    h: g.chartH,
    color: GICS_COLORS.chartBg,
    layer: 1,
    kind: 'chartBg',
  })
  
  // Chart bars
  specs.push({
    slotId: 'GICS_CHART_BARS',
    x: g.chartX + g.chartPadding,
    y: g.chartY + g.chartBarsY,
    w: g.chartBarsW,
    h: g.chartBarsH,
    color: GICS_COLORS.bar,
    layer: 3,
    kind: 'chartBars',
  })
  
  return specs
}

const gridInsightsChartSplitOverlay = (gx, gy, gw, gh) => {
  const g = GICS_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(12, Math.round(w * sx)),
    height: Math.max(10, Math.round(h * sy)),
  })
  
  const overlays = {}
  
  // Insight cards
  const insightYs = [g.insight1Y, g.insight2Y, g.insight3Y]
  insightYs.forEach((y, i) => {
    overlays[`insight${i+1}`] = box(
      g.leftX + g.leftPadding + 16,
      y + 16,
      g.insightW - 32,
      g.insightH - 32
    )
  })
  
  // Takeaway in left column
  overlays.takeawayTitle = box(
    g.leftX + g.leftPadding,
    g.takeawayY,
    g.insightW,
    g.takeawayTitleH
  )
  overlays.takeawayBody = box(
    g.leftX + g.leftPadding,
    g.takeawayBodyY,
    g.insightW,
    g.takeawayBodyH
  )
  
  // Chart title
  overlays.chartTitle = box(
    g.chartX + g.chartPadding,
    g.chartTitleY,
    g.chartBarsW,
    g.chartTitleH
  )
  
  return overlays
}

const specToGridInsightsChartSplitContent = (spec) => {
  if (spec.kind === 'leftBg') {
    return { svg: leftColumnBgSvg(spec.w, spec.h, GICS_GEOM.leftRadius), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'insightCard') {
    return { svg: insightCardSvg(spec.w, spec.h, GICS_GEOM.insightRadius), colorMode: 'fixed', fill: spec.color }
  }
  if (spec.kind === 'chartBg') {
    return { svg: chartBgSvg(spec.w, spec.h, GICS_GEOM.chartRadius), colorMode: 'fixed', fill: spec.color }
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
    : (GICS_DEFAULTS[sid] || existing)
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

const layoutGridInsightsChartSplit = (elements, schema, palette = {}, canvas = {}) => {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / GICS_GEOM.viewW
  const sy = canvasH / GICS_GEOM.viewH
  const overlay = gridInsightsChartSplitOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^GICS_/i
  
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isGridInsightsChartSplitSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || ''), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId) || bySlot.get(slotId.toUpperCase())
    return {
      id: prev?.id || newId('txt-gics'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    // Three insights in left column
    placeText('INSIGHT_1', overlay.insight1, {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 600, color: '#334155', clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('INSIGHT_2', overlay.insight2, {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 600, color: '#334155', clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    placeText('INSIGHT_3', overlay.insight3, {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 600, color: '#334155', clipToSlot: true, lineHeight: 1.2,
    }, 'caption'),
    
    // Takeaway in left column
    placeText('TAKEAWAY_TITLE', overlay.takeawayTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 20, fontWeight: 700, color: '#1E293B', clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
    placeText('TAKEAWAY_BODY', overlay.takeawayBody, {
      align: 'left', verticalAlign: 'top', fontSize: 14, fontWeight: 400, color: '#64748B', clipToSlot: true, lineHeight: 1.5, wrap: 'wrap',
    }, 'body'),
    
    // Chart title in right column
    placeText('CHART_TITLE', overlay.chartTitle, {
      align: 'left', verticalAlign: 'top', fontSize: 36, fontWeight: 800, color: headingInk(palette), clipToSlot: true, lineHeight: 1.2,
    }, 'heading'),
  ]

  const chrome = gridInsightsChartSplitChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToGridInsightsChartSplitContent(spec)
    if (!graphic) return null
    return {
      id: prev?.id || newId('shp-gics'),
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
  GICS_GEOM,
  GICS_COLORS,
  GICS_DEFAULTS,
  isGridInsightsChartSplitLayout,
  isGridInsightsChartSplitSlot,
  gridInsightsChartSplitChromeSpecs,
  gridInsightsChartSplitOverlay,
  specToGridInsightsChartSplitContent,
  layoutGridInsightsChartSplit,
}
