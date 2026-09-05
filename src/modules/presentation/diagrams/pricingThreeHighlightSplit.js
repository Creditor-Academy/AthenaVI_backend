/**
 * Pricing three highlight split — chevron headers, feature table, MORE INFORMATION buttons.
 * Layout id: pricing_three_highlight_split_v1 only.
 */

const PRICING_HS_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 80,
  headingY: 16,
  headingW: 840,
  headingH: 42,
  padX: 44,
  labelW: 250,
  n: 3,
  rows: 5,
  headerY: 80,
  headerH: 78,
  chevH: 16,
  chevW: 30,
  rowH: 52,
  btnH: 44,
  btnGap: 56,
  btnInset: 12,
  ctaNudgeY: 8,
}

const PRICING_HS_PALETTE = ['#1E4A8C', '#3B9FE8', '#2BB3A8']
const CHECK_COLOR = '#3B82C8'
const X_COLOR = '#C5CAD3'
const GRID_LINE = '#E5E7EB'
const LABEL_BG = '#F3F4F6'

const PRICING_HS_DEFAULTS = {
  HEADING: 'Slide Title Here',
  PLAN_1_LABEL: 'Base Plan',
  PLAN_1_PRICE: '$00.00',
  PLAN_1_CTA: 'MORE INFORMATION',
  PLAN_2_LABEL: 'Silver Plan',
  PLAN_2_PRICE: '$000.00',
  PLAN_2_CTA: 'MORE INFORMATION',
  PLAN_3_LABEL: 'Gold Plan',
  PLAN_3_PRICE: '$000.00',
  PLAN_3_CTA: 'MORE INFORMATION',
  ROW_1_LABEL: 'Add text here',
  ROW_2_LABEL: 'Add text here',
  ROW_3_LABEL: 'Add text here',
  ROW_4_LABEL: 'Add text here',
  ROW_5_LABEL: 'Add text here',
}

function isPricingThreeHighlightSplitLayout(layoutId) {
  return /pricing_three_highlight_split_v1$/i.test(String(layoutId || ''))
}

function isPricingThreeHighlightSplitTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_CTA$/.test(sid)
    || /^ROW_\d+_LABEL$/.test(sid)
}

function planW() {
  const g = PRICING_HS_GEOM
  return (g.viewW - g.padX * 2 - g.labelW) / g.n
}

function tableX() {
  return PRICING_HS_GEOM.padX
}

function planX(i) {
  return tableX() + PRICING_HS_GEOM.labelW + i * planW()
}

function gridY() {
  const g = PRICING_HS_GEOM
  return g.headerY + g.headerH
}

function gridH() {
  return PRICING_HS_GEOM.rows * PRICING_HS_GEOM.rowH
}

function btnY() {
  return gridY() + gridH() + PRICING_HS_GEOM.btnGap
}

function hexLum(hex) {
  const s = String(hex || '').replace('#', '')
  if (s.length !== 6) return 1
  const r = parseInt(s.slice(0, 2), 16) / 255
  const g = parseInt(s.slice(2, 4), 16) / 255
  const b = parseInt(s.slice(4, 6), 16) / 255
  const lin = (c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}

function headingInk(palette = {}) {
  const bg = palette.bg || palette.background || palette.slideBg
    || palette.colors?.bg || palette.colors?.background || '#ffffff'
  return hexLum(bg) < 0.45 ? '#F3F4F6' : '#1F2937'
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
  const sid = String(slotId || '').toUpperCase()
  const existing = plainTextFromContent(el?.content)
  const text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (PRICING_HS_DEFAULTS[sid] || existing)
  return {
    ...(el?.content || {}),
    ...style,
    text,
    runs: null,
    listType: null,
    letterSpacing: style.letterSpacing ?? '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  }
}

function headerSvg() {
  const g = PRICING_HS_GEOM
  const w = planW()
  const body = g.headerH
  const h = body + g.chevH
  const mid = w / 2
  const d = `M 0 0 L ${w} 0 L ${w} ${body} L ${mid + g.chevW} ${body} L ${mid} ${h} L ${mid - g.chevW} ${body} L 0 ${body} Z`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <path d="${d}" fill="currentColor"/>
  </svg>`
}

function buttonSvg() {
  const g = PRICING_HS_GEOM
  const w = planW() - g.btnInset * 2
  const h = g.btnH
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${w}" height="${h}" rx="8" fill="currentColor"/>
  </svg>`
}

function iconCheck(cx, cy, r) {
  const d = `M ${cx - r * 0.4} ${cy + r * 0.02} L ${cx - r * 0.08} ${cy + r * 0.36} L ${cx + r * 0.44} ${cy - r * 0.32}`
  return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>
    <path d="${d}" fill="none" stroke="#ffffff" stroke-width="${Math.max(1.8, r * 0.22)}" stroke-linecap="round" stroke-linejoin="round"/>`
}

function iconX(cx, cy, r) {
  const o = r * 0.32
  return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${X_COLOR}"/>
    <path d="M ${cx - o} ${cy - o} L ${cx + o} ${cy + o} M ${cx + o} ${cy - o} L ${cx - o} ${cy + o}" fill="none" stroke="#ffffff" stroke-width="${Math.max(1.8, r * 0.22)}" stroke-linecap="round"/>`
}

function gridSvg() {
  const g = PRICING_HS_GEOM
  const w = g.labelW + planW() * g.n
  const h = gridH()
  const included = [3, 4, 5]
  const parts = []
  for (let r = 0; r < g.rows; r += 1) {
    parts.push(`<rect x="0" y="${r * g.rowH}" width="${g.labelW}" height="${g.rowH}" fill="${r % 2 === 0 ? LABEL_BG : '#FAFBFC'}"/>`)
  }
  for (let r = 0; r <= g.rows; r += 1) {
    const y = r * g.rowH
    parts.push(`<line x1="0" y1="${y}" x2="${w}" y2="${y}" stroke="${GRID_LINE}" stroke-width="1"/>`)
  }
  parts.push(`<line x1="0" y1="0" x2="0" y2="${h}" stroke="${GRID_LINE}" stroke-width="1"/>`)
  for (let i = 0; i <= g.n; i += 1) {
    const x = g.labelW + i * planW()
    parts.push(`<line x1="${x}" y1="0" x2="${x}" y2="${h}" stroke="${GRID_LINE}" stroke-width="1"/>`)
  }
  const ir = 13
  for (let i = 0; i < g.n; i += 1) {
    const cx = g.labelW + (i + 0.5) * planW()
    for (let r = 0; r < g.rows; r += 1) {
      const cy = (r + 0.5) * g.rowH
      parts.push(r < included[i] ? iconCheck(cx, cy, ir) : iconX(cx, cy, ir))
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    ${parts.join('')}
  </svg>`
}

function pricingThreeHighlightSplitChromeSpecs() {
  const g = PRICING_HS_GEOM
  const w = planW()
  const specs = [{
    slotId: 'PRICING_HS_GRID',
    kind: 'grid',
    x: tableX(),
    y: gridY(),
    w: g.labelW + w * g.n,
    h: gridH(),
    color: CHECK_COLOR,
    layer: 4,
  }]
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `PRICING_HS_${i + 1}`,
      kind: 'header',
      n: i + 1,
      x: planX(i),
      y: g.headerY,
      w,
      h: g.headerH + g.chevH,
      color: PRICING_HS_PALETTE[i],
      layer: 6,
    })
    specs.push({
      slotId: `PRICING_HS_${i + 1}_BTN`,
      kind: 'button',
      n: i + 1,
      x: planX(i) + g.btnInset,
      y: btnY(),
      w: w - g.btnInset * 2,
      h: g.btnH,
      color: PRICING_HS_PALETTE[i],
      layer: 6,
    })
  }
  return specs
}

function pricingThreeHighlightSplitOverlay(gx, gy, gw, gh) {
  const g = PRICING_HS_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(16, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })
  const w = planW()
  const labels = []
  const prices = []
  const ctas = []
  const rows = []
  for (let i = 0; i < g.n; i += 1) {
    const x = planX(i)
    labels.push(box(x + 8, g.headerY + 10, w - 16, 28))
    prices.push(box(x + 8, g.headerY + 38, w - 16, 26))
    ctas.push(box(x + g.btnInset + 6, btnY() + g.ctaNudgeY, w - g.btnInset * 2 - 12, g.btnH - 10))
  }
  for (let r = 0; r < g.rows; r += 1) {
    rows.push(box(tableX() + 16, gridY() + r * g.rowH, g.labelW - 28, g.rowH))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    prices,
    ctas,
    rows,
  }
}

function specToPricingThreeHighlightSplitContent(spec) {
  if (spec.kind === 'grid') return { svg: gridSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec.kind === 'button') return { svg: buttonSvg(), colorMode: 'recolorable', fill: spec.color }
  return { svg: headerSvg(), colorMode: 'recolorable', fill: spec.color }
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingThreeHighlightSplitElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_HS_GEOM.viewW
  const sy = canvasH / PRICING_HS_GEOM.viewH
  const overlay = pricingThreeHighlightSplitOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_HS_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingThreeHighlightSplitTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-pricehs'),
      type: 'text',
      slotId,
      role: prev?.role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const titleColor = headingInk(palette)
  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'center', verticalAlign: 'center', fontSize: 32, fontWeight: 800, color: titleColor, clipToSlot: true, lineHeight: 1.1,
    }),
  ]
  for (let i = 0; i < 3; i += 1) {
    const n = i + 1
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 18, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 700, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: '#ffffff', clipToSlot: true, lineHeight: 1.15, letterSpacing: '0.06em',
    }))
  }
  for (let r = 0; r < 5; r += 1) {
    next.push(placeText(`ROW_${r + 1}_LABEL`, overlay.rows[r], {
      align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 700, color: '#4B5563', clipToSlot: true, lineHeight: 1.2,
    }))
  }

  const chrome = pricingThreeHighlightSplitChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingThreeHighlightSplitContent(spec)
    return {
      id: prev?.id || newId('shp-pricehs'),
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
  })
  return [...chrome, ...next]
}

function layoutPricingThreeHighlightSplit(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingThreeHighlightSplitElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingThreeHighlightSplitElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingThreeHighlightSplitLayout,
  layoutPricingThreeHighlightSplit,
}
