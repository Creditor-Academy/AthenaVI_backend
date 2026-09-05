/**
 * Pricing three highlight — centered title, side plans on canvas, middle featured panel.
 * Layout id: pricing_three_highlight_v1 only (not split).
 */

const PRICING_TH_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 80,
  headingY: 22,
  headingW: 840,
  headingH: 48,
  padX: 36,
  n: 3,
  cardY: 86,
  cardH: 448,
  panelInsetX: 10,
  panelPadY: 8,
  btnW: 148,
  btnH: 38,
  ctaNudgeY: 7,
}

const ACCENT = '#1B4F8C'

const PRICING_TH_DEFAULTS = {
  HEADING: 'Slide Title Here',
  PLAN_1_LABEL: 'Basic',
  PLAN_1_PRICE: '$000',
  PLAN_1_PERIOD: 'PER MONTH',
  PLAN_1_ITEM_1: '12 Data Base',
  PLAN_1_ITEM_2: '15 GB Disk Space',
  PLAN_1_ITEM_3: '10 Users',
  PLAN_1_CTA: 'Get Started',
  PLAN_2_LABEL: 'Medium',
  PLAN_2_PRICE: '$000',
  PLAN_2_PERIOD: 'PER MONTH',
  PLAN_2_ITEM_1: '12 Data Base',
  PLAN_2_ITEM_2: '15 GB Disk Space',
  PLAN_2_ITEM_3: '10 Users',
  PLAN_2_CTA: 'Get Started',
  PLAN_3_LABEL: 'Ultimate',
  PLAN_3_PRICE: '$000',
  PLAN_3_PERIOD: 'PER MONTH',
  PLAN_3_ITEM_1: '12 Data Base',
  PLAN_3_ITEM_2: '15 GB Disk Space',
  PLAN_3_ITEM_3: '10 Users',
  PLAN_3_CTA: 'Get Started',
}

function isPricingThreeHighlightLayout(layoutId) {
  const id = String(layoutId || '')
  if (/split/i.test(id)) return false
  return /pricing_three_highlight_v1$/i.test(id)
}

function isPricingThreeHighlightTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  if (/^PLAN_\d+_BODY$/.test(sid)) return false
  return sid === 'HEADING'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_PERIOD$/.test(sid)
    || /^PLAN_\d+_CTA$/.test(sid)
    || /^PLAN_\d+_ITEM_\d+$/.test(sid)
}

function cardW() {
  const g = PRICING_TH_GEOM
  return (g.viewW - g.padX * 2) / g.n
}

function cardX(i) {
  return PRICING_TH_GEOM.padX + i * cardW()
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

function themeBg(palette = {}) {
  return palette.bg || palette.background || palette.slideBg
    || palette.colors?.bg || palette.colors?.background || '#ffffff'
}

function headingInk(palette = {}) {
  return hexLum(themeBg(palette)) < 0.45 ? '#F3F4F6' : '#111827'
}

function accentOf(palette = {}) {
  return palette.primary || palette.accent || palette.colors?.primary || palette.colors?.accent || ACCENT
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
    : (PRICING_TH_DEFAULTS[sid] || existing)
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

function checkMark(cx, cy, r, featured) {
  const d = `M ${cx - r * 0.42} ${cy + r * 0.04} L ${cx - r * 0.12} ${cy + r * 0.38} L ${cx + r * 0.46} ${cy - r * 0.32}`
  if (featured) {
    return `<path d="${d}" fill="none" stroke="#ffffff" stroke-width="${Math.max(2, r * 0.28)}" stroke-linecap="round" stroke-linejoin="round"/>`
  }
  return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>
    <path d="${d}" fill="none" stroke="#ffffff" stroke-width="${Math.max(1.6, r * 0.2)}" stroke-linecap="round" stroke-linejoin="round"/>`
}

function columnChromeSvg(spec) {
  const g = PRICING_TH_GEOM
  const w = cardW()
  const h = g.cardH
  const featured = spec.n === 2
  const btnFill = featured ? '#ffffff' : 'currentColor'
  const row0 = 214
  const rowH = 36
  const cx = w / 2 - 62
  const checks = []
  for (let k = 0; k < 3; k += 1) {
    checks.push(checkMark(cx, row0 + k * rowH + 14, 9, featured))
  }
  const btnX = (w - g.btnW) / 2
  const btnY = h - 58
  let panel = ''
  if (featured) {
    const x = g.panelInsetX
    const y = g.panelPadY
    const pw = w - g.panelInsetX * 2
    const ph = h - g.panelPadY * 2
    panel = `<rect x="${x}" y="${y}" width="${pw}" height="${ph}" rx="18" fill="currentColor"/>`
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    ${panel}
    ${checks.join('')}
    <rect x="${btnX}" y="${btnY}" width="${g.btnW}" height="${g.btnH}" rx="${g.btnH / 2}" fill="${btnFill}"/>
  </svg>`
}

function pricingThreeHighlightChromeSpecs(palette = {}) {
  const g = PRICING_TH_GEOM
  const w = cardW()
  const color = accentOf(palette)
  const specs = []
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `PRICING_TH_${i + 1}`,
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h: g.cardH,
      color,
      layer: 4,
    })
  }
  return specs
}

function pricingThreeHighlightOverlay(gx, gy, gw, gh) {
  const g = PRICING_TH_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(16, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })
  const w = cardW()
  const labels = []
  const prices = []
  const periods = []
  const items = [[], [], []]
  const ctas = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const y = g.cardY
    labels.push(box(x + 16, y + 28, w - 32, 28))
    prices.push(box(x + 12, y + 64, w - 24, 64))
    periods.push(box(x + 16, y + 128, w - 32, 22))
    for (let k = 0; k < 3; k += 1) {
      items[i].push(box(x + w / 2 - 48, y + 214 + k * 36, w / 2 + 20, 28))
    }
    ctas.push(box(
      x + (w - g.btnW) / 2,
      y + g.cardH - 58 + g.ctaNudgeY,
      g.btnW,
      g.btnH - 4,
    ))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    prices,
    periods,
    items,
    ctas,
  }
}

function specToPricingThreeHighlightContent(spec) {
  return { svg: columnChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingThreeHighlightElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_TH_GEOM.viewW
  const sy = canvasH / PRICING_TH_GEOM.viewH
  const overlay = pricingThreeHighlightOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_TH_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingThreeHighlightTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-priceh'),
      type: 'text',
      slotId,
      role: prev?.role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const accent = accentOf(palette)
  const titleColor = headingInk(palette)
  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'center', verticalAlign: 'center', fontSize: 36, fontWeight: 800, color: titleColor, clipToSlot: true, lineHeight: 1.1,
    }),
  ]
  for (let i = 0; i < 3; i += 1) {
    const n = i + 1
    const featured = i === 1
    const ink = featured ? '#ffffff' : '#111827'
    const mute = featured ? 'rgba(255,255,255,0.82)' : '#6B7280'
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 500, color: mute, clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'center', verticalAlign: 'center', fontSize: 48, fontWeight: 800, color: ink, clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_PERIOD`, overlay.periods[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 600, color: mute, clipToSlot: true, lineHeight: 1, letterSpacing: '0.16em',
    }))
    for (let k = 0; k < 3; k += 1) {
      next.push(placeText(`PLAN_${n}_ITEM_${k + 1}`, overlay.items[i][k], {
        align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 500, color: ink, clipToSlot: true, lineHeight: 1.2,
      }))
    }
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], {
      align: 'center', verticalAlign: 'center', fontSize: 13, fontWeight: 700,
      color: featured ? accent : '#ffffff', clipToSlot: true, lineHeight: 1.2,
    }))
  }

  const chrome = pricingThreeHighlightChromeSpecs(palette).map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingThreeHighlightContent(spec)
    return {
      id: prev?.id || newId('shp-priceh'),
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

function layoutPricingThreeHighlight(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingThreeHighlightElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingThreeHighlightElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingThreeHighlightLayout,
  layoutPricingThreeHighlight,
}
