/**
 * Pricing comparison cards — four spec-sheet cards with check/x rows.
 * Layout id: pricing_comparison_cards_v1 only.
 */

const PRICING_PCC_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 40,
  headingY: 14,
  headingW: 920,
  headingH: 32,
  padX: 22,
  cardY: 58,
  cardH: 478,
  gap: 14,
  n: 4,
  rows: 5,
  barH: 8,
}

const PRICING_PCC_PALETTE = [
  { main: '#4C6EF5', checks: 2 },
  { main: '#FA5252', checks: 3 },
  { main: '#12B886', checks: 4 },
  { main: '#343A40', checks: 5 },
]

const FEATURES = [
  'Cloud storage included',
  'Team seats on the plan',
  'Email support window',
  'Usage analytics',
  'SSO and admin tools',
]

const PRICING_PCC_DEFAULTS = {
  HEADING: 'Compare plans',
  PLAN_1_LABEL: 'Light',
  PLAN_1_PRICE: 'FREE',
  PLAN_1_CTA: 'Select Light',
  PLAN_2_LABEL: 'Professional',
  PLAN_2_PRICE: '$20',
  PLAN_2_CTA: 'Select Pro',
  PLAN_3_LABEL: 'Extended',
  PLAN_3_PRICE: '$50',
  PLAN_3_CTA: 'Select Extended',
  PLAN_4_LABEL: 'Full',
  PLAN_4_PRICE: '$100',
  PLAN_4_CTA: 'Select Full',
  PLAN_1_ITEM_1: FEATURES[0],
  PLAN_1_ITEM_2: FEATURES[1],
  PLAN_1_ITEM_3: FEATURES[2],
  PLAN_1_ITEM_4: FEATURES[3],
  PLAN_1_ITEM_5: FEATURES[4],
  PLAN_2_ITEM_1: FEATURES[0],
  PLAN_2_ITEM_2: FEATURES[1],
  PLAN_2_ITEM_3: FEATURES[2],
  PLAN_2_ITEM_4: FEATURES[3],
  PLAN_2_ITEM_5: FEATURES[4],
  PLAN_3_ITEM_1: FEATURES[0],
  PLAN_3_ITEM_2: FEATURES[1],
  PLAN_3_ITEM_3: FEATURES[2],
  PLAN_3_ITEM_4: FEATURES[3],
  PLAN_3_ITEM_5: FEATURES[4],
  PLAN_4_ITEM_1: FEATURES[0],
  PLAN_4_ITEM_2: FEATURES[1],
  PLAN_4_ITEM_3: FEATURES[2],
  PLAN_4_ITEM_4: FEATURES[3],
  PLAN_4_ITEM_5: FEATURES[4],
}

function isPricingComparisonCardsLayout(layoutId) {
  return /pricing_comparison_cards_v1$/i.test(String(layoutId || ''))
}

function isPricingComparisonCardsTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_CTA$/.test(sid)
    || /^PLAN_\d+_ITEM_\d+$/.test(sid)
}

function cardW() {
  const g = PRICING_PCC_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return PRICING_PCC_GEOM.padX + i * (cardW() + PRICING_PCC_GEOM.gap)
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

function featureIcon(cx, cy, r, on) {
  const sw = Math.max(1.5, r * 0.28)
  if (on) {
    const d = `M ${cx - r * 0.38} ${cy + 0.04 * r} L ${cx - r * 0.08} ${cy + r * 0.34} L ${cx + r * 0.42} ${cy - r * 0.3}`
    return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>
      <path d="${d}" fill="none" stroke="#ffffff" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round"/>`
  }
  const a = r * 0.32
  return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="#E5E7EB"/>
    <path d="M ${cx - a} ${cy - a} L ${cx + a} ${cy + a} M ${cx + a} ${cy - a} L ${cx - a} ${cy + a}" fill="none" stroke="#ffffff" stroke-width="${sw}" stroke-linecap="round"/>`
}

function cardChromeSvg(spec) {
  const g = PRICING_PCC_GEOM
  const w = cardW()
  const h = g.cardH
  const pal = PRICING_PCC_PALETTE[(spec.n || 1) - 1]
  const fid = `pccSh${spec.n || 1}`
  const clipId = `pccClip${spec.n || 1}`
  const featured = spec.n === 3
  const icons = []
  const row0 = 132
  const rowH = 52
  for (let k = 0; k < g.rows; k += 1) {
    icons.push(featureIcon(22, row0 + k * rowH + 16, 8, k < pal.checks))
  }
  const badge = featured
    ? `<rect x="${w - 78}" y="18" width="64" height="18" rx="9" fill="currentColor"/><rect x="${w - 78}" y="18" width="64" height="18" rx="9" fill="#ffffff" fill-opacity="0.18"/>`
    : ''
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-10%" y="-6%" width="120%" height="118%">
        <feDropShadow dx="0" dy="7" stdDeviation="8" flood-color="#0f172a" flood-opacity="${featured ? 0.18 : 0.1}"/>
      </filter>
      <clipPath id="${clipId}"><rect x="0.7" y="0.7" width="${w - 1.4}" height="${h - 1.4}" rx="16"/></clipPath>
    </defs>
    <rect x="0.7" y="0.7" width="${w - 1.4}" height="${h - 1.4}" rx="16" fill="#FFFEFB" stroke="${featured ? pal.main : '#E7E2D8'}" stroke-width="${featured ? 1.8 : 1.1}" filter="url(#${fid})"/>
    <g clip-path="url(#${clipId})">
      <rect x="0" y="0" width="${w}" height="${g.barH}" fill="currentColor"/>
      ${badge}
      <line x1="16" y1="118" x2="${w - 16}" y2="118" stroke="#EDE8DF" stroke-width="1.2" stroke-dasharray="4 5"/>
      ${icons.join('')}
    </g>
  </svg>`
}

function pricingComparisonCardsChromeSpecs() {
  const g = PRICING_PCC_GEOM
  const w = cardW()
  const specs = []
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `PRICING_PCC_${i + 1}`,
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h: g.cardH,
      color: PRICING_PCC_PALETTE[i].main,
      layer: 4,
    })
  }
  return specs
}

function pricingComparisonCardsOverlay(gx, gy, gw, gh) {
  const g = PRICING_PCC_GEOM
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
  const items = [[], [], [], []]
  const ctas = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const y = g.cardY
    labels.push(box(x + 14, y + 18, w - 28, 22))
    prices.push(box(x + 14, y + 44, w - 28, 48))
    for (let k = 0; k < g.rows; k += 1) {
      items[i].push(box(x + 38, y + 132 + k * 52, w - 52, 32))
    }
    ctas.push(box(x + 14, y + g.cardH - 42, w - 28, 22))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    prices,
    items,
    ctas,
  }
}

function specToPricingComparisonCardsContent(spec) {
  return { svg: cardChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function pricingComparisonCardsPreviewSvg() {
  const specs = pricingComparisonCardsChromeSpecs()
  const g = PRICING_PCC_GEOM
  const parts = specs.map((spec) => {
    const inner = specToPricingComparisonCardsContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 100 100'}" preserveAspectRatio="none" color="${spec.color}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
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
    : (PRICING_PCC_DEFAULTS[sid] || existing)
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

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingComparisonCardsElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_PCC_GEOM.viewW
  const sy = canvasH / PRICING_PCC_GEOM.viewH
  const overlay = pricingComparisonCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_PCC_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingComparisonCardsTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-pricepcc'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const titleColor = headingInk(palette)
  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'center', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: titleColor, clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
  ]
  for (let i = 0; i < 4; i += 1) {
    const n = i + 1
    const pal = PRICING_PCC_PALETTE[i]
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 800, color: pal.main, clipToSlot: true, lineHeight: 1, letterSpacing: '0.04em',
    }, 'heading'))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'left', verticalAlign: 'center', fontSize: 28, fontWeight: 800, color: '#111827', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    for (let k = 0; k < 5; k += 1) {
      const on = k < pal.checks
      next.push(placeText(`PLAN_${n}_ITEM_${k + 1}`, overlay.items[i][k], {
        align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 500,
        color: on ? '#374151' : '#9CA3AF', clipToSlot: true, lineHeight: 1.2,
      }, 'body'))
    }
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], {
      align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 700, color: pal.main, clipToSlot: true, lineHeight: 1,
    }, 'caption'))
  }

  const chrome = pricingComparisonCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingComparisonCardsContent(spec)
    return {
      id: prev?.id || newId('shp-pricepcc'),
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

function layoutPricingComparisonCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingComparisonCardsElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingComparisonCardsElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingComparisonCardsLayout,
  layoutPricingComparisonCards,
}
