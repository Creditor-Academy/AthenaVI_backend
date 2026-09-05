/**
 * Pricing three plans — side-tab cards, Start Now burst, check / x features.
 * Layout id: pricing_three_plans_v1 only (not featured / highlight / four).
 */

const PRICING_TP_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 80,
  headingY: 10,
  headingW: 840,
  headingH: 40,
  subX: 120,
  subY: 50,
  subW: 760,
  subH: 26,
  ruleX: 460,
  ruleY: 82,
  ruleW: 80,
  ruleH: 4,
  padX: 28,
  gap: 18,
  cardY: 102,
  cardH: 430,
  tabW: 40,
  tabInset: 48,
  burstCx: 218,
  burstCy: 54,
  burstR: 40,
  n: 3,
}

const PRICING_TP_PALETTE = [
  { main: '#2EC4D6', checks: 1 },
  { main: '#8BC34A', checks: 2 },
  { main: '#E8A317', checks: 3 },
]

function isPricingThreePlansLayout(layoutId) {
  const id = String(layoutId || '')
  if (/featured|highlight|four_/i.test(id)) return false
  return /pricing_three_plans_v1$/i.test(id)
}

function isPricingThreePlansTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  if (/^PLAN_\d+_BODY$/.test(sid)) return false
  return sid === 'HEADING' || sid === 'SUBHEADING'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_CTA$/.test(sid)
    || /^PLAN_\d+_ITEM_\d+$/.test(sid)
}

const PRICING_TP_DEFAULTS = {
  HEADING: 'Three Pricing Table Slide',
  SUBHEADING: 'Present complex data in an easy-to-understand way.',
  PLAN_1_LABEL: 'Basic Plan',
  PLAN_1_PRICE: '$49',
  PLAN_1_CTA: 'Start\nNow',
  PLAN_1_ITEM_1: 'Present complex data in an easy-to',
  PLAN_1_ITEM_2: 'Data in an easy-to-understand way',
  PLAN_1_ITEM_3: 'Present complex data in an easy-to',
  PLAN_1_ITEM_4: 'Data in an easy-to-understand way',
  PLAN_2_LABEL: 'Standard Plan',
  PLAN_2_PRICE: '$79',
  PLAN_2_CTA: 'Start\nNow',
  PLAN_2_ITEM_1: 'Present complex data in an easy-to',
  PLAN_2_ITEM_2: 'Data in an easy-to-understand way',
  PLAN_2_ITEM_3: 'Present complex data in an easy-to',
  PLAN_2_ITEM_4: 'Data in an easy-to-understand way',
  PLAN_3_LABEL: 'Premium Plan',
  PLAN_3_PRICE: '$99',
  PLAN_3_CTA: 'Start\nNow',
  PLAN_3_ITEM_1: 'Present complex data in an easy-to',
  PLAN_3_ITEM_2: 'Data in an easy-to-understand way',
  PLAN_3_ITEM_3: 'Present complex data in an easy-to',
  PLAN_3_ITEM_4: 'Data in an easy-to-understand way',
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
  let text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (PRICING_TP_DEFAULTS[sid] || existing)
  if (/_CTA$/.test(sid) && /^start\s+now$/i.test(text.replace(/\n/g, ' ').trim())) {
    text = 'Start\nNow'
  }
  return {
    ...(el?.content || {}),
    ...style,
    text,
    runs: null,
    listType: null,
    letterSpacing: '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
  }
}

function cardW() {
  const g = PRICING_TP_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return PRICING_TP_GEOM.padX + i * (cardW() + PRICING_TP_GEOM.gap)
}

function starPoints(cx, cy, rOuter, rInner, spikes = 8) {
  const pts = []
  for (let i = 0; i < spikes * 2; i += 1) {
    const r = i % 2 === 0 ? rOuter : rInner
    const a = (Math.PI / spikes) * i - Math.PI / 2
    pts.push(`${(cx + r * Math.cos(a)).toFixed(1)},${(cy + r * Math.sin(a)).toFixed(1)}`)
  }
  return pts.join(' ')
}

function planChromeSvg(spec) {
  const g = PRICING_TP_GEOM
  const w = cardW()
  const h = g.cardH
  const tab = g.tabW
  const checks = spec.checks || 1
  const markX = tab + 22
  const markY0 = 128
  const markStep = 58
  const navy = '#1B3A4B'
  const marks = []
  for (let i = 0; i < 4; i += 1) {
    const y = markY0 + i * markStep
    if (i < checks) {
      marks.push(`<path d="M ${markX - 8} ${y} L ${markX - 2} ${y + 7} L ${markX + 10} ${y - 8}" fill="none" stroke="${navy}" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>`)
    } else {
      marks.push(`<path d="M ${markX - 8} ${y - 8} L ${markX + 8} ${y + 8} M ${markX + 8} ${y - 8} L ${markX - 8} ${y + 8}" fill="none" stroke="${navy}" stroke-width="3" stroke-linecap="round"/>`)
    }
  }
  const tabY = g.tabInset
  const tabH = h - g.tabInset * 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="${tabY}" width="${tab}" height="${tabH}" rx="12" fill="currentColor"/>
    ${marks.join('')}
  </svg>`
}

function starBadgeSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <polygon points="${starPoints(50, 50, 48, 29, 12)}" fill="currentColor"/>
  </svg>`
}

function ruleSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 4" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="80" height="4" rx="2" fill="currentColor"/>
  </svg>`
}

function pricingThreePlansChromeSpecs() {
  const g = PRICING_TP_GEOM
  const w = cardW()
  const specs = [
    {
      slotId: 'PRICING_TP_RULE',
      kind: 'graphic',
      rule: true,
      x: g.ruleX,
      y: g.ruleY,
      w: g.ruleW,
      h: g.ruleH,
      color: '#2EC4D6',
      layer: 3,
    },
  ]
  for (let i = 0; i < g.n; i += 1) {
    const pal = PRICING_TP_PALETTE[i]
    const x = cardX(i)
    specs.push({
      slotId: `PRICING_TP_${i + 1}_CARD`,
      kind: 'shape',
      x,
      y: g.cardY,
      w,
      h: g.cardH,
      borderRadius: 16,
      fill: '#E8EEF2',
      layer: 3,
    })
    specs.push({
      slotId: `PRICING_TP_${i + 1}`,
      kind: 'graphic',
      n: i + 1,
      checks: pal.checks,
      x,
      y: g.cardY,
      w,
      h: g.cardH,
      color: pal.main,
      layer: 4,
    })
    const starSize = g.burstR * 2
    specs.push({
      slotId: `PRICING_TP_${i + 1}_STAR`,
      kind: 'graphic',
      star: true,
      x: x + g.burstCx - g.burstR,
      y: g.cardY + g.burstCy - g.burstR,
      w: starSize,
      h: starSize,
      color: pal.main,
      layer: 5,
    })
  }
  return specs
}

function pricingThreePlansOverlay(gx, gy, gw, gh) {
  const g = PRICING_TP_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h, extra = {}) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(16, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
    ...extra,
  })
  const w = cardW()
  const labels = []
  const prices = []
  const ctas = []
  const items = [[], [], []]
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const tabH = g.cardH - g.tabInset * 2
    labels.push(box(
      x + g.tabW / 2 - tabH / 2,
      g.cardY + g.cardH / 2 - 16,
      tabH,
      32,
      { rotation: -90 }
    ))
    prices.push(box(x + g.tabW + 16, g.cardY + 18, 110, 58))
    const star = g.burstR * 2
    const inset = star * 0.24
    ctas.push(box(
      x + g.burstCx - g.burstR + inset,
      g.cardY + g.burstCy - g.burstR + inset + 2,
      star - inset * 2,
      star - inset * 2 - 2
    ))
    for (let k = 0; k < 4; k += 1) {
      items[i].push(box(x + g.tabW + 40, g.cardY + 108 + k * 58, w - g.tabW - 56, 36))
    }
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    subheading: box(g.subX, g.subY, g.subW, g.subH),
    labels,
    prices,
    ctas,
    items,
  }
}

function specToPricingThreePlansContent(spec) {
  if (spec?.rule) return { svg: ruleSvg(), colorMode: 'recolorable', fill: spec.color }
  if (spec?.star) return { svg: starBadgeSvg(), colorMode: 'recolorable', fill: spec.color }
  return { svg: planChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function pricingThreePlansPreviewSvg() {
  const specs = pricingThreePlansChromeSpecs()
  const g = PRICING_TP_GEOM
  const parts = specs.map((spec) => {
    if (spec.kind === 'shape') {
      return `<rect x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" rx="${spec.borderRadius || 12}" fill="${spec.fill}"/>`
    }
    const inner = specToPricingThreePlansContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    const par = spec.star ? 'xMidYMid meet' : 'none'
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 100 100'}" preserveAspectRatio="${par}" color="${spec.color}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingThreePlans(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_TP_GEOM.viewW
  const sy = canvasH / PRICING_TP_GEOM.viewH
  const overlay = pricingThreePlansOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_TP_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingThreePlansTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-price'),
      type: 'text',
      slotId,
      role: prev?.role || 'body',
      layer: 12,
      placement: {
        x: box.x,
        y: box.y,
        width: box.width,
        height: box.height,
        rotation: box.rotation || 0,
        opacity: 1,
      },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    placeText('HEADING', overlay.heading, { align: 'center', verticalAlign: 'center', fontSize: 32, fontWeight: 800, color: '#1B3A4B', clipToSlot: true, lineHeight: 1.1 }),
    placeText('SUBHEADING', overlay.subheading, { align: 'center', verticalAlign: 'center', fontSize: 14, fontWeight: 500, color: '#6B7280', clipToSlot: true, lineHeight: 1.25 }),
  ]
  for (let i = 0; i < 3; i += 1) {
    const n = i + 1
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], { align: 'center', verticalAlign: 'center', fontSize: 15, fontWeight: 700, color: '#ffffff', clipToSlot: true, lineHeight: 1 }))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], { align: 'left', verticalAlign: 'center', fontSize: 40, fontWeight: 800, color: PRICING_TP_PALETTE[i].main, clipToSlot: true, lineHeight: 1 }))
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], { align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1.12, wrap: 'wrap' }))
    for (let k = 0; k < 4; k += 1) {
      next.push(placeText(`PLAN_${n}_ITEM_${k + 1}`, overlay.items[i][k], { align: 'left', verticalAlign: 'center', fontSize: 14, fontWeight: 500, color: '#6B7280', clipToSlot: true, lineHeight: 1.2 }))
    }
  }
  const chrome = pricingThreePlansChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const scale = spec.star ? Math.min(sx, sy) : null
    const placement = spec.star
      ? {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.max(4, Math.round(spec.w * scale)),
        height: Math.max(4, Math.round(spec.h * scale)),
        rotation: 0,
        opacity: 1,
      }
      : {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.max(4, Math.round(spec.w * sx)),
        height: Math.max(4, Math.round(spec.h * sy)),
        rotation: 0,
        opacity: 1,
      }
    if (spec.kind === 'shape') {
      return {
        id: prev?.id || newId('shp-price'),
        type: 'shape',
        layer: spec.layer || 3,
        placement,
        content: { shape: 'rect', borderRadius: Math.round((spec.borderRadius || 12) * Math.min(sx, sy)), fill: spec.fill },
        role: 'decoration',
        slotId: spec.slotId,
      }
    }
    const graphic = specToPricingThreePlansContent(spec)
    return {
      id: prev?.id || newId('shp-price'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement,
      content: { svg: graphic.svg, colorMode: graphic.colorMode, fill: graphic.fill || spec.color, alt: spec.slotId },
      role: 'decoration',
      slotId: spec.slotId,
    }
  })
  return [...chrome, ...next]
}

module.exports = {
  PRICING_TP_GEOM,
  PRICING_TP_PALETTE,
  PRICING_TP_DEFAULTS,
  isPricingThreePlansLayout,
  isPricingThreePlansTextSlot,
  pricingThreePlansChromeSpecs,
  pricingThreePlansOverlay,
  specToPricingThreePlansContent,
  pricingThreePlansPreviewSvg,
  layoutPricingThreePlans,
}
