/**
 * Pricing four plans — navy cards, folded ribbon tabs, pill trial CTAs.
 * Layout id: pricing_four_plans_v1 only (not featured).
 */

const PRICING_FP_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 36,
  headingY: 16,
  headingW: 640,
  headingH: 36,
  padX: 28,
  gap: 16,
  n: 4,
  cardY: 78,
  cardH: 452,
  tabH: 44,
  btnW: 0.78,
  btnH: 36,
  ctaNudgeY: 7,
}

const CARD_NAVY = '#1A3A5C'
const PRICING_FP_PALETTE = ['#4EC4F5', '#F39C12', '#4EC4F5', '#4EC4F5']

const PRICING_FP_DEFAULTS = {
  HEADING: 'Pricing Table',
  PLAN_1_LABEL: 'Free',
  PLAN_1_PRICE: '$ 0',
  PLAN_1_PERIOD: '/yr',
  PLAN_1_ITEM_1: 'Feature Number 1',
  PLAN_1_ITEM_2: 'Feature Number 2',
  PLAN_1_ITEM_3: 'Feature Number 3',
  PLAN_1_ITEM_4: 'Feature Number 4',
  PLAN_1_CTA: '30-day free trial',
  PLAN_2_LABEL: 'Standard',
  PLAN_2_PRICE: '$ 19',
  PLAN_2_PERIOD: '/yr',
  PLAN_2_ITEM_1: 'Feature Number 1',
  PLAN_2_ITEM_2: 'Feature Number 2',
  PLAN_2_ITEM_3: 'Feature Number 3',
  PLAN_2_ITEM_4: 'Feature Number 4',
  PLAN_2_CTA: '30-day free trial',
  PLAN_3_LABEL: 'Professional',
  PLAN_3_PRICE: '$ 99',
  PLAN_3_PERIOD: '/yr',
  PLAN_3_ITEM_1: 'Feature Number 1',
  PLAN_3_ITEM_2: 'Feature Number 2',
  PLAN_3_ITEM_3: 'Feature Number 3',
  PLAN_3_ITEM_4: 'Feature Number 4',
  PLAN_3_CTA: '30-day free trial',
  PLAN_4_LABEL: 'Enterprise',
  PLAN_4_PRICE: '$ 499',
  PLAN_4_PERIOD: '/yr',
  PLAN_4_ITEM_1: 'Feature Number 1',
  PLAN_4_ITEM_2: 'Feature Number 2',
  PLAN_4_ITEM_3: 'Feature Number 3',
  PLAN_4_ITEM_4: 'Feature Number 4',
  PLAN_4_CTA: '30-day free trial',
}

function isPricingFourPlansLayout(layoutId) {
  const id = String(layoutId || '')
  if (/featured/i.test(id)) return false
  return /pricing_four_plans_v1$/i.test(id)
}

function isPricingFourPlansTextSlot(slotId) {
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
  const g = PRICING_FP_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return PRICING_FP_GEOM.padX + i * (cardW() + PRICING_FP_GEOM.gap)
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
  let text = existing && existing.toLowerCase() !== 'double-click to edit'
    ? existing
    : (PRICING_FP_DEFAULTS[sid] || existing)
  if (sid === 'HEADING' && /powerpoint\s*template/i.test(text)) {
    text = PRICING_FP_DEFAULTS.HEADING
  }
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

function cardBodySvg(spec) {
  const g = PRICING_FP_GEOM
  const w = cardW()
  const h = g.cardH
  const tabH = g.tabH
  const fid = `fpCard${spec.n || 1}`
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-12%" y="-6%" width="124%" height="120%">
        <feDropShadow dx="0" dy="10" stdDeviation="10" flood-color="#0f172a" flood-opacity="0.22"/>
      </filter>
    </defs>
    <rect x="0" y="${tabH * 0.35}" width="${w}" height="${h - tabH * 0.35}" rx="16" fill="currentColor" filter="url(#${fid})"/>
  </svg>`
}

function accentChromeSvg(spec) {
  const g = PRICING_FP_GEOM
  const w = cardW()
  const h = g.cardH
  const tabH = g.tabH
  const fold = 16
  const bid = `fpBtn${spec.n || 1}`
  const btnW = w * g.btnW
  const btnX = (w - btnW) / 2
  const btnY = h - 58
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${bid}" x="-20%" y="-40%" width="140%" height="180%">
        <feDropShadow dx="0" dy="6" stdDeviation="6" flood-color="${spec.color}" flood-opacity="0.45"/>
      </filter>
    </defs>
    <path d="M ${fold} 0 L ${w - 10} 0 Q ${w} 0 ${w} 10 L ${w} ${tabH - 6} Q ${w} ${tabH} ${w - 10} ${tabH} L ${fold} ${tabH} Z" fill="currentColor"/>
    <path d="M 0 ${tabH} L ${fold} 0 L ${fold} ${tabH} Z" fill="#0F2740" fill-opacity="0.45"/>
    <rect x="${btnX}" y="${btnY}" width="${btnW}" height="${g.btnH}" rx="${g.btnH / 2}" fill="currentColor" filter="url(#${bid})"/>
  </svg>`
}

function pricingFourPlansChromeSpecs() {
  const g = PRICING_FP_GEOM
  const w = cardW()
  const specs = []
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `PRICING_FP_${i + 1}_CARD`,
      kind: 'card',
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h: g.cardH,
      color: CARD_NAVY,
      layer: 3,
    })
    specs.push({
      slotId: `PRICING_FP_${i + 1}`,
      kind: 'accent',
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h: g.cardH,
      color: PRICING_FP_PALETTE[i],
      layer: 4,
    })
  }
  return specs
}

function pricingFourPlansOverlay(gx, gy, gw, gh) {
  const g = PRICING_FP_GEOM
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
  const items = [[], [], [], []]
  const ctas = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const y = g.cardY
    labels.push(box(x + 18, y + 6, w - 28, 34))
    {
      const clusterW = Math.min(w - 20, 168)
      const cx0 = x + (w - clusterW) / 2
      const periodW = 38
      const gap = 6
      prices.push(box(cx0, y + 80, clusterW - periodW - gap, 44))
      periods.push(box(cx0 + clusterW - periodW, y + 90, periodW, 24))
    }
    for (let k = 0; k < 4; k += 1) {
      items[i].push(box(x + 12, y + 160 + k * 38, w - 24, 32))
    }
    const btnW = w * g.btnW
    ctas.push(box(x + (w - btnW) / 2, y + g.cardH - 58 + g.ctaNudgeY, btnW, g.btnH - 8))
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

function specToPricingFourPlansContent(spec) {
  if (spec.kind === 'card') return { svg: cardBodySvg(spec), colorMode: 'recolorable', fill: spec.color }
  return { svg: accentChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingFourPlansElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_FP_GEOM.viewW
  const sy = canvasH / PRICING_FP_GEOM.viewH
  const overlay = pricingFourPlansOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_FP_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingFourPlansTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-price4'),
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
      align: 'left', verticalAlign: 'center', fontSize: 22, fontWeight: 700, color: titleColor, clipToSlot: true, lineHeight: 1.1,
    }),
  ]
  for (let i = 0; i < 4; i += 1) {
    const n = i + 1
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'right', verticalAlign: 'center', fontSize: 26, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_PERIOD`, overlay.periods[i], {
      align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.85)', clipToSlot: true, lineHeight: 1,
    }))
    for (let k = 0; k < 4; k += 1) {
      next.push(placeText(`PLAN_${n}_ITEM_${k + 1}`, overlay.items[i][k], {
        align: 'center', verticalAlign: 'center', fontSize: 12, fontWeight: 500, color: '#ffffff', clipToSlot: true, lineHeight: 1.2,
      }))
    }
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], {
      align: 'center', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: '#ffffff', clipToSlot: true, lineHeight: 1.15,
    }))
  }

  const chrome = pricingFourPlansChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingFourPlansContent(spec)
    return {
      id: prev?.id || newId('shp-price4'),
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

function layoutPricingFourPlans(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingFourPlansElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingFourPlansElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingFourPlansLayout,
  layoutPricingFourPlans,
}
