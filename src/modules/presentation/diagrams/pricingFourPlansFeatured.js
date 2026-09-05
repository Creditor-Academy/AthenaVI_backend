/**
 * Pricing four plans featured — white cards, wavy accent footers, check lists.
 * Layout id: pricing_four_plans_featured_v1 only.
 */

const PRICING_FF_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 36,
  headingY: 14,
  headingW: 520,
  headingH: 34,
  padX: 24,
  gap: 14,
  n: 4,
  cardY: 58,
  cardH: 478,
  rows: 5,
  footY: 392,
  row0: 64,
  rowH: 42,
  dividerY: 52,
}

const PRICING_FF_PALETTE = [
  { main: '#2E7BD6', checks: 2 },
  { main: '#2BB3A8', checks: 3 },
  { main: '#F0A202', checks: 4 },
  { main: '#C0392B', checks: 5 },
]

const FEATURE = 'Lorem ipsum is simply dummy'
const DESC = 'Lorem Ipsum is simply dummy text of the printing and typesetting.'

const PRICING_FF_DEFAULTS = {
  HEADING: 'Pricing Table',
  PLAN_1_LABEL: 'Essential',
  PLAN_1_BODY: DESC,
  PLAN_1_CAPTION: 'Only With',
  PLAN_1_PRICE: '$ 9.99',
  PLAN_1_PERIOD: '/yr',
  PLAN_2_LABEL: 'Team',
  PLAN_2_BODY: DESC,
  PLAN_2_CAPTION: 'Only With',
  PLAN_2_PRICE: '$ 19.99',
  PLAN_2_PERIOD: '/yr',
  PLAN_3_LABEL: 'Professional',
  PLAN_3_BODY: DESC,
  PLAN_3_CAPTION: 'Only With',
  PLAN_3_PRICE: '$ 29.99',
  PLAN_3_PERIOD: '/yr',
  PLAN_4_LABEL: 'Enterprise',
  PLAN_4_BODY: DESC,
  PLAN_4_CAPTION: 'Only With',
  PLAN_4_PRICE: '$ 39.99',
  PLAN_4_PERIOD: '/yr',
  PLAN_1_ITEM_1: FEATURE,
  PLAN_1_ITEM_2: FEATURE,
  PLAN_1_ITEM_3: FEATURE,
  PLAN_1_ITEM_4: FEATURE,
  PLAN_1_ITEM_5: FEATURE,
  PLAN_2_ITEM_1: FEATURE,
  PLAN_2_ITEM_2: FEATURE,
  PLAN_2_ITEM_3: FEATURE,
  PLAN_2_ITEM_4: FEATURE,
  PLAN_2_ITEM_5: FEATURE,
  PLAN_3_ITEM_1: FEATURE,
  PLAN_3_ITEM_2: FEATURE,
  PLAN_3_ITEM_3: FEATURE,
  PLAN_3_ITEM_4: FEATURE,
  PLAN_3_ITEM_5: FEATURE,
  PLAN_4_ITEM_1: FEATURE,
  PLAN_4_ITEM_2: FEATURE,
  PLAN_4_ITEM_3: FEATURE,
  PLAN_4_ITEM_4: FEATURE,
  PLAN_4_ITEM_5: FEATURE,
}

function isPricingFourPlansFeaturedLayout(layoutId) {
  return /pricing_four_plans_featured_v1$/i.test(String(layoutId || ''))
}

function isPricingFourPlansFeaturedTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_BODY$/.test(sid)
    || /^PLAN_\d+_CAPTION$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_PERIOD$/.test(sid)
    || /^PLAN_\d+_ITEM_\d+$/.test(sid)
}

function cardW() {
  const g = PRICING_FF_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return PRICING_FF_GEOM.padX + i * (cardW() + PRICING_FF_GEOM.gap)
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
    : (PRICING_FF_DEFAULTS[sid] || existing)
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

function featureIcon(cx, cy, r, on) {
  const sw = Math.max(1.5, r * 0.28)
  if (on) {
    const d = `M ${cx - r * 0.38} ${cy + 0.04 * r} L ${cx - r * 0.08} ${cy + r * 0.34} L ${cx + r * 0.42} ${cy - r * 0.3}`
    return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="currentColor"/>
      <path d="${d}" fill="none" stroke="#ffffff" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round"/>`
  }
  const a = r * 0.32
  return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="#D1D5DB"/>
    <path d="M ${cx - a} ${cy - a} L ${cx + a} ${cy + a} M ${cx + a} ${cy - a} L ${cx - a} ${cy + a}" fill="none" stroke="#ffffff" stroke-width="${sw}" stroke-linecap="round"/>`
}

function cardChromeSvg(spec) {
  const g = PRICING_FF_GEOM
  const w = cardW()
  const h = g.cardH
  const pal = PRICING_FF_PALETTE[(spec.n || 1) - 1]
  const fid = `ffSh${spec.n || 1}`
  const clipId = `ffClip${spec.n || 1}`
  const fy = g.footY
  const wave = [
    `M 0 ${h}`,
    `L 0 ${fy - 14}`,
    `C ${w * 0.18} ${fy - 28} ${w * 0.42} ${fy + 10} ${w * 0.7} ${fy + 12}`,
    `C ${w * 0.88} ${fy + 14} ${w * 0.96} ${fy + 10} ${w} ${fy + 8}`,
    `L ${w} ${h} Z`,
  ].join(' ')
  const icons = []
  for (let k = 0; k < g.rows; k += 1) {
    icons.push(featureIcon(22, g.row0 + k * g.rowH + 16, 8, k < pal.checks))
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-10%" y="-6%" width="120%" height="118%">
        <feDropShadow dx="0" dy="6" stdDeviation="7" flood-color="#0f172a" flood-opacity="0.1"/>
      </filter>
      <clipPath id="${clipId}"><rect x="0.8" y="0.8" width="${w - 1.6}" height="${h - 1.6}" rx="12"/></clipPath>
    </defs>
    <rect x="0.8" y="0.8" width="${w - 1.6}" height="${h - 1.6}" rx="12" fill="#ffffff" stroke="#E5E7EB" stroke-width="1.2" filter="url(#${fid})"/>
    <g clip-path="url(#${clipId})">
      <line x1="16" y1="${g.dividerY}" x2="${w - 16}" y2="${g.dividerY}" stroke="#D1D5DB" stroke-width="1.4"/>
      <path d="${wave}" fill="currentColor"/>
      ${icons.join('')}
    </g>
  </svg>`
}

function pricingFourPlansFeaturedChromeSpecs() {
  const g = PRICING_FF_GEOM
  const w = cardW()
  const specs = []
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `PRICING_FF_${i + 1}`,
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h: g.cardH,
      color: PRICING_FF_PALETTE[i].main,
      layer: 4,
    })
  }
  return specs
}

function pricingFourPlansFeaturedOverlay(gx, gy, gw, gh) {
  const g = PRICING_FF_GEOM
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
  const items = [[], [], [], []]
  const bodies = []
  const captions = []
  const prices = []
  const periods = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const y = g.cardY
    labels.push(box(x + 10, y + 2, w - 20, g.dividerY - 4))
    for (let k = 0; k < g.rows; k += 1) {
      items[i].push(box(x + 38, y + g.row0 + k * g.rowH, w - 50, 30))
    }
    bodies.push(box(x + 14, y + g.row0 + g.rows * g.rowH + 4, w - 28, 40))
    captions.push(box(x + 12, y + 408, w - 24, 20))
    const clusterW = Math.min(w - 16, 188)
    const periodW = 38
    const gap = 4
    const cx0 = x + (w - clusterW) / 2
    prices.push(box(cx0, y + 426, clusterW - periodW - gap, 36))
    periods.push(box(cx0 + clusterW - periodW, y + 436, periodW, 20))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    items,
    bodies,
    captions,
    prices,
    periods,
  }
}

function specToPricingFourPlansFeaturedContent(spec) {
  return { svg: cardChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingFourPlansFeaturedElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_FF_GEOM.viewW
  const overlay = pricingFourPlansFeaturedOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_FF_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingFourPlansFeaturedTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-priceff'),
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
      align: 'left', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: titleColor, clipToSlot: true, lineHeight: 1.1,
    }),
  ]
  for (let i = 0; i < 4; i += 1) {
    const n = i + 1
    const pal = PRICING_FF_PALETTE[i]
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 800, color: pal.main, clipToSlot: true, lineHeight: 1,
    }))
    for (let k = 0; k < 5; k += 1) {
      const on = k < pal.checks
      next.push(placeText(`PLAN_${n}_ITEM_${k + 1}`, overlay.items[i][k], {
        align: 'left', verticalAlign: 'center', fontSize: 11, fontWeight: 500,
        color: on ? pal.main : '#A0A7B3', clipToSlot: true, lineHeight: 1.2,
      }))
    }
    next.push(placeText(`PLAN_${n}_BODY`, overlay.bodies[i], {
      align: 'center', verticalAlign: 'top', fontSize: 10, fontWeight: 500, color: '#4B5563', clipToSlot: true, lineHeight: 1.3, wrap: 'wrap',
    }))
    next.push(placeText(`PLAN_${n}_CAPTION`, overlay.captions[i], {
      align: 'center', verticalAlign: 'center', fontSize: 12, fontWeight: 500, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'right', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_PERIOD`, overlay.periods[i], {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 600, color: 'rgba(255,255,255,0.92)', clipToSlot: true, lineHeight: 1,
    }))
  }

  const chrome = pricingFourPlansFeaturedChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingFourPlansFeaturedContent(spec)
    return {
      id: prev?.id || newId('shp-priceff'),
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

function layoutPricingFourPlansFeatured(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingFourPlansFeaturedElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingFourPlansFeaturedElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingFourPlansFeaturedLayout,
  layoutPricingFourPlansFeatured,
}
