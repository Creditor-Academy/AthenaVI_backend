/**
 * Pricing three plans featured — table cards, corner star ribbon, overlapping Purchase pills.
 * Layout id: pricing_three_plans_featured_v1 only.
 */

const PRICING_TF_GEOM = {
  viewW: 1000,
  viewH: 560,
  eyebrowX: 40,
  eyebrowY: 18,
  eyebrowW: 220,
  eyebrowH: 22,
  headingX: 40,
  headingY: 40,
  headingW: 520,
  headingH: 44,
  padX: 36,
  gap: 28,
  cardY: 102,
  cardH: 400,
  graphicExtra: 28,
  n: 3,
  checkR: 11,
  btnW: 148,
  btnH: 40,
  ctaNudgeY: 8,
}

const PRICING_TF_PALETTE = [
  { main: '#F1B324', checks: 1 },
  { main: '#3B78C3', checks: 3, featured: true },
  { main: '#21B08F', checks: 3 },
]

const LOREM = 'Lorem Ipsum is simply dummy text of the printing and typesetting industry.'

const PRICING_TF_DEFAULTS = {
  HEADING: 'PRICING PLANS',
  PLAN_1_LABEL: 'BASIC',
  PLAN_1_PRICE: '$29',
  PLAN_1_CENTS: ',99',
  PLAN_1_BODY: LOREM,
  PLAN_1_ITEM_1: 'Feature comes here 1',
  PLAN_1_ITEM_2: 'Feature comes here 2',
  PLAN_1_ITEM_3: 'Feature comes here 3',
  PLAN_1_CTA: 'Purchase',
  PLAN_2_LABEL: 'PROFESSIONAL',
  PLAN_2_PRICE: '$49',
  PLAN_2_CENTS: ',99',
  PLAN_2_BODY: LOREM,
  PLAN_2_ITEM_1: 'Feature comes here 1',
  PLAN_2_ITEM_2: 'Feature comes here 2',
  PLAN_2_ITEM_3: 'Feature comes here 3',
  PLAN_2_CTA: 'Purchase',
  PLAN_3_LABEL: 'PREMIUM',
  PLAN_3_PRICE: '$99',
  PLAN_3_CENTS: ',99',
  PLAN_3_BODY: LOREM,
  PLAN_3_ITEM_1: 'Feature comes here 1',
  PLAN_3_ITEM_2: 'Feature comes here 2',
  PLAN_3_ITEM_3: 'Feature comes here 3',
  PLAN_3_CTA: 'Purchase',
}

function isPricingThreePlansFeaturedLayout(layoutId) {
  return /pricing_three_plans_featured_v1$/i.test(String(layoutId || ''))
}

function isPricingThreePlansFeaturedTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_CENTS$/.test(sid)
    || /^PLAN_\d+_BODY$/.test(sid)
    || /^PLAN_\d+_CTA$/.test(sid)
    || /^PLAN_\d+_ITEM_\d+$/.test(sid)
}

function cardW() {
  const g = PRICING_TF_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return PRICING_TF_GEOM.padX + i * (cardW() + PRICING_TF_GEOM.gap)
}

function graphicH() {
  return PRICING_TF_GEOM.cardH + PRICING_TF_GEOM.graphicExtra
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
  return hexLum(themeBg(palette)) < 0.45 ? '#F3F4F6' : '#1F2937'
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
    : (PRICING_TF_DEFAULTS[sid] || existing)
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

function checkMark(cx, cy, r, active) {
  const fill = active ? 'currentColor' : '#D1D5DB'
  const d = `M ${cx - r * 0.42} ${cy + r * 0.04} L ${cx - r * 0.12} ${cy + r * 0.38} L ${cx + r * 0.46} ${cy - r * 0.32}`
  return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}"/>
    <path d="${d}" fill="none" stroke="#ffffff" stroke-width="${Math.max(1.8, r * 0.22)}" stroke-linecap="round" stroke-linejoin="round"/>`
}

function starOutline(cx, cy, r) {
  const pts = []
  for (let i = 0; i < 5; i += 1) {
    const a = -Math.PI / 2 + i * (Math.PI * 2) / 5
    pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r])
    const b = a + Math.PI / 5
    pts.push([cx + Math.cos(b) * r * 0.42, cy + Math.sin(b) * r * 0.42])
  }
  return pts.map((p, i) => `${i ? 'L' : 'M'} ${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' ') + ' Z'
}

function cardChromeSvg(spec) {
  const g = PRICING_TF_GEOM
  const w = cardW()
  const whiteH = g.cardH
  const h = graphicH()
  const pal = PRICING_TF_PALETTE[(spec.n || 1) - 1]
  const fid = `tfSh${spec.n || 1}`
  const rBot = 18
  const card = `M 0 0 L ${w} 0 L ${w} ${whiteH - rBot} Q ${w} ${whiteH} ${w - rBot} ${whiteH} L ${rBot} ${whiteH} Q 0 ${whiteH} 0 ${whiteH - rBot} Z`
  const checks = []
  const row0 = 198
  const rowH = 44
  const cx = 28
  for (let k = 0; k < 3; k += 1) {
    checks.push(checkMark(cx, row0 + k * rowH + 14, g.checkR, k < pal.checks))
  }
  const btnX = (w - g.btnW) / 2
  const btnY = whiteH - g.btnH / 2
  let ribbon = ''
  if (pal.featured) {
    ribbon = `<polygon points="0,0 78,0 0,78" fill="currentColor"/>
      <path d="${starOutline(22, 22, 11)}" fill="none" stroke="#ffffff" stroke-width="1.6" stroke-linejoin="round"/>`
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-12%" y="-8%" width="124%" height="128%">
        <feDropShadow dx="0" dy="10" stdDeviation="12" flood-color="#0f172a" flood-opacity="0.12"/>
      </filter>
    </defs>
    <path d="${card}" fill="#ffffff" filter="url(#${fid})"/>
    ${ribbon}
    ${checks.join('')}
    <rect x="${btnX}" y="${btnY}" width="${g.btnW}" height="${g.btnH}" rx="${g.btnH / 2}" fill="currentColor"/>
  </svg>`
}

function pricingThreePlansFeaturedChromeSpecs() {
  const g = PRICING_TF_GEOM
  const w = cardW()
  const h = graphicH()
  const specs = []
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `PRICING_TF_${i + 1}`,
      kind: 'graphic',
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h,
      color: PRICING_TF_PALETTE[i].main,
      layer: 4,
    })
  }
  return specs
}

function pricingThreePlansFeaturedOverlay(gx, gy, gw, gh) {
  const g = PRICING_TF_GEOM
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
  const cents = []
  const bodies = []
  const items = [[], [], []]
  const ctas = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const y = g.cardY
    labels.push(box(x + 16, y + 18, w - 32, 28))
    prices.push(box(x + w / 2 - 92, y + 52, 94, 52))
    cents.push(box(x + w / 2 + 4, y + 56, 52, 26))
    bodies.push(box(x + 22, y + 112, w - 44, 72))
    for (let k = 0; k < 3; k += 1) {
      items[i].push(box(x + 46, y + 198 + k * 44, w - 68, 28))
    }
    ctas.push(box(
      x + (w - g.btnW) / 2,
      y + g.cardH - g.btnH / 2 + g.ctaNudgeY,
      g.btnW,
      g.btnH - 4,
    ))
  }
  return {
    eyebrow: box(g.eyebrowX, g.eyebrowY, g.eyebrowW, g.eyebrowH),
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    labels,
    prices,
    cents,
    bodies,
    items,
    ctas,
  }
}

function specToPricingThreePlansFeaturedContent(spec) {
  return { svg: cardChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function pricingThreePlansFeaturedPreviewSvg() {
  const specs = pricingThreePlansFeaturedChromeSpecs()
  const g = PRICING_TF_GEOM
  const parts = specs.map((spec) => {
    const inner = specToPricingThreePlansFeaturedContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 100 100'}" preserveAspectRatio="none" color="${spec.color}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingThreePlansFeaturedElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_TF_GEOM.viewW
  const sy = canvasH / PRICING_TF_GEOM.viewH
  const overlay = pricingThreePlansFeaturedOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_TF_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingThreePlansFeaturedTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-pricef'),
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
      align: 'left', verticalAlign: 'center', fontSize: 34, fontWeight: 800, color: titleColor, clipToSlot: true, lineHeight: 1, letterSpacing: '0.04em',
    }),
  ]
  for (let i = 0; i < 3; i += 1) {
    const n = i + 1
    const pal = PRICING_TF_PALETTE[i]
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 15, fontWeight: 700, color: '#6B7280', clipToSlot: true, lineHeight: 1, letterSpacing: '0.12em',
    }))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'right', verticalAlign: 'center', fontSize: 40, fontWeight: 800, color: '#4B5563', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_CENTS`, overlay.cents[i], {
      align: 'left', verticalAlign: 'top', fontSize: 16, fontWeight: 700, color: '#6B7280', clipToSlot: true, lineHeight: 1,
    }))
    next.push(placeText(`PLAN_${n}_BODY`, overlay.bodies[i], {
      align: 'center', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#9CA3AF', clipToSlot: true, lineHeight: 1.35, wrap: 'wrap', fontStyle: 'italic',
    }))
    for (let k = 0; k < 3; k += 1) {
      const on = k < pal.checks
      const color = on ? (i === 0 ? pal.main : '#4B5563') : '#9CA3AF'
      next.push(placeText(`PLAN_${n}_ITEM_${k + 1}`, overlay.items[i][k], {
        align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 500, color, clipToSlot: true, lineHeight: 1.2,
      }))
    }
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], {
      align: 'center', verticalAlign: 'center', fontSize: 13, fontWeight: 700, color: '#ffffff', clipToSlot: true, lineHeight: 1.2,
    }))
  }

  const chrome = pricingThreePlansFeaturedChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingThreePlansFeaturedContent(spec)
    return {
      id: prev?.id || newId('shp-pricef'),
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

function layoutPricingThreePlansFeatured(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingThreePlansFeaturedElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingThreePlansFeaturedElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingThreePlansFeaturedLayout,
  layoutPricingThreePlansFeatured,
};
