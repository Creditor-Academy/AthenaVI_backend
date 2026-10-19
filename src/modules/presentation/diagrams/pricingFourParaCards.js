/**
 * Pricing four para cards — vertical membership cards with chip header + paragraph body.
 * Layout id: pricing_four_para_cards_v1 only.
 */

const PRICING_FPAC_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 40,
  headingY: 12,
  headingW: 920,
  headingH: 30,
  introX: 80,
  introY: 42,
  introW: 840,
  introH: 24,
  padX: 22,
  cardY: 76,
  cardH: 460,
  gap: 14,
  n: 4,
  headH: 148,
}

const PRICING_FPAC_PALETTE = ['#C4A35A', '#1B365D', '#1F7A5C', '#3A2F45']

const PARA = 'A short paragraph that explains who this plan is for and what working together actually looks like in practice.'

const PRICING_FPAC_DEFAULTS = {
  HEADING: 'Membership cards',
  BODY: 'Pick a card — each plan is a paragraph, not a checklist.',
  PLAN_1_LABEL: 'Bronze',
  PLAN_1_PRICE: '$39',
  PLAN_1_BODY: PARA,
  PLAN_1_CTA: 'Get this card',
  PLAN_2_LABEL: 'Silver',
  PLAN_2_PRICE: '$89',
  PLAN_2_BODY: PARA,
  PLAN_2_CTA: 'Get this card',
  PLAN_3_LABEL: 'Gold',
  PLAN_3_PRICE: '$159',
  PLAN_3_BODY: PARA,
  PLAN_3_CTA: 'Get this card',
  PLAN_4_LABEL: 'Black',
  PLAN_4_PRICE: '$329',
  PLAN_4_BODY: PARA,
  PLAN_4_CTA: 'Get this card',
}

function isPricingFourParaCardsLayout(layoutId) {
  return /pricing_four_para_cards_v1$/i.test(String(layoutId || ''))
}

function isPricingFourParaCardsTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || sid === 'BODY'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_BODY$/.test(sid)
    || /^PLAN_\d+_CTA$/.test(sid)
}

function cardW() {
  const g = PRICING_FPAC_GEOM
  return (g.viewW - g.padX * 2 - g.gap * (g.n - 1)) / g.n
}

function cardX(i) {
  return PRICING_FPAC_GEOM.padX + i * (cardW() + PRICING_FPAC_GEOM.gap)
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

function mutedInk(palette = {}) {
  return hexLum(palette.bg || palette.background || '#ffffff') < 0.45 ? '#CBD5E1' : '#64748B'
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
    : (PRICING_FPAC_DEFAULTS[sid] || existing)
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

function cardChromeSvg(spec) {
  const g = PRICING_FPAC_GEOM
  const w = cardW()
  const h = g.cardH
  const hh = g.headH
  const fid = `fpacSh${spec.n || 1}`
  const clipId = `fpacClip${spec.n || 1}`
  const featured = spec.n === 3
  const chip = `<rect x="16" y="18" width="36" height="26" rx="4" fill="#F5E6B8" fill-opacity="0.92"/>
    <rect x="20" y="22" width="28" height="6" rx="1" fill="#C9A227" fill-opacity="0.55"/>
    <rect x="20" y="32" width="18" height="6" rx="1" fill="#C9A227" fill-opacity="0.35"/>`
  const waves = [0, 1, 2].map((k) => {
    const r = 10 + k * 7
    return `<path d="M ${w - 22 - r} 28 A ${r} ${r} 0 0 1 ${w - 22 + r} 28" fill="none" stroke="#ffffff" stroke-opacity="${0.55 - k * 0.14}" stroke-width="1.4"/>`
  }).join('')
  const badge = featured
    ? `<path d="M ${w - 54} 0 L ${w} 0 L ${w} 40 Z" fill="#F5E6B8"/><path d="M ${w - 38} 10 L ${w - 10} 10" stroke="#1B365D" stroke-width="2"/>`
    : ''
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-12%" y="-8%" width="124%" height="118%">
        <feDropShadow dx="0" dy="8" stdDeviation="8" flood-color="#0f172a" flood-opacity="0.16"/>
      </filter>
      <clipPath id="${clipId}"><rect x="0.7" y="0.7" width="${w - 1.4}" height="${h - 1.4}" rx="16"/></clipPath>
    </defs>
    <rect x="0.7" y="0.7" width="${w - 1.4}" height="${h - 1.4}" rx="16" fill="#FFFEFB" stroke="#E8E4DC" stroke-width="1.1" filter="url(#${fid})"/>
    <g clip-path="url(#${clipId})">
      <rect x="0" y="0" width="${w}" height="${hh}" fill="currentColor"/>
      ${chip}
      ${waves}
      ${badge}
    </g>
  </svg>`
}

function pricingFourParaCardsChromeSpecs() {
  const g = PRICING_FPAC_GEOM
  const w = cardW()
  const specs = []
  for (let i = 0; i < g.n; i += 1) {
    specs.push({
      slotId: `PRICING_FPAC_${i + 1}`,
      n: i + 1,
      x: cardX(i),
      y: g.cardY,
      w,
      h: g.cardH,
      color: PRICING_FPAC_PALETTE[i],
      layer: 4,
    })
  }
  return specs
}

function pricingFourParaCardsOverlay(gx, gy, gw, gh) {
  const g = PRICING_FPAC_GEOM
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
  const bodies = []
  const ctas = []
  for (let i = 0; i < g.n; i += 1) {
    const x = cardX(i)
    const y = g.cardY
    labels.push(box(x + 14, y + 58, w - 28, 24))
    prices.push(box(x + 14, y + 86, w - 28, 42))
    bodies.push(box(x + 14, y + g.headH + 16, w - 28, 210))
    ctas.push(box(x + 14, y + g.cardH - 44, w - 28, 22))
  }
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    intro: box(g.introX, g.introY, g.introW, g.introH),
    labels,
    prices,
    bodies,
    ctas,
  }
}

function specToPricingFourParaCardsContent(spec) {
  return { svg: cardChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function pricingFourParaCardsPreviewSvg() {
  const specs = pricingFourParaCardsChromeSpecs()
  const g = PRICING_FPAC_GEOM
  const parts = specs.map((spec) => {
    const inner = specToPricingFourParaCardsContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 100 100'}" preserveAspectRatio="none" color="${spec.color}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingFourParaCardsElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_FPAC_GEOM.viewW
  const sy = canvasH / PRICING_FPAC_GEOM.viewH
  const overlay = pricingFourParaCardsOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_FPAC_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingFourParaCardsTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-pricefpac'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const titleColor = headingInk(palette)
  const mute = mutedInk(palette)
  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'center', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: titleColor, clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('BODY', overlay.intro, {
      align: 'center', verticalAlign: 'center', fontSize: 12, fontWeight: 500, color: mute, clipToSlot: true, lineHeight: 1.3,
    }, 'body'),
  ]
  for (let i = 0; i < 4; i += 1) {
    const n = i + 1
    const pal = PRICING_FPAC_PALETTE[i]
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1, letterSpacing: '0.04em',
    }, 'heading'))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'left', verticalAlign: 'center', fontSize: 26, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`PLAN_${n}_BODY`, overlay.bodies[i], {
      align: 'left', verticalAlign: 'top', fontSize: 11, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'))
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], {
      align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 700, color: pal, clipToSlot: true, lineHeight: 1,
    }, 'caption'))
  }

  const chrome = pricingFourParaCardsChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingFourParaCardsContent(spec)
    return {
      id: prev?.id || newId('shp-pricefpac'),
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

function layoutPricingFourParaCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingFourParaCardsElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingFourParaCardsElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingFourParaCardsLayout,
  layoutPricingFourParaCards,
}
