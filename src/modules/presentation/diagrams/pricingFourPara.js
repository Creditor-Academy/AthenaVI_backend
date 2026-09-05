/**
 * Pricing four para — 2×2 prospectus tiles, paragraph-first (not feature lists).
 * Layout id: pricing_four_para_v1 only (not cards).
 */

const PRICING_FPA_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 36,
  headingY: 16,
  headingW: 640,
  headingH: 34,
  introX: 36,
  introY: 50,
  introW: 820,
  introH: 28,
  padX: 32,
  gridY: 88,
  padBottom: 20,
  gap: 16,
  n: 4,
  spine: 12,
  fold: 28,
}

const PRICING_FPA_PALETTE = ['#3D5A80', '#EE6C4D', '#2A9D8F', '#6D597A']

const PARA = 'A short paragraph that explains who this plan is for and what working together actually looks like in practice.'

const PRICING_FPA_DEFAULTS = {
  HEADING: 'Choose a plan',
  BODY: 'Four ways to work with us — written as stories, not a feature dump.',
  PLAN_1_LABEL: 'Starter',
  PLAN_1_PRICE: '$29',
  PLAN_1_BODY: PARA,
  PLAN_1_CTA: 'Explore plan',
  PLAN_2_LABEL: 'Studio',
  PLAN_2_PRICE: '$79',
  PLAN_2_BODY: PARA,
  PLAN_2_CTA: 'Explore plan',
  PLAN_3_LABEL: 'Agency',
  PLAN_3_PRICE: '$149',
  PLAN_3_BODY: PARA,
  PLAN_3_CTA: 'Explore plan',
  PLAN_4_LABEL: 'Partner',
  PLAN_4_PRICE: '$299',
  PLAN_4_BODY: PARA,
  PLAN_4_CTA: 'Explore plan',
}

function isPricingFourParaLayout(layoutId) {
  const id = String(layoutId || '')
  if (/cards/i.test(id)) return false
  return /pricing_four_para_v1$/i.test(id)
}

function isPricingFourParaTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || sid === 'BODY'
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_BODY$/.test(sid)
    || /^PLAN_\d+_CTA$/.test(sid)
}

function cellW() {
  const g = PRICING_FPA_GEOM
  return (g.viewW - g.padX * 2 - g.gap) / 2
}

function cellH() {
  const g = PRICING_FPA_GEOM
  return (g.viewH - g.gridY - g.padBottom - g.gap) / 2
}

function cellPos(i) {
  const g = PRICING_FPA_GEOM
  const col = i % 2
  const row = Math.floor(i / 2)
  return {
    x: g.padX + col * (cellW() + g.gap),
    y: g.gridY + row * (cellH() + g.gap),
  }
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
    : (PRICING_FPA_DEFAULTS[sid] || existing)
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
  const g = PRICING_FPA_GEOM
  const w = cellW()
  const h = cellH()
  const fid = `fpaSh${spec.n || 1}`
  const clipId = `fpaClip${spec.n || 1}`
  const spine = g.spine
  const fold = g.fold
  const marks = []
  for (let k = 0; k < (spec.n || 1); k += 1) {
    marks.push(`<circle cx="${spine / 2}" cy="${18 + k * 14}" r="3.2" fill="#ffffff" fill-opacity="0.92"/>`)
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="${fid}" x="-8%" y="-8%" width="116%" height="120%">
        <feDropShadow dx="0" dy="5" stdDeviation="6" flood-color="#1e293b" flood-opacity="0.12"/>
      </filter>
      <clipPath id="${clipId}"><rect x="0.6" y="0.6" width="${w - 1.2}" height="${h - 1.2}" rx="14"/></clipPath>
    </defs>
    <rect x="0.6" y="0.6" width="${w - 1.2}" height="${h - 1.2}" rx="14" fill="#FFFEFB" stroke="#E7E2D8" stroke-width="1.1" filter="url(#${fid})"/>
    <g clip-path="url(#${clipId})">
      <rect x="0" y="0" width="${spine}" height="${h}" fill="currentColor"/>
      ${marks.join('')}
      <path d="M ${w - fold} 0 L ${w} 0 L ${w} ${fold} Z" fill="currentColor"/>
      <path d="M ${w - fold} 0 L ${w - fold} ${fold} L ${w} ${fold}" fill="none" stroke="#ffffff" stroke-opacity="0.45" stroke-width="1"/>
      <rect x="${spine}" y="${h - 6}" width="${w - spine}" height="6" fill="currentColor" opacity="0.14"/>
    </g>
  </svg>`
}

function pricingFourParaChromeSpecs() {
  const specs = []
  for (let i = 0; i < PRICING_FPA_GEOM.n; i += 1) {
    const pos = cellPos(i)
    specs.push({
      slotId: `PRICING_FPA_${i + 1}`,
      n: i + 1,
      x: pos.x,
      y: pos.y,
      w: cellW(),
      h: cellH(),
      color: PRICING_FPA_PALETTE[i],
      layer: 4,
    })
  }
  return specs
}

function pricingFourParaOverlay(gx, gy, gw, gh) {
  const g = PRICING_FPA_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(16, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })
  const w = cellW()
  const h = cellH()
  const labels = []
  const prices = []
  const bodies = []
  const ctas = []
  for (let i = 0; i < g.n; i += 1) {
    const { x, y } = cellPos(i)
    const left = x + g.spine + 16
    const innerW = w - g.spine - 28 - g.fold * 0.2
    labels.push(box(left, y + 16, innerW, 26))
    prices.push(box(left, y + 44, innerW * 0.7, 36))
    bodies.push(box(left, y + 86, innerW, h - 128))
    ctas.push(box(left, y + h - 34, 140, 20))
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

function specToPricingFourParaContent(spec) {
  return { svg: cardChromeSvg(spec), colorMode: 'recolorable', fill: spec.color }
}

function pricingFourParaPreviewSvg() {
  const specs = pricingFourParaChromeSpecs()
  const g = PRICING_FPA_GEOM
  const parts = specs.map((spec) => {
    const inner = specToPricingFourParaContent(spec).svg
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    const vb = inner.match(/viewBox="([^"]+)"/)
    return `<svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="${vb ? vb[1] : '0 0 100 100'}" preserveAspectRatio="none" color="${spec.color}">${match ? match[1] : ''}</svg>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`
}

function layoutPricingFourParaElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_FPA_GEOM.viewW
  const sy = canvasH / PRICING_FPA_GEOM.viewH
  const overlay = pricingFourParaOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_FPA_/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingFourParaTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-pricefpa'),
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
      align: 'left', verticalAlign: 'center', fontSize: 26, fontWeight: 800, color: titleColor, clipToSlot: true, lineHeight: 1.1,
    }, 'heading'),
    placeText('BODY', overlay.intro, {
      align: 'left', verticalAlign: 'center', fontSize: 13, fontWeight: 500, color: mute, clipToSlot: true, lineHeight: 1.3,
    }, 'body'),
  ]
  for (let i = 0; i < 4; i += 1) {
    const n = i + 1
    const pal = PRICING_FPA_PALETTE[i]
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'left', verticalAlign: 'center', fontSize: 15, fontWeight: 800, color: pal, clipToSlot: true, lineHeight: 1,
    }, 'heading'))
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'left', verticalAlign: 'center', fontSize: 28, fontWeight: 800, color: '#111827', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`PLAN_${n}_BODY`, overlay.bodies[i], {
      align: 'left', verticalAlign: 'top', fontSize: 12, fontWeight: 400, color: '#4B5563', clipToSlot: true, lineHeight: 1.4, wrap: 'wrap',
    }, 'body'))
    next.push(placeText(`PLAN_${n}_CTA`, overlay.ctas[i], {
      align: 'left', verticalAlign: 'center', fontSize: 12, fontWeight: 700, color: pal, clipToSlot: true, lineHeight: 1,
    }, 'caption'))
  }

  const chrome = pricingFourParaChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingFourParaContent(spec)
    return {
      id: prev?.id || newId('shp-pricefpa'),
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

function layoutPricingFourPara(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingFourParaElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingFourParaElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingFourParaLayout,
  layoutPricingFourPara,
}
