/**
 * Pricing comparison table — navy header, zebra rows, storage + check grid.
 * Layout id: pricing_comparison_table_v1 only (not cards).
 */

const PRICING_PCT_GEOM = {
  viewW: 1000,
  viewH: 560,
  x: 36,
  y: 36,
  w: 928,
  h: 488,
  headerH: 86,
  rows: 7,
  labelShare: 0.30,
}

const NAVY = '#1B365D'
const ORANGE = '#E67E22'
const LABEL_BLUE = '#3D6B99'
const ZEBRA = '#EEF3F8'

const FEATURE = 'LOREM IPSUM IS SIMPLY DUMMY'

const PRICING_PCT_DEFAULTS = {
  HEADING: 'PRICING TABLE',
  PLAN_1_PRICE: 'FREE',
  PLAN_1_LABEL: 'LIGHT',
  PLAN_2_PRICE: '$20',
  PLAN_2_LABEL: 'PROFESSIONAL',
  PLAN_3_PRICE: '$50',
  PLAN_3_LABEL: 'EXTENDED',
  PLAN_4_PRICE: '$100',
  PLAN_4_LABEL: 'FULL',
  FEATURE_1: FEATURE,
  FEATURE_2: FEATURE,
  FEATURE_3: FEATURE,
  FEATURE_4: FEATURE,
  FEATURE_5: FEATURE,
  FEATURE_6: FEATURE,
  FEATURE_7: FEATURE,
  PLAN_1_ITEM_1: '10GB',
  PLAN_2_ITEM_1: '50GB',
  PLAN_3_ITEM_1: '200GB',
  PLAN_4_ITEM_1: '1TB',
}

/** 0 none, 1 navy check, 2 orange check — body rows 2–7 (after storage). */
const CHECK_MAP = [
  [1, 1, 1, 1],
  [1, 1, 1, 1],
  [0, 1, 1, 1],
  [0, 0, 2, 2],
  [0, 0, 2, 2],
  [0, 0, 0, 2],
]

function isPricingComparisonTableLayout(layoutId) {
  const id = String(layoutId || '')
  if (/cards/i.test(id)) return false
  return /pricing_comparison_table_v1$/i.test(id)
}

function isPricingComparisonTableTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING'
    || /^PLAN_\d+_PRICE$/.test(sid)
    || /^PLAN_\d+_LABEL$/.test(sid)
    || /^PLAN_\d+_ITEM_1$/.test(sid)
    || /^FEATURE_\d+$/.test(sid)
}

function labelW() {
  return PRICING_PCT_GEOM.w * PRICING_PCT_GEOM.labelShare
}

function planW() {
  return (PRICING_PCT_GEOM.w - labelW()) / 4
}

function colX(i) {
  const g = PRICING_PCT_GEOM
  if (i === 0) return g.x
  return g.x + labelW() + (i - 1) * planW()
}

function colW(i) {
  return i === 0 ? labelW() : planW()
}

function rowH() {
  const g = PRICING_PCT_GEOM
  return (g.h - g.headerH) / g.rows
}

function rowY(r) {
  return PRICING_PCT_GEOM.y + PRICING_PCT_GEOM.headerH + r * rowH()
}

function checkIcon(cx, cy, r, kind) {
  const fill = kind === 2 ? ORANGE : 'currentColor'
  const d = `M ${cx - r * 0.38} ${cy + 0.02 * r} L ${cx - r * 0.08} ${cy + r * 0.34} L ${cx + r * 0.42} ${cy - r * 0.3}`
  return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}"/>
    <path d="${d}" fill="none" stroke="#ffffff" stroke-width="${Math.max(1.6, r * 0.28)}" stroke-linecap="round" stroke-linejoin="round"/>`
}

function tableChromeSvg() {
  const g = PRICING_PCT_GEOM
  const w = g.w
  const h = g.h
  const hh = g.headerH
  const rh = rowH()
  const zebras = []
  for (let r = 0; r < g.rows; r += 1) {
    if (r % 2 === 0) {
      zebras.push(`<rect x="0" y="${hh + r * rh}" width="${w}" height="${rh}" fill="${ZEBRA}"/>`)
    }
  }
  const vlines = []
  for (let i = 1; i < 5; i += 1) {
    const x = colX(i) - g.x
    vlines.push(`<line x1="${x}" y1="${hh}" x2="${x}" y2="${h}" stroke="#D5DEE8" stroke-width="1"/>`)
    vlines.push(`<line x1="${x}" y1="8" x2="${x}" y2="${hh}" stroke="rgba(255,255,255,0.22)" stroke-width="1"/>`)
  }
  const checks = []
  for (let r = 0; r < 6; r += 1) {
    for (let p = 0; p < 4; p += 1) {
      const kind = CHECK_MAP[r][p]
      if (!kind) continue
      const cx = colX(p + 1) - g.x + colW(p + 1) / 2
      const cy = hh + (r + 1) * rh + rh / 2
      checks.push(checkIcon(cx, cy, 11, kind))
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="pctSh" x="-4%" y="-4%" width="108%" height="112%">
        <feDropShadow dx="0" dy="8" stdDeviation="10" flood-color="#0f172a" flood-opacity="0.14"/>
      </filter>
      <clipPath id="pctClip"><rect x="0" y="0" width="${w}" height="${h}" rx="16"/></clipPath>
    </defs>
    <rect x="0" y="0" width="${w}" height="${h}" rx="16" fill="#ffffff" filter="url(#pctSh)"/>
    <g clip-path="url(#pctClip)">
      <rect x="0" y="0" width="${w}" height="${h}" fill="#ffffff"/>
      ${zebras.join('')}
      <rect x="0" y="0" width="${w}" height="${hh}" fill="currentColor"/>
      ${vlines.join('')}
      ${checks.join('')}
    </g>
    <rect x="0.6" y="0.6" width="${w - 1.2}" height="${h - 1.2}" rx="16" fill="none" stroke="#D7DEE7" stroke-width="1.1"/>
  </svg>`
}

function pricingComparisonTableChromeSpecs() {
  const g = PRICING_PCT_GEOM
  return [{
    slotId: 'PRICING_PCT',
    x: g.x,
    y: g.y,
    w: g.w,
    h: g.h,
    color: NAVY,
    layer: 4,
  }]
}

function pricingComparisonTableOverlay(gx, gy, gw, gh) {
  const g = PRICING_PCT_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(16, Math.round(w * sx)),
    height: Math.max(12, Math.round(h * sy)),
  })
  const prices = []
  const labels = []
  const values = []
  const features = []
  const rh = rowH()
  for (let p = 0; p < 4; p += 1) {
    const x = colX(p + 1)
    const w = colW(p + 1)
    prices.push(box(x + 6, g.y + 12, w - 12, 42))
    labels.push(box(x + 6, g.y + 52, w - 12, 24))
    values.push(box(x + 6, rowY(0) + 8, w - 12, rh - 16))
  }
  for (let r = 0; r < 7; r += 1) {
    features.push(box(colX(0) + 16, rowY(r) + 8, colW(0) - 24, rh - 16))
  }
  return {
    heading: box(colX(0) + 14, g.y + 18, colW(0) - 24, g.headerH - 32),
    prices,
    labels,
    values,
    features,
  }
}

function specToPricingComparisonTableContent(spec) {
  return { svg: tableChromeSvg(), colorMode: 'recolorable', fill: spec.color }
}

function pricingComparisonTablePreviewSvg() {
  const spec = pricingComparisonTableChromeSpecs()[0]
  const inner = specToPricingComparisonTableContent(spec).svg
  const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
  const g = PRICING_PCT_GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">
    <svg x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" viewBox="0 0 ${spec.w} ${spec.h}" preserveAspectRatio="none" color="${spec.color}">${match ? match[1] : ''}</svg>
  </svg>`
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
    : (PRICING_PCT_DEFAULTS[sid] || existing)
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

function layoutPricingComparisonTableElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const sx = canvasW / PRICING_PCT_GEOM.viewW
  const sy = canvasH / PRICING_PCT_GEOM.viewH
  const overlay = pricingComparisonTableOverlay(0, 0, canvasW, canvasH)
  const chromeRe = /^PRICING_PCT$/i
  const prevBySlot = new Map(
    elements.filter((el) => chromeRe.test(String(el.slotId || ''))).map((el) => [String(el.slotId || '').toUpperCase(), el])
  )
  const filtered = elements.filter((el) => !chromeRe.test(String(el.slotId || '')) && isPricingComparisonTableTextSlot(el.slotId))
  const bySlot = new Map(filtered.map((el) => [String(el.slotId || '').toUpperCase(), el]))

  const placeText = (slotId, box, style, role) => {
    const prev = bySlot.get(slotId)
    return {
      id: prev?.id || newId('txt-pricepct'),
      type: 'text',
      slotId,
      role: prev?.role || role || 'body',
      layer: 12,
      placement: { x: box.x, y: box.y, width: box.width, height: box.height, rotation: 0, opacity: 1 },
      content: filledContent(prev, slotId, style),
    }
  }

  const next = [
    placeText('HEADING', overlay.heading, {
      align: 'left', verticalAlign: 'center', fontSize: 18, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1.1, letterSpacing: '0.04em',
    }, 'heading'),
  ]
  for (let i = 0; i < 4; i += 1) {
    const n = i + 1
    next.push(placeText(`PLAN_${n}_PRICE`, overlay.prices[i], {
      align: 'center', verticalAlign: 'center', fontSize: 22, fontWeight: 800, color: '#ffffff', clipToSlot: true, lineHeight: 1,
    }, 'stat'))
    next.push(placeText(`PLAN_${n}_LABEL`, overlay.labels[i], {
      align: 'center', verticalAlign: 'center', fontSize: 10, fontWeight: 700, color: 'rgba(255,255,255,0.88)', clipToSlot: true, lineHeight: 1, letterSpacing: '0.08em',
    }, 'caption'))
    next.push(placeText(`PLAN_${n}_ITEM_1`, overlay.values[i], {
      align: 'center', verticalAlign: 'center', fontSize: 16, fontWeight: 800, color: NAVY, clipToSlot: true, lineHeight: 1,
    }, 'stat'))
  }
  for (let r = 0; r < 7; r += 1) {
    next.push(placeText(`FEATURE_${r + 1}`, overlay.features[r], {
      align: 'left', verticalAlign: 'center', fontSize: 11, fontWeight: 700, color: LABEL_BLUE, clipToSlot: true, lineHeight: 1.15, letterSpacing: '0.04em',
    }, 'body'))
  }

  const chrome = pricingComparisonTableChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase())
    const graphic = specToPricingComparisonTableContent(spec)
    return {
      id: prev?.id || newId('shp-pricepct'),
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

function layoutPricingComparisonTable(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  if (Array.isArray(doc)) {
    return layoutPricingComparisonTableElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas)
  }
  const palette = themeTokens?.palette || themeTokens || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutPricingComparisonTableElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isPricingComparisonTableLayout,
  layoutPricingComparisonTable,
}
