/**
 * Agenda three-column cards — overlapping icon, numbered bar, title, body, footer dash.
 */

const AGENDA_THREE_COLUMN_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 8,
  headingH: 42,
  padX: 72,
  gutter: 36,
  colTopY: 161,
  colBottomPad: 16,
  iconR: 42,
  bandH: 44,
  radius: 16,
  iconToBarGap: 16,
}

const DEFAULT_COLUMN_PALETTE = [
  { main: '#1E4B8C', iconKey: 'document' },
  { main: '#3D7EDB', iconKey: 'clipboard' },
  { main: '#4EC4D4', iconKey: 'briefcase' },
]

function parseHex(hex) {
  const raw = String(hex || '').replace('#', '')
  if (raw.length !== 6) return null
  const n = Number.parseInt(raw, 16)
  if (Number.isNaN(n)) return null
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

function toHex(r, g, b) {
  return `#${[r, g, b].map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('')}`
}

function mixHex(a, b, t) {
  const A = parseHex(a) || [30, 75, 140]
  const B = parseHex(b) || [255, 255, 255]
  return toHex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t)
}

function columnRects() {
  const { viewW, viewH, padX, gutter, colTopY, colBottomPad } = AGENDA_THREE_COLUMN_GEOM
  const colW = (viewW - padX * 2 - gutter * 2) / 3
  const colH = viewH - colTopY - colBottomPad
  return [0, 1, 2].map((i) => {
    const x = padX + i * (colW + gutter)
    return { x, y: colTopY, w: colW, h: colH, cx: x + colW / 2 }
  })
}

function iconPath(key, cx, cy, size) {
  const s = size * 0.32
  const paths = {
    document: `M ${cx - s * 0.42} ${cy - s * 0.55} h ${s * 0.55} l ${s * 0.28} ${s * 0.28} v ${s * 0.82} h ${-s * 0.83} z M ${cx + s * 0.13} ${cy - s * 0.55} v ${s * 0.28} h ${s * 0.28} M ${cx - s * 0.18} ${cy + s * 0.05} h ${s * 0.42} M ${cx - s * 0.18} ${cy + s * 0.28} h ${s * 0.28} M ${cx + s * 0.08} ${cy + s * 0.02} a ${s * 0.22} ${s * 0.22} 0 1 1 0 0.01 M ${cx + s * 0.08} ${cy + s * 0.02} l ${s * 0.08} ${s * 0.12} l ${s * 0.12} ${-s * 0.2}`,
    clipboard: `M ${cx - s * 0.38} ${cy - s * 0.28} h ${s * 0.76} v ${s * 0.9} h ${-s * 0.76} z M ${cx - s * 0.18} ${cy - s * 0.42} h ${s * 0.36} v ${s * 0.22} h ${-s * 0.36} z M ${cx - s * 0.14} ${cy + s * 0.08} h ${s * 0.28} M ${cx - s * 0.14} ${cy + s * 0.3} h ${s * 0.2}`,
    briefcase: `M ${cx - s * 0.55} ${cy - s * 0.08} h ${s * 1.1} v ${s * 0.7} h ${-s * 1.1} z M ${cx - s * 0.22} ${cy - s * 0.42} h ${s * 0.44} v ${s * 0.34} h ${-s * 0.44} z M ${cx - s * 0.55} ${cy + s * 0.18} h ${s * 1.1}`,
    gear: `M ${cx} ${cy - s * 0.55} l ${s * 0.22} ${s * 0.12} l ${s * 0.12} ${-s * 0.22} l ${s * 0.35} 0 l ${s * 0.12} ${s * 0.22} l ${s * 0.22} ${-s * 0.12} l ${s * 0.22} ${s * 0.12} l ${-s * 0.12} ${s * 0.22} l 0 ${s * 0.35} l ${-s * 0.22} ${s * 0.12} l ${-s * 0.12} ${-s * 0.22} l ${-s * 0.35} 0 l ${-s * 0.12} ${s * 0.22} l ${-s * 0.22} ${-s * 0.12} l ${-s * 0.22} ${s * 0.12} l ${s * 0.12} ${s * 0.22} l 0 ${-s * 0.35} z M ${cx} ${cy} m ${-s * 0.28} 0 a ${s * 0.28} ${s * 0.28} 0 1 0 ${s * 0.56} 0 a ${s * 0.28} ${s * 0.28} 0 1 0 ${-s * 0.56} 0`,
    clock: `M ${cx} ${cy} m ${-s * 0.55} 0 a ${s * 0.55} ${s * 0.55} 0 1 0 ${s * 1.1} 0 a ${s * 0.55} ${s * 0.55} 0 1 0 ${-s * 1.1} 0 M ${cx} ${cy} V ${cy - s * 0.25} M ${cx} ${cy} L ${cx + s * 0.28} ${cy + s * 0.18}`,
    lightbulb: `M ${cx} ${cy - s * 0.72} q ${s * 0.85} ${s * 0.48} ${s * 0.85} ${s * 1.05} q 0 ${s * 0.55} ${-s * 0.45} ${s * 0.85} h ${-s * 0.8} q ${-s * 0.45} ${-s * 0.3} ${-s * 0.45} ${-s * 0.85} q 0 ${-s * 0.57} ${s * 0.85} ${-s * 1.05}`,
    calendar: `M ${cx - s * 0.55} ${cy - s * 0.25} h ${s * 1.1} v ${s * 0.95} h ${-s * 1.1} z M ${cx - s * 0.35} ${cy - s * 0.55} v ${s * 0.35} M ${cx + s * 0.35} ${cy - s * 0.55} v ${s * 0.35}`,
    chart: `M ${cx - s * 0.5} ${cy + s * 0.55} V ${cy - s * 0.1} M ${cx} ${cy + s * 0.55} V ${cy - s * 0.65} M ${cx + s * 0.5} ${cy + s * 0.55} V ${cy + s * 0.15}`,
    user: `M ${cx} ${cy - s * 0.42} a ${s * 0.38} ${s * 0.38} 0 1 1 0 ${s * 0.76} a ${s * 0.38} ${s * 0.38} 0 1 1 0 ${-s * 0.76} M ${cx - s * 0.62} ${cy + s * 0.82} q ${s * 0.62} ${-s * 0.42} ${s * 1.24} 0`,
  }
  return paths[key] || paths.document
}

function ringDash(i) {
  if (i === 1) return '6 5'
  if (i === 2) return '2 3.8'
  return ''
}

function resolveColumnPalette(colors = {}) {
  const accent = colors.accent || '#3D7EDB'
  return DEFAULT_COLUMN_PALETTE.map((p, i) => ({
    ...p,
    main: mixHex(p.main, accent, 0.12 + i * 0.02),
  }))
}

function agendaThreeColumnGraphicFrame(canvasW, canvasH) {
  const headingY = Math.round(canvasH * 0.04)
  const headingH = Math.round(canvasH * 0.078)
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY,
    headingH,
  }
}

function agendaThreeColumnCardInlineSvg(spec) {
  const w = spec.w
  const h = spec.h
  const color = spec.color
  const iconR = spec.iconR
  const cx = w / 2
  const iconCy = iconR
  const cardY = iconR
  const cardH = h - iconR
  const radius = spec.radius
  const notchR = iconR + 10
  const barY = iconR * 2 + (spec.iconToBarGap || 18)
  const barH = spec.bandH
  const footW = Math.min(80, w * 0.3)
  const footY = h - 22
  const dash = spec.ringDash ? ` stroke-dasharray="${spec.ringDash}"` : ''
  const iconD = iconPath(spec.iconKey, cx, iconCy, iconR * 1.5)
  const uid = String(spec.slotId || 'c').replace(/[^a-z0-9]/gi, '')
  const numSize = Math.round(barH * 0.62)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <mask id="notch-${uid}">
        <rect x="0" y="${cardY}" width="${w}" height="${cardH}" rx="${radius}" fill="#fff"/>
        <circle cx="${cx}" cy="${iconCy}" r="${notchR}" fill="#000"/>
      </mask>
    </defs>
    <rect x="2" y="${cardY}" width="${w - 4}" height="${cardH}" rx="${radius}" fill="#ffffff" stroke="${color}" stroke-width="2.6" mask="url(#notch-${uid})"/>
    <rect x="${cx - footW / 2}" y="${footY}" width="${footW}" height="9" rx="4" fill="${color}"/>
    <circle cx="${cx}" cy="${iconCy}" r="${iconR}" fill="#ffffff"/>
    <circle cx="${cx}" cy="${iconCy}" r="${iconR - 9}" fill="${color}"/>
    <circle cx="${cx}" cy="${iconCy}" r="${iconR - 1.2}" fill="none" stroke="${color}" stroke-width="2.6"${dash}/>
    <path d="${iconD}" fill="none" stroke="#ffffff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
    <rect x="2" y="${barY}" width="${w - 4}" height="${barH}" fill="${color}"/>
    <text x="${cx}" y="${barY + barH / 2}" dominant-baseline="middle" text-anchor="middle" fill="#ffffff" stroke="none" font-size="${numSize}" font-weight="800" font-family="Arial,Helvetica,sans-serif">${spec.badge}</text>
  </svg>`
}

function agendaThreeColumnRuleInlineSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 4" width="100%" height="100%" preserveAspectRatio="none"><rect x="0" y="1.5" width="1000" height="1.5" fill="currentColor" opacity="0"/></svg>'
}

function agendaThreeColumnIconInlineSvg(iconKey = 'document') {
  const cx = 28
  const cy = 28
  const d = iconPath(iconKey, cx, cy, 44)
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 56 56" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><circle cx="${cx}" cy="${cy}" r="26" fill="#ffffff"/><path d="${d}" fill="none" stroke="#4B5563" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
}

function agendaThreeColumnNumberInlineSvg(label = '01') {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 48" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><text x="40" y="36" text-anchor="middle" fill="#ffffff" font-size="28" font-weight="800" font-family="system-ui,sans-serif">${label}</text></svg>`
}

function plainTextFromContent(content = {}) {
  if (typeof content.text === 'string') return content.text
  if (Array.isArray(content.runs)) return content.runs.map((r) => r.text || '').join('')
  return ''
}

function colouredColumnTextContent(content = {}, opts = {}) {
  const {
    color = '#111827',
    fontSize = 16,
    fontWeight = 400,
    fontStyle,
    align = 'center',
    verticalAlign = 'flex-start',
  } = opts
  return {
    text: plainTextFromContent(content),
    color,
    colorRole: null,
    fill: null,
    runs: null,
    fontSize,
    fontWeight,
    fontStyle: fontStyle || undefined,
    align,
    verticalAlign,
    letterSpacing: '0',
    lineHeight: 1,
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
    listType: null,
  }
}

function agendaThreeColumnChromeSpecs(colors = {}) {
  const palette = resolveColumnPalette(colors)
  const { iconR, bandH, radius, iconToBarGap } = AGENDA_THREE_COLUMN_GEOM
  const specs = []
  const cols = columnRects()

  for (let i = 0; i < 3; i += 1) {
    const col = cols[i]
    const pal = palette[i % palette.length]
    const n = i + 1
    specs.push({
      slotId: `AGENDA_COL_CHROME_${n}`,
      kind: 'graphic',
      cardChrome: true,
      x: col.x,
      y: col.y - iconR,
      w: col.w,
      h: col.h + iconR,
      color: pal.main,
      iconKey: pal.iconKey,
      iconR,
      bandH,
      radius,
      iconToBarGap,
      ringDash: ringDash(i),
      badge: String(n).padStart(2, '0'),
      layer: 4,
    })
  }
  return specs
}

function agendaThreeColumnOverlayPlacements(gx, gy, gw, gh) {
  const sx = gw / AGENDA_THREE_COLUMN_GEOM.viewW
  const sy = gh / AGENDA_THREE_COLUMN_GEOM.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(32, Math.round(w * sx)),
    height: Math.max(22, Math.round(h * sy)),
  })

  const { headingY, headingH, iconR, bandH, iconToBarGap, viewW } = AGENDA_THREE_COLUMN_GEOM
  const overlay = {
    heading: box(80, headingY, viewW - 160, headingH),
    columns: [],
  }
  const cols = columnRects()

  for (let i = 0; i < 3; i += 1) {
    const col = cols[i]
    const pad = col.w * 0.1
    const textW = col.w - pad * 2
    const textX = col.x + pad
    const barY = col.y + iconR + iconToBarGap
    const headingBoxY = barY + bandH + 10
    const bodyY = headingBoxY + 40
    const itemH = 34
    const itemGap = 4
    overlay.columns.push({
      heading: box(textX, headingBoxY, textW, 38),
      items: [
        box(textX, bodyY, textW, itemH),
        box(textX, bodyY + itemH + itemGap, textW, itemH),
        box(textX, bodyY + (itemH + itemGap) * 2, textW, itemH),
        box(-940 - i * 20, -900, 8, 8),
      ],
    })
  }
  return overlay
}

function buildAgendaThreeColumnPreviewSvg(colors = {}) {
  const specs = agendaThreeColumnChromeSpecs(colors)
  const { viewW, viewH } = AGENDA_THREE_COLUMN_GEOM
  const parts = specs.map((spec) => {
    const inner = agendaThreeColumnCardInlineSvg(spec)
    const match = inner.match(/<svg[^>]*>([\s\S]*)<\/svg>/i)
    return `<g transform="translate(${spec.x},${spec.y})">${match ? match[1] : ''}</g>`
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}">${parts.join('')}</svg>`
}

function agendaThreeColumnPreviewSvg(colors = {}) {
  return buildAgendaThreeColumnPreviewSvg(colors).replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"'
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"'
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"'
    return `<svg${next}>`
  })
}

function specToThreeColumnContent(spec) {
  if (spec.cardChrome) {
    return { svg: agendaThreeColumnCardInlineSvg(spec), colorMode: 'original', fill: spec.color }
  }
  if (spec.rule) {
    return { svg: agendaThreeColumnRuleInlineSvg(), colorMode: 'recolorable', fill: '#94a3b8' }
  }
  if (spec.badge) {
    return { svg: agendaThreeColumnNumberInlineSvg(spec.badge), colorMode: 'fixed', fill: '#ffffff' }
  }
  if (spec.iconKey) {
    return { svg: agendaThreeColumnIconInlineSvg(spec.iconKey), colorMode: 'fixed', fill: '#ffffff' }
  }
  return { svg: agendaThreeColumnIconInlineSvg('document'), colorMode: 'fixed', fill: '#ffffff' }
}

function isAgendaThreeColumnColouredLayout(layoutId, family, variant) {
  if (family === 'three_col' && (variant === 'coloured' || variant === 'default' || !variant)) {
    return true
  }
  return /agenda_three_(columns|icons)_v1/i.test(String(layoutId || ''))
}

function isAgendaThreeColumnTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || /^AGENDA_COL_\d+_(HEADING|ITEM_[123])$/.test(sid)
}

module.exports = {
  AGENDA_THREE_COLUMN_GEOM,
  DEFAULT_COLUMN_PALETTE,
  agendaThreeColumnGraphicFrame,
  agendaThreeColumnCardInlineSvg,
  agendaThreeColumnRuleInlineSvg,
  agendaThreeColumnIconInlineSvg,
  agendaThreeColumnNumberInlineSvg,
  colouredColumnTextContent,
  agendaThreeColumnChromeSpecs,
  agendaThreeColumnOverlayPlacements,
  agendaThreeColumnPreviewSvg,
  specToThreeColumnContent,
  isAgendaThreeColumnColouredLayout,
  isAgendaThreeColumnTextSlot,
};
