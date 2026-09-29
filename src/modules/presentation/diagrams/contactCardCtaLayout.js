/**
 * Contact Card CTA
 * Layout ID: contact_card_cta_v1
 *
 * Centered card with address / phone / email rows and a Get in touch pill.
 * Closing Contact CTA and split/image twins keep their own look.
 */

function isContactCardCtaLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/split|image|overlay|thank_you|centered_text|minimal|closing_contact/i.test(id)) return false
  return id === 'contact_card_cta_v1' || id === 'contact_card_cta'
}

const CONTACT_CARD_CTA_DEFAULTS = {
  HEADING: "Let's connect",
  CONTACT_ADDRESS: '123 Main Street',
  CONTACT_PHONE: '+1 (555) 123-4567',
  CONTACT_EMAIL: 'hello@company.com',
  CTA: 'Get in touch',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  cardX: 460,
  cardY: 88,
  cardW: 1000,
  cardH: 904,
  cardR: 40,
  headingX: 500,
  headingY: 124,
  headingW: 920,
  headingH: 88,
  iconX: 548,
  iconSize: 56,
  rowYs: [248, 392, 520],
  labelX: 632,
  valueX: 632,
  valueW: 760,
  addressH: 88,
  valueH: 48,
  pillX: 700,
  pillY: 680,
  pillW: 520,
  pillH: 80,
}

function iconPaths(cx, cy) {
  return {
    pin: `M ${cx} ${cy - 12} c -8 0 -14 6 -14 14 c 0 11 14 22 14 22 s 14 -11 14 -22 c 0 -8 -6 -14 -14 -14 z M ${cx} ${cy + 1} a 5 5 0 1 1 0.01 0`,
    phone: `M ${cx - 10} ${cy - 6} h 7 l 3 5 h 10 v 13 h -20 z M ${cx - 3} ${cy - 12} h 6`,
    mail: `M ${cx - 14} ${cy - 8} h 28 v 18 h -28 z M ${cx - 14} ${cy - 8} l 14 10 l 14 -10`,
  }
}

function buildContactCardCtaChromeSvg() {
  const { cardX, cardY, cardW, cardH, cardR, iconX, iconSize, rowYs, labelX } = GEOM
  const labels = ['Address', 'Phone', 'Email']
  const kinds = ['pin', 'phone', 'mail']
  const rows = rowYs.map((y, i) => {
    const cx = iconX + iconSize / 2
    const cy = y + iconSize / 2
    const d = iconPaths(cx, cy)[kinds[i]]
    return `<circle cx="${cx}" cy="${cy}" r="${iconSize / 2}" fill="currentColor" opacity="0.12"/>
      <circle cx="${cx}" cy="${cy}" r="${iconSize / 2}" fill="none" stroke="currentColor" stroke-width="2" opacity="0.35"/>
      <path d="${d}" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>
      <text x="${labelX}" y="${y + 22}" fill="currentColor" font-size="18" font-weight="700" font-family="system-ui,sans-serif" opacity="0.85">${labels[i]}</text>`
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="cccShadow" x="-8%" y="-6%" width="120%" height="120%">
        <feDropShadow dx="0" dy="16" stdDeviation="20" flood-color="#94A3B8" flood-opacity="0.2" />
      </filter>
    </defs>
    <ellipse cx="160" cy="80" rx="240" ry="130" fill="currentColor" opacity="0.08"/>
    <ellipse cx="1760" cy="80" rx="240" ry="130" fill="currentColor" opacity="0.08"/>
    <rect x="${cardX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="#FFFFFF" filter="url(#cccShadow)"/>
    ${rows}
  </svg>`
}

function buildContactCardCtaPillSvg() {
  const { pillW, pillH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${pillW} ${pillH}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${pillW}" height="${pillH}" rx="${pillH / 2}" fill="currentColor"/>
  </svg>`
}

function findEl(elements, ids) {
  const set = new Set(ids)
  return (elements || []).find((e) => set.has(String(e.slotId || '').toUpperCase()))
}

function textOf(el, fallback) {
  const txt = el?.content?.text || el?.text
  if (txt && String(txt).trim()) return String(txt).trim()
  return fallback
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill
  if (fill && typeof fill === 'object' && fill.color) return fill.color
  return fallback
}

function textEl({ id, slotId, role, x, y, w, h, text, fontSize, fontWeight, color, maxLines, lineHeight = 1.25, align = 'left', verticalAlign = 'flex-start' }) {
  return {
    id,
    slotId,
    type: 'text',
    role,
    layer: 12,
    placement: { x, y, width: w, height: h, rotation: 0, opacity: 1 },
    content: {
      text,
      fontSize,
      fontWeight,
      color,
      align,
      verticalAlign,
      lineHeight,
      clipToSlot: true,
      maxLines,
    },
  }
}

function buildElements({ canvasW, canvasH, heading, address, phone, email, cta, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = CONTACT_CARD_CTA_DEFAULTS
  const valueX = Math.round(GEOM.valueX * sx)
  const valueW = Math.round(GEOM.valueW * sx)
  const [y0, y1, y2] = GEOM.rowYs
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildContactCardCtaChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    {
      id: prev.CTA_BG?.id || 'slot-CTA_BG',
      slotId: 'CTA_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 8,
      placement: {
        x: Math.round(GEOM.pillX * sx),
        y: Math.round(GEOM.pillY * sy),
        width: Math.round(GEOM.pillW * sx),
        height: Math.round(GEOM.pillH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: buildContactCardCtaPillSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    textEl({
      id: prev.HEADING?.id || 'slot-HEADING',
      slotId: 'HEADING',
      role: 'heading',
      x: Math.round(GEOM.headingX * sx),
      y: Math.round(GEOM.headingY * sy),
      w: Math.round(GEOM.headingW * sx),
      h: Math.round(GEOM.headingH * sy),
      text: heading || d.HEADING,
      fontSize: Math.round(48 * scale),
      fontWeight: 800,
      color: textColor,
      maxLines: 1,
      align: 'center',
      verticalAlign: 'middle',
    }),
    textEl({
      id: prev.CONTACT_ADDRESS?.id || 'slot-CONTACT_ADDRESS',
      slotId: 'CONTACT_ADDRESS',
      role: 'body',
      x: valueX,
      y: Math.round((y0 + 32) * sy),
      w: valueW,
      h: Math.round(GEOM.addressH * sy),
      text: address || d.CONTACT_ADDRESS,
      fontSize: Math.round(22 * scale),
      fontWeight: 500,
      color: mutedColor,
      maxLines: 2,
    }),
    textEl({
      id: prev.CONTACT_PHONE?.id || 'slot-CONTACT_PHONE',
      slotId: 'CONTACT_PHONE',
      role: 'body',
      x: valueX,
      y: Math.round((y1 + 32) * sy),
      w: valueW,
      h: Math.round(GEOM.valueH * sy),
      text: phone || d.CONTACT_PHONE,
      fontSize: Math.round(22 * scale),
      fontWeight: 500,
      color: mutedColor,
      maxLines: 1,
    }),
    textEl({
      id: prev.CONTACT_EMAIL?.id || 'slot-CONTACT_EMAIL',
      slotId: 'CONTACT_EMAIL',
      role: 'body',
      x: valueX,
      y: Math.round((y2 + 32) * sy),
      w: valueW,
      h: Math.round(GEOM.valueH * sy),
      text: email || d.CONTACT_EMAIL,
      fontSize: Math.round(22 * scale),
      fontWeight: 500,
      color: mutedColor,
      maxLines: 1,
    }),
    textEl({
      id: prev.CTA?.id || 'slot-CTA',
      slotId: 'CTA',
      role: 'cta',
      x: Math.round(GEOM.pillX * sx),
      y: Math.round(GEOM.pillY * sy),
      w: Math.round(GEOM.pillW * sx),
      h: Math.round(GEOM.pillH * sy),
      text: cta || d.CTA,
      fontSize: Math.round(24 * scale),
      fontWeight: 700,
      color: '#FFFFFF',
      maxLines: 1,
      align: 'center',
      verticalAlign: 'middle',
    }),
  ]
}

function layoutContactCardCta(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || '#6366F1'
  const textColor = pal.text || '#0F172A'
  const mutedColor = pal.muted || '#64748B'
  const prev = {
    IMAGE_CARD_BG: findEl(elements, ['IMAGE_CARD_BG']),
    CTA_BG: findEl(elements, ['CTA_BG']),
    HEADING: findEl(elements, ['HEADING']),
    CONTACT_ADDRESS: findEl(elements, ['CONTACT_ADDRESS']),
    CONTACT_PHONE: findEl(elements, ['CONTACT_PHONE']),
    CONTACT_EMAIL: findEl(elements, ['CONTACT_EMAIL']),
    CTA: findEl(elements, ['CTA']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, CONTACT_CARD_CTA_DEFAULTS.HEADING),
    address: textOf(prev.CONTACT_ADDRESS, CONTACT_CARD_CTA_DEFAULTS.CONTACT_ADDRESS),
    phone: textOf(prev.CONTACT_PHONE, CONTACT_CARD_CTA_DEFAULTS.CONTACT_PHONE),
    email: textOf(prev.CONTACT_EMAIL, CONTACT_CARD_CTA_DEFAULTS.CONTACT_EMAIL),
    cta: textOf(prev.CTA, CONTACT_CARD_CTA_DEFAULTS.CTA),
    accent: resolveStoredColor(prev.CTA_BG, accent) || resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildContactCardCtaCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = CONTACT_CARD_CTA_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
    address: String(by.CONTACT_ADDRESS || content.address || d.CONTACT_ADDRESS).trim(),
    phone: String(by.CONTACT_PHONE || content.phone || d.CONTACT_PHONE).trim(),
    email: String(by.CONTACT_EMAIL || content.email || d.CONTACT_EMAIL).trim(),
    cta: String(by.CTA || content.cta || d.CTA).trim(),
    accent: pal.primary || pal.accent || '#6366F1',
    textColor: pal.text || '#0F172A',
    mutedColor: pal.muted || '#64748B',
  })
}

function xmlText(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function contactCardCtaPreviewSvg() {
  const chrome = buildContactCardCtaChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const d = CONTACT_CARD_CTA_DEFAULTS
  const { headingX, headingY, headingW, headingH, valueX, rowYs, pillX, pillY, pillW, pillH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    ${chrome}
    <text x="${headingX + headingW / 2}" y="${headingY + headingH * 0.7}" text-anchor="middle" fill="#0F172A" font-size="48" font-weight="800" font-family="system-ui,sans-serif">${xmlText(d.HEADING)}</text>
    <text x="${valueX}" y="${rowYs[0] + 62}" fill="#64748B" font-size="22" font-weight="500" font-family="system-ui,sans-serif">${xmlText(d.CONTACT_ADDRESS)}</text>
    <text x="${valueX}" y="${rowYs[1] + 62}" fill="#64748B" font-size="22" font-weight="500" font-family="system-ui,sans-serif">${xmlText(d.CONTACT_PHONE)}</text>
    <text x="${valueX}" y="${rowYs[2] + 62}" fill="#64748B" font-size="22" font-weight="500" font-family="system-ui,sans-serif">${xmlText(d.CONTACT_EMAIL)}</text>
    <rect x="${pillX}" y="${pillY}" width="${pillW}" height="${pillH}" rx="${pillH / 2}" fill="#6366F1"/>
    <text x="${pillX + pillW / 2}" y="${pillY + pillH * 0.64}" text-anchor="middle" fill="#FFFFFF" font-size="24" font-weight="700" font-family="system-ui,sans-serif">${xmlText(d.CTA)}</text>
  </svg>`
}

module.exports = {
  isContactCardCtaLayout,
  CONTACT_CARD_CTA_DEFAULTS,
  buildContactCardCtaChromeSvg,
  buildContactCardCtaPillSvg,
  layoutContactCardCta,
  buildContactCardCtaCanvasElements,
  contactCardCtaPreviewSvg,
};
