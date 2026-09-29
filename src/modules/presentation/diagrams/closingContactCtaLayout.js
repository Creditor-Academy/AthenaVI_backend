/**
 * Closing Contact CTA
 * Layout ID: closing_contact_cta_v1
 *
 * Connect heading, highlighted email, and Get in touch pill.
 * Contact Card CTA and split/image twins keep their own look.
 */

function isClosingContactCtaLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/card|split|image|overlay|thank_you|centered_text|minimal/i.test(id)) return false
  return id === 'closing_contact_cta_v1' || id === 'closing_contact_cta'
}

const CLOSING_CONTACT_CTA_DEFAULTS = {
  HEADING: "Let's connect",
  CONTACT: 'hello@company.com',
  CTA: 'Get in touch',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headingX: 160,
  headingY: 220,
  headingW: 1600,
  headingH: 140,
  contactX: 240,
  contactY: 390,
  contactW: 1440,
  contactH: 64,
  underlineY: 468,
  pillX: 700,
  pillY: 540,
  pillW: 520,
  pillH: 84,
}

function buildClosingContactCtaChromeSvg() {
  const { underlineY } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <ellipse cx="140" cy="70" rx="260" ry="140" fill="currentColor" opacity="0.08"/>
    <ellipse cx="1780" cy="70" rx="260" ry="140" fill="currentColor" opacity="0.08"/>
    <ellipse cx="960" cy="1100" rx="440" ry="150" fill="currentColor" opacity="0.06"/>
    <rect x="810" y="${underlineY}" width="300" height="3" rx="1.5" fill="currentColor"/>
  </svg>`
}

function buildClosingContactCtaPillSvg() {
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

function textEl({ id, slotId, role, x, y, w, h, text, fontSize, fontWeight, color, maxLines, lineHeight = 1.2 }) {
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
      align: 'center',
      verticalAlign: 'middle',
      lineHeight,
      clipToSlot: true,
      maxLines,
    },
  }
}

function buildElements({ canvasW, canvasH, heading, contact, cta, accent, textColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = CLOSING_CONTACT_CTA_DEFAULTS
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildClosingContactCtaChromeSvg(),
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
        svg: buildClosingContactCtaPillSvg(),
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
      fontSize: Math.round(72 * scale),
      fontWeight: 800,
      color: textColor,
      maxLines: 2,
    }),
    textEl({
      id: prev.CONTACT?.id || 'slot-CONTACT',
      slotId: 'CONTACT',
      role: 'contact',
      x: Math.round(GEOM.contactX * sx),
      y: Math.round(GEOM.contactY * sy),
      w: Math.round(GEOM.contactW * sx),
      h: Math.round(GEOM.contactH * sy),
      text: contact || d.CONTACT,
      fontSize: Math.round(28 * scale),
      fontWeight: 600,
      color: accent,
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
    }),
  ]
}

function layoutClosingContactCta(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || '#6366F1'
  const textColor = pal.text || '#0F172A'
  const prev = {
    IMAGE_CARD_BG: findEl(elements, ['IMAGE_CARD_BG']),
    CTA_BG: findEl(elements, ['CTA_BG']),
    HEADING: findEl(elements, ['HEADING']),
    CONTACT: findEl(elements, ['CONTACT']),
    CTA: findEl(elements, ['CTA']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, CLOSING_CONTACT_CTA_DEFAULTS.HEADING),
    contact: textOf(prev.CONTACT, CLOSING_CONTACT_CTA_DEFAULTS.CONTACT),
    cta: textOf(prev.CTA, CLOSING_CONTACT_CTA_DEFAULTS.CTA),
    accent: resolveStoredColor(prev.CTA_BG, accent) || resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildClosingContactCtaCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = CLOSING_CONTACT_CTA_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
    contact: String(by.CONTACT || content.contact || d.CONTACT).trim(),
    cta: String(by.CTA || content.cta || d.CTA).trim(),
    accent: pal.primary || pal.accent || '#6366F1',
    textColor: pal.text || '#0F172A',
  })
}

function xmlText(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function closingContactCtaPreviewSvg() {
  const chrome = buildClosingContactCtaChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { headingX, headingY, headingW, headingH, contactX, contactY, contactW, contactH, pillX, pillY, pillW, pillH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    ${chrome}
    <text x="${headingX + headingW / 2}" y="${headingY + headingH * 0.7}" text-anchor="middle" fill="#0F172A" font-size="72" font-weight="800" font-family="system-ui,sans-serif">${xmlText(CLOSING_CONTACT_CTA_DEFAULTS.HEADING)}</text>
    <text x="${contactX + contactW / 2}" y="${contactY + contactH * 0.68}" text-anchor="middle" fill="#6366F1" font-size="28" font-weight="600" font-family="system-ui,sans-serif">${xmlText(CLOSING_CONTACT_CTA_DEFAULTS.CONTACT)}</text>
    <rect x="${pillX}" y="${pillY}" width="${pillW}" height="${pillH}" rx="${pillH / 2}" fill="#6366F1"/>
    <text x="${pillX + pillW / 2}" y="${pillY + pillH * 0.64}" text-anchor="middle" fill="#FFFFFF" font-size="24" font-weight="700" font-family="system-ui,sans-serif">${xmlText(CLOSING_CONTACT_CTA_DEFAULTS.CTA)}</text>
  </svg>`
}

module.exports = {
  isClosingContactCtaLayout,
  CLOSING_CONTACT_CTA_DEFAULTS,
  buildClosingContactCtaChromeSvg,
  buildClosingContactCtaPillSvg,
  layoutClosingContactCta,
  buildClosingContactCtaCanvasElements,
  closingContactCtaPreviewSvg,
};
