/**
 * Centered Text CTA
 * Layout ID: centered_text_cta_v1
 *
 * Centered thank-you, subtitle, accent pill, and contact line.
 * Thank-you / minimal / contact CTA twins keep their own look.
 */

function isCenteredTextCtaLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/thank_you|minimal|contact_card|closing_contact|split|overlay|image/i.test(id)) return false
  return id === 'centered_text_cta_v1' || id === 'centered_text_cta'
}

const CENTERED_TEXT_CTA_DEFAULTS = {
  HEADING: 'Thank you',
  SUBTITLE: "Let's build something great together",
  CTA: 'Book a demo',
  CONTACT: 'hello@company.com',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headingX: 180,
  headingY: 228,
  headingW: 1560,
  headingH: 140,
  subtitleX: 260,
  subtitleY: 388,
  subtitleW: 1400,
  subtitleH: 80,
  pillX: 690,
  pillY: 520,
  pillW: 540,
  pillH: 88,
  contactX: 360,
  contactY: 680,
  contactW: 1200,
  contactH: 52,
}

function buildCenteredTextCtaChromeSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <ellipse cx="160" cy="80" rx="280" ry="150" fill="currentColor" opacity="0.08"/>
    <ellipse cx="1760" cy="80" rx="280" ry="150" fill="currentColor" opacity="0.08"/>
    <ellipse cx="960" cy="1080" rx="480" ry="160" fill="currentColor" opacity="0.06"/>
  </svg>`
}

function buildCenteredTextCtaPillSvg() {
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

function textEl({ id, slotId, role, x, y, w, h, text, fontSize, fontWeight, color, maxLines, lineHeight = 1.25 }) {
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

function buildElements({ canvasW, canvasH, heading, subtitle, cta, contact, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = CENTERED_TEXT_CTA_DEFAULTS
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildCenteredTextCtaChromeSvg(),
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
        svg: buildCenteredTextCtaPillSvg(),
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
      id: prev.SUBTITLE?.id || 'slot-SUBTITLE',
      slotId: 'SUBTITLE',
      role: 'subheading',
      x: Math.round(GEOM.subtitleX * sx),
      y: Math.round(GEOM.subtitleY * sy),
      w: Math.round(GEOM.subtitleW * sx),
      h: Math.round(GEOM.subtitleH * sy),
      text: subtitle || d.SUBTITLE,
      fontSize: Math.round(28 * scale),
      fontWeight: 500,
      color: mutedColor,
      maxLines: 2,
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
    textEl({
      id: prev.CONTACT?.id || 'slot-CONTACT',
      slotId: 'CONTACT',
      role: 'caption',
      x: Math.round(GEOM.contactX * sx),
      y: Math.round(GEOM.contactY * sy),
      w: Math.round(GEOM.contactW * sx),
      h: Math.round(GEOM.contactH * sy),
      text: contact || d.CONTACT,
      fontSize: Math.round(18 * scale),
      fontWeight: 500,
      color: mutedColor,
      maxLines: 1,
    }),
  ]
}

function layoutCenteredTextCta(docOrElements, schema = {}, palette = {}, canvas = {}) {
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
    SUBTITLE: findEl(elements, ['SUBTITLE']),
    CTA: findEl(elements, ['CTA']),
    CONTACT: findEl(elements, ['CONTACT']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, CENTERED_TEXT_CTA_DEFAULTS.HEADING),
    subtitle: textOf(prev.SUBTITLE, CENTERED_TEXT_CTA_DEFAULTS.SUBTITLE),
    cta: textOf(prev.CTA, CENTERED_TEXT_CTA_DEFAULTS.CTA),
    contact: textOf(prev.CONTACT, CENTERED_TEXT_CTA_DEFAULTS.CONTACT),
    accent: resolveStoredColor(prev.CTA_BG, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildCenteredTextCtaCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = CENTERED_TEXT_CTA_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
    subtitle: String(by.SUBTITLE || content.subtitle || d.SUBTITLE).trim(),
    cta: String(by.CTA || content.cta || d.CTA).trim(),
    contact: String(by.CONTACT || content.contact || d.CONTACT).trim(),
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

function centeredTextCtaPreviewSvg() {
  const chrome = buildCenteredTextCtaChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { headingX, headingY, headingW, headingH, subtitleX, subtitleY, subtitleW, subtitleH, pillX, pillY, pillW, pillH, contactX, contactY, contactW } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    ${chrome}
    <text x="${headingX + headingW / 2}" y="${headingY + headingH * 0.72}" text-anchor="middle" fill="#0F172A" font-size="72" font-weight="800" font-family="system-ui,sans-serif">${xmlText(CENTERED_TEXT_CTA_DEFAULTS.HEADING)}</text>
    <text x="${subtitleX + subtitleW / 2}" y="${subtitleY + subtitleH * 0.65}" text-anchor="middle" fill="#64748B" font-size="28" font-weight="500" font-family="system-ui,sans-serif">${xmlText(CENTERED_TEXT_CTA_DEFAULTS.SUBTITLE)}</text>
    <rect x="${pillX}" y="${pillY}" width="${pillW}" height="${pillH}" rx="${pillH / 2}" fill="#6366F1"/>
    <text x="${pillX + pillW / 2}" y="${pillY + pillH * 0.64}" text-anchor="middle" fill="#FFFFFF" font-size="24" font-weight="700" font-family="system-ui,sans-serif">${xmlText(CENTERED_TEXT_CTA_DEFAULTS.CTA)}</text>
    <text x="${contactX + contactW / 2}" y="${contactY + 36}" text-anchor="middle" fill="#64748B" font-size="18" font-weight="500" font-family="system-ui,sans-serif">${xmlText(CENTERED_TEXT_CTA_DEFAULTS.CONTACT)}</text>
  </svg>`
}


module.exports = {
  isCenteredTextCtaLayout,
  CENTERED_TEXT_CTA_DEFAULTS,
  buildCenteredTextCtaChromeSvg,
  buildCenteredTextCtaPillSvg,
  layoutCenteredTextCta,
  buildCenteredTextCtaCanvasElements,
  centeredTextCtaPreviewSvg,
};
