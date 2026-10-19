/**
 * Minimal Text CTA
 * Layout ID: minimal_text_cta_v1
 *
 * Quiet closer: heading, thin accent rule, compact pill.
 * Centered Text CTA and Closing Thank You keep their own engines.
 */

function isMinimalTextCtaLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/thank_you|centered_text|contact|image|overlay|split/i.test(id)) return false
  return id === 'minimal_text_cta_v1' || id === 'minimal_text_cta'
}

const MINIMAL_TEXT_CTA_DEFAULTS = {
  HEADING: 'Thank you',
  CTA: 'Book a demo',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headingX: 200,
  headingY: 360,
  headingW: 1520,
  headingH: 100,
  ruleY: 488,
  pillX: 740,
  pillY: 560,
  pillW: 440,
  pillH: 72,
}

function buildMinimalTextCtaChromeSvg() {
  const { ruleY } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <ellipse cx="960" cy="1080" rx="420" ry="140" fill="currentColor" opacity="0.06"/>
    <rect x="860" y="${ruleY}" width="200" height="3" rx="1.5" fill="currentColor"/>
  </svg>`
}

function buildMinimalTextCtaPillSvg() {
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

function buildElements({ canvasW, canvasH, heading, cta, accent, textColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = MINIMAL_TEXT_CTA_DEFAULTS
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildMinimalTextCtaChromeSvg(),
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
        svg: buildMinimalTextCtaPillSvg(),
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
      fontSize: Math.round(56 * scale),
      fontWeight: 600,
      color: textColor,
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
      fontSize: Math.round(22 * scale),
      fontWeight: 700,
      color: '#FFFFFF',
      maxLines: 1,
    }),
  ]
}

function layoutMinimalTextCta(docOrElements, schema = {}, palette = {}, canvas = {}) {
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
    CTA: findEl(elements, ['CTA']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, MINIMAL_TEXT_CTA_DEFAULTS.HEADING),
    cta: textOf(prev.CTA, MINIMAL_TEXT_CTA_DEFAULTS.CTA),
    accent: resolveStoredColor(prev.CTA_BG, accent) || resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildMinimalTextCtaCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = MINIMAL_TEXT_CTA_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
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

function minimalTextCtaPreviewSvg() {
  const chrome = buildMinimalTextCtaChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { headingX, headingY, headingW, headingH, pillX, pillY, pillW, pillH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    ${chrome}
    <text x="${headingX + headingW / 2}" y="${headingY + headingH * 0.68}" text-anchor="middle" fill="#0F172A" font-size="56" font-weight="600" font-family="system-ui,sans-serif">${xmlText(MINIMAL_TEXT_CTA_DEFAULTS.HEADING)}</text>
    <rect x="${pillX}" y="${pillY}" width="${pillW}" height="${pillH}" rx="${pillH / 2}" fill="#6366F1"/>
    <text x="${pillX + pillW / 2}" y="${pillY + pillH * 0.64}" text-anchor="middle" fill="#FFFFFF" font-size="22" font-weight="700" font-family="system-ui,sans-serif">${xmlText(MINIMAL_TEXT_CTA_DEFAULTS.CTA)}</text>
  </svg>`
}

module.exports = {
  isMinimalTextCtaLayout,
  MINIMAL_TEXT_CTA_DEFAULTS,
  buildMinimalTextCtaChromeSvg,
  buildMinimalTextCtaPillSvg,
  layoutMinimalTextCta,
  buildMinimalTextCtaCanvasElements,
  minimalTextCtaPreviewSvg,
};
