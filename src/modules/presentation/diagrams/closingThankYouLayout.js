/**
 * Closing Thank You
 * Layout ID: closing_thank_you_v1
 *
 * Oversized centered thank-you with a short closer line.
 * Centered Text CTA and Minimal Text CTA keep their own engines.
 */

function isClosingThankYouLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/centered_text|minimal|contact|image|overlay|split/i.test(id)) return false
  return id === 'closing_thank_you_v1' || id === 'closing_thank_you'
}

const CLOSING_THANK_YOU_DEFAULTS = {
  HEADING: 'Thank you',
  SUBTITLE: 'Questions?',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headingX: 140,
  headingY: 300,
  headingW: 1640,
  headingH: 180,
  markY: 516,
  subtitleX: 280,
  subtitleY: 560,
  subtitleW: 1360,
  subtitleH: 80,
}

function buildClosingThankYouChromeSvg() {
  const { markY } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <ellipse cx="120" cy="90" rx="300" ry="160" fill="currentColor" opacity="0.08"/>
    <ellipse cx="1800" cy="90" rx="300" ry="160" fill="currentColor" opacity="0.08"/>
    <ellipse cx="960" cy="1100" rx="520" ry="180" fill="currentColor" opacity="0.06"/>
    <circle cx="960" cy="${markY}" r="6" fill="currentColor"/>
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

function textEl({ id, slotId, role, x, y, w, h, text, fontSize, fontWeight, color, maxLines, lineHeight = 1.15 }) {
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
      verticalAlign: 'flex-start',
      lineHeight,
      clipToSlot: true,
      maxLines,
    },
  }
}

function buildElements({ canvasW, canvasH, heading, subtitle, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = CLOSING_THANK_YOU_DEFAULTS
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildClosingThankYouChromeSvg(),
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
      fontSize: Math.round(96 * scale),
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
      fontSize: Math.round(32 * scale),
      fontWeight: 500,
      color: mutedColor,
      maxLines: 2,
    }),
  ]
}

function layoutClosingThankYou(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || '#6366F1'
  const textColor = pal.text || '#0F172A'
  const mutedColor = pal.muted || '#64748B'
  const prev = {
    IMAGE_CARD_BG: findEl(elements, ['IMAGE_CARD_BG']),
    HEADING: findEl(elements, ['HEADING']),
    SUBTITLE: findEl(elements, ['SUBTITLE']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, CLOSING_THANK_YOU_DEFAULTS.HEADING),
    subtitle: textOf(prev.SUBTITLE, CLOSING_THANK_YOU_DEFAULTS.SUBTITLE),
    accent: resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildClosingThankYouCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = CLOSING_THANK_YOU_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
    subtitle: String(by.SUBTITLE || content.subtitle || d.SUBTITLE).trim(),
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

function closingThankYouPreviewSvg() {
  const chrome = buildClosingThankYouChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { headingX, headingY, headingW, headingH, subtitleX, subtitleY, subtitleW, subtitleH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    ${chrome}
    <text x="${headingX + headingW / 2}" y="${headingY + headingH * 0.72}" text-anchor="middle" fill="#0F172A" font-size="96" font-weight="800" font-family="system-ui,sans-serif">${xmlText(CLOSING_THANK_YOU_DEFAULTS.HEADING)}</text>
    <text x="${subtitleX + subtitleW / 2}" y="${subtitleY + subtitleH * 0.68}" text-anchor="middle" fill="#64748B" font-size="32" font-weight="500" font-family="system-ui,sans-serif">${xmlText(CLOSING_THANK_YOU_DEFAULTS.SUBTITLE)}</text>
  </svg>`
}


module.exports = {
  isClosingThankYouLayout,
  CLOSING_THANK_YOU_DEFAULTS,
  buildClosingThankYouChromeSvg,
  layoutClosingThankYou,
  buildClosingThankYouCanvasElements,
  closingThankYouPreviewSvg,
};
