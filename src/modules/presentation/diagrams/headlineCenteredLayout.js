/**
 * Headline Centered
 * Layout ID: headline_centered_v1
 *
 * Quiet editorial statement: a centered headline, accent dash, and supporting
 * paragraph. Chrome recolours with the theme accent.
 */

function isHeadlineCenteredLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'headline_centered_v1' || id === 'headline_centered'
}

const HEADLINE_CENTERED_DEFAULTS = {
  HEADLINE: 'Opening headline',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headX: 260,
  headY: 280,
  headW: 1400,
  headH: 220,
  barW: 72,
  barH: 6,
  barY: 524,
  bodyX: 360,
  bodyY: 560,
  bodyW: 1200,
  bodyH: 220,
}

const TYPE = {
  headline: { size: 40, weight: 800, lh: 1.15 },
  body: { size: 18, weight: 400, lh: 1.5 },
}

function buildHeadlineCenteredChromeSvg() {
  const { barW, barH, barY, viewW } = GEOM
  const barX = (viewW - barW) / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <circle cx="960" cy="540" r="420" fill="currentColor" opacity="0.04" />
    <circle cx="960" cy="540" r="310" fill="none" stroke="currentColor" stroke-width="2" opacity="0.12" />
    <circle cx="168" cy="140" r="120" fill="currentColor" opacity="0.05" />
    <circle cx="1760" cy="960" r="150" fill="currentColor" opacity="0.05" />
    <rect x="${barX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
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

function textEl({ slotId, prev, x, y, w, h, text, fontSize, fontWeight, color, lineHeight, maxLines, sx, sy, scale, role, align, verticalAlign }) {
  return {
    id: prev?.id || `slot-${slotId}`,
    slotId,
    type: 'text',
    role,
    layer: 10,
    placement: {
      x: Math.round(x * sx),
      y: Math.round(y * sy),
      width: Math.round(w * sx),
      height: Math.round(h * sy),
      rotation: 0,
      opacity: 1,
    },
    content: {
      text,
      fontSize: Math.round(fontSize * scale),
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

function paletteColors(palette) {
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  return {
    accent: pal.primary || pal.accent || '#6366F1',
    textColor: pal.text || '#0F172A',
    mutedColor: pal.muted || pal.textMuted || '#64748B',
  }
}

function buildElements({ canvasW, canvasH, headline, body, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildHeadlineCenteredChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    textEl({
      slotId: 'HEADLINE',
      prev: prev.HEADLINE,
      x: GEOM.headX,
      y: GEOM.headY,
      w: GEOM.headW,
      h: GEOM.headH,
      text: headline,
      fontSize: TYPE.headline.size,
      fontWeight: TYPE.headline.weight,
      color: textColor,
      lineHeight: TYPE.headline.lh,
      maxLines: 3,
      role: 'heading',
      align: 'center',
      verticalAlign: 'flex-end',
      sx, sy, scale,
    }),
    textEl({
      slotId: 'BODY',
      prev: prev.BODY,
      x: GEOM.bodyX,
      y: GEOM.bodyY,
      w: GEOM.bodyW,
      h: GEOM.bodyH,
      text: body,
      fontSize: TYPE.body.size,
      fontWeight: TYPE.body.weight,
      color: mutedColor,
      lineHeight: TYPE.body.lh,
      maxLines: 4,
      role: 'body',
      align: 'center',
      verticalAlign: 'flex-start',
      sx, sy, scale,
    }),
  ]
}

function layoutHeadlineCentered(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headlineEl = findEl(elements, ['HEADLINE', 'HEADING', 'MAIN_TITLE', 'TITLE'])
  const bodyEl = findEl(elements, ['BODY', 'SUBTITLE'])
  const cardEl = findEl(elements, ['IMAGE_CARD_BG', 'DIVIDER'])
  const out = buildElements({
    canvasW,
    canvasH,
    headline: textOf(headlineEl, HEADLINE_CENTERED_DEFAULTS.HEADLINE),
    body: textOf(bodyEl, HEADLINE_CENTERED_DEFAULTS.BODY),
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev: { IMAGE_CARD_BG: cardEl, HEADLINE: headlineEl, BODY: bodyEl },
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildHeadlineCenteredCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    headline: String(bySlot.HEADLINE || bySlot.HEADING || content.heading || content.title || HEADLINE_CENTERED_DEFAULTS.HEADLINE).trim(),
    body: String(bySlot.BODY || content.body || HEADLINE_CENTERED_DEFAULTS.BODY).trim(),
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isHeadlineCenteredLayout,
  layoutHeadlineCentered,
  buildHeadlineCenteredChromeSvg,
  HEADLINE_CENTERED_DEFAULTS,
};
