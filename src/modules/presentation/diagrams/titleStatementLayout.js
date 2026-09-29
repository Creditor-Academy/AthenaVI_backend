/**
 * Title Statement
 * Layout ID: title_statement_v1
 *
 * Left-aligned editorial statement: a large headline, accent bar, then a
 * supporting paragraph. Distinct from Headline Centered and Title Statement Split.
 */

function isTitleStatementLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'title_statement_v1' || id === 'title_statement'
}

const TITLE_STATEMENT_DEFAULTS = {
  HEADLINE: 'Bold opening statement',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headX: 140,
  headY: 240,
  headW: 1320,
  headH: 280,
  barX: 140,
  barY: 544,
  barW: 72,
  barH: 6,
  bodyX: 140,
  bodyY: 580,
  bodyW: 1100,
  bodyH: 280,
}

const TYPE = {
  headline: { size: 40, weight: 800, lh: 1.15 },
  body: { size: 18, weight: 400, lh: 1.5 },
}

function buildTitleStatementChromeSvg() {
  const { barX, barY, barW, barH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <path d="M1180 0 H1920 V1080 H1480 C 1320 720 1280 280 1180 0 Z" fill="currentColor" opacity="0.05" />
    <circle cx="1760" cy="160" r="180" fill="currentColor" opacity="0.07" />
    <circle cx="1760" cy="160" r="104" fill="none" stroke="currentColor" stroke-width="2" opacity="0.16" />
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

function textEl({ slotId, prev, x, y, w, h, text, fontSize, fontWeight, color, lineHeight, maxLines, sx, sy, scale, role }) {
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
      align: 'left',
      verticalAlign: 'flex-start',
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
        svg: buildTitleStatementChromeSvg(),
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
      maxLines: 4,
      role: 'heading',
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
      maxLines: 5,
      role: 'body',
      sx, sy, scale,
    }),
  ]
}

function layoutTitleStatement(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headlineEl = findEl(elements, ['HEADLINE', 'HEADING', 'MAIN_TITLE', 'TITLE'])
  const bodyEl = findEl(elements, ['BODY', 'SUBTITLE'])
  const cardEl = findEl(elements, ['IMAGE_CARD_BG'])
  const out = buildElements({
    canvasW,
    canvasH,
    headline: textOf(headlineEl, TITLE_STATEMENT_DEFAULTS.HEADLINE),
    body: textOf(bodyEl, TITLE_STATEMENT_DEFAULTS.BODY),
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev: { IMAGE_CARD_BG: cardEl, HEADLINE: headlineEl, BODY: bodyEl },
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildTitleStatementCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    headline: String(bySlot.HEADLINE || bySlot.HEADING || content.heading || content.title || TITLE_STATEMENT_DEFAULTS.HEADLINE).trim(),
    body: String(bySlot.BODY || content.body || TITLE_STATEMENT_DEFAULTS.BODY).trim(),
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isTitleStatementLayout,
  layoutTitleStatement,
  buildTitleStatementChromeSvg,
  TITLE_STATEMENT_DEFAULTS,
};
