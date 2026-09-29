/**
 * Headline Right Text
 * Layout ID: headline_right_text_v1
 *
 * Asymmetric editorial: oversized headline in a tinted left panel,
 * supporting copy in a floating card on the right.
 * Distinct from Title Statement Split (equal columns + center rule).
 */

function isHeadlineRightTextLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'headline_right_text_v1' || id === 'headline_right_text'
}

const HEADLINE_RIGHT_TEXT_DEFAULTS = {
  HEADLINE: 'Section headline',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without crowding the headline.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  panelW: 820,
  stripX: 812,
  stripW: 8,
  dashX: 108,
  dashY: 268,
  dashW: 56,
  dashH: 6,
  headX: 108,
  headY: 300,
  headW: 640,
  headH: 520,
  cardX: 900,
  cardY: 160,
  cardW: 900,
  cardH: 760,
  cardR: 36,
  bodyX: 960,
  bodyY: 240,
  bodyW: 780,
  bodyH: 600,
}

const TYPE = {
  headline: { size: 40, weight: 800, lh: 1.14 },
  body: { size: 18, weight: 400, lh: 1.55 },
}

function buildHeadlineRightTextChromeSvg() {
  const {
    panelW, stripX, stripW, dashX, dashY, dashW, dashH,
    cardX, cardY, cardW, cardH, cardR,
  } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="hrtCardShadow" x="-8%" y="-6%" width="120%" height="120%">
        <feDropShadow dx="0" dy="18" stdDeviation="22" flood-color="#94A3B8" flood-opacity="0.16" />
      </filter>
    </defs>
    <rect x="0" y="0" width="${panelW}" height="1080" fill="currentColor" opacity="0.07" />
    <circle cx="80" cy="980" r="220" fill="currentColor" opacity="0.08" />
    <circle cx="80" cy="980" r="128" fill="none" stroke="currentColor" stroke-width="2" opacity="0.18" />
    <circle cx="720" cy="80" r="110" fill="currentColor" opacity="0.06" />
    <rect x="${stripX}" y="0" width="${stripW}" height="1080" fill="currentColor" />
    <rect x="${cardX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="#FFFFFF" filter="url(#hrtCardShadow)" />
    <rect x="${cardX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="currentColor" opacity="0.035" />
    <rect x="${dashX}" y="${dashY}" width="${dashW}" height="${dashH}" rx="${dashH / 2}" fill="currentColor" />
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

function textEl({ slotId, prev, x, y, w, h, text, fontSize, fontWeight, color, lineHeight, maxLines, sx, sy, scale, role, verticalAlign }) {
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
      verticalAlign: verticalAlign || 'flex-start',
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
        svg: buildHeadlineRightTextChromeSvg(),
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
      maxLines: 5,
      role: 'heading',
      verticalAlign: 'flex-start',
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
      maxLines: 8,
      role: 'body',
      sx, sy, scale,
    }),
  ]
}

function layoutHeadlineRightText(docOrElements, schema = {}, palette = {}, canvas = {}) {
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
    headline: textOf(headlineEl, HEADLINE_RIGHT_TEXT_DEFAULTS.HEADLINE),
    body: textOf(bodyEl, HEADLINE_RIGHT_TEXT_DEFAULTS.BODY),
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev: { IMAGE_CARD_BG: cardEl, HEADLINE: headlineEl, BODY: bodyEl },
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildHeadlineRightTextCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    headline: String(bySlot.HEADLINE || bySlot.HEADING || content.heading || content.title || HEADLINE_RIGHT_TEXT_DEFAULTS.HEADLINE).trim(),
    body: String(bySlot.BODY || content.body || HEADLINE_RIGHT_TEXT_DEFAULTS.BODY).trim(),
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isHeadlineRightTextLayout,
  layoutHeadlineRightText,
  buildHeadlineRightTextChromeSvg,
  HEADLINE_RIGHT_TEXT_DEFAULTS,
};
