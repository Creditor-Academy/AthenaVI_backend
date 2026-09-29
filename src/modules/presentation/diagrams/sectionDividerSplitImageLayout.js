/**
 * Section Divider Split Image
 * Layout ID: section_divider_split_image_v1
 *
 * Chapter opener: heading + body on a tinted left panel, full-height photo on the right.
 * Distinct from Section Divider Split (no image) and Split Diagonal (number + cream panel).
 */

function isSectionDividerSplitImageLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'section_divider_split_image_v1' || id === 'section_divider_split_image'
}

const SECTION_DIVIDER_SPLIT_IMAGE_DEFAULTS = {
  HEADING: 'Next section',
  BODY: 'What this chapter covers, why it matters now, and the decisions it is here to unlock.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  panelW: 960,
  stripX: 952,
  stripW: 8,
  dashX: 120,
  dashY: 268,
  dashW: 64,
  dashH: 6,
  headX: 120,
  headY: 300,
  headW: 740,
  headH: 220,
  bodyX: 120,
  bodyY: 560,
  bodyW: 740,
  bodyH: 360,
  imgX: 960,
  imgY: 0,
  imgW: 960,
  imgH: 1080,
}

function buildSectionDividerSplitImageChromeSvg() {
  const { panelW, stripX, stripW, dashX, dashY, dashW, dashH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${panelW}" height="1080" fill="currentColor" opacity="0.07" />
    <circle cx="90" cy="980" r="210" fill="currentColor" opacity="0.08" />
    <circle cx="90" cy="980" r="118" fill="none" stroke="currentColor" stroke-width="2" opacity="0.18" />
    <circle cx="820" cy="90" r="100" fill="currentColor" opacity="0.06" />
    <rect x="${stripX}" y="0" width="${stripW}" height="1080" fill="currentColor" />
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

function buildElements({ canvasW, canvasH, heading, body, imageUrl, accent, textColor, mutedColor, prev = {} }) {
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
        svg: buildSectionDividerSplitImageChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    {
      id: prev.HERO_IMAGE?.id || 'slot-HERO_IMAGE',
      slotId: 'HERO_IMAGE',
      type: 'image',
      role: 'image',
      layer: 6,
      placement: {
        x: Math.round(GEOM.imgX * sx),
        y: Math.round(GEOM.imgY * sy),
        width: Math.round(GEOM.imgW * sx),
        height: Math.round(GEOM.imgH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...(imageUrl ? { url: imageUrl, src: imageUrl } : {}),
        fit: 'cover',
        borderRadius: 0,
        alt: '',
      },
    },
    textEl({
      slotId: 'HEADING',
      prev: prev.HEADING,
      x: GEOM.headX,
      y: GEOM.headY,
      w: GEOM.headW,
      h: GEOM.headH,
      text: heading,
      fontSize: 40,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 3,
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
      fontSize: 18,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.5,
      maxLines: 6,
      role: 'body',
      sx, sy, scale,
    }),
  ]
}

function layoutSectionDividerSplitImage(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'HEADLINE', 'TITLE'])
  const bodyEl = findEl(elements, ['BODY', 'SUBTITLE'])
  const imageEl = findEl(elements, ['HERO_IMAGE', 'IMAGE'])
  const cardEl = findEl(elements, ['IMAGE_CARD_BG', 'CHROME'])
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, SECTION_DIVIDER_SPLIT_IMAGE_DEFAULTS.HEADING),
    body: textOf(bodyEl, SECTION_DIVIDER_SPLIT_IMAGE_DEFAULTS.BODY),
    imageUrl: imageEl?.content?.url || imageEl?.content?.src || null,
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev: { IMAGE_CARD_BG: cardEl, HERO_IMAGE: imageEl, HEADING: headingEl, BODY: bodyEl },
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildSectionDividerSplitImageCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || SECTION_DIVIDER_SPLIT_IMAGE_DEFAULTS.HEADING).trim(),
    body: String(bySlot.BODY || content.body || SECTION_DIVIDER_SPLIT_IMAGE_DEFAULTS.BODY).trim(),
    imageUrl:
      bySlot.HERO_IMAGE__url ||
      bySlot.HERO_IMAGE_url ||
      content.imageUrl ||
      content.imageRef?.url ||
      null,
    accent,
    textColor,
    mutedColor,
  })
}

module.exports = {
  isSectionDividerSplitImageLayout,
  layoutSectionDividerSplitImage,
  buildSectionDividerSplitImageChromeSvg,
  SECTION_DIVIDER_SPLIT_IMAGE_DEFAULTS,
};
