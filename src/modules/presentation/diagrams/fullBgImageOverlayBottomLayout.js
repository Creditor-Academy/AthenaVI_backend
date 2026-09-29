/**
 * Full Bg Image Overlay Bottom
 * Layout ID: full_bg_image_overlay_bottom_v1
 *
 * Full-bleed photo with a cinematic bottom wash. Title, subtitle, and body
 * sit on the lower band. Distinct from Full Bg Image Overlay (left stack)
 * and the Side twin.
 */

function isFullBgImageOverlayBottomLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || schema?.variant || '').toLowerCase()
  return id === 'full_bg_image_overlay_bottom_v1' || id === 'full_bg_image_overlay_bottom'
}

const FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS = {
  MAIN_TITLE: 'Presentation title',
  SUBTITLE: 'Supporting line or tagline',
  BODY: 'A short paragraph that sits on the photo without crowding the headline.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  barX: 896,
  barY: 548,
  barW: 128,
  barH: 6,
  titleX: 200,
  titleY: 580,
  titleW: 1520,
  titleH: 180,
  subX: 260,
  subY: 776,
  subW: 1400,
  subH: 64,
  bodyX: 300,
  bodyY: 852,
  bodyW: 1320,
  bodyH: 160,
}

function buildFullBgImageOverlayBottomChromeSvg() {
  const { barX, barY, barW, barH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="fbiobWash" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="currentColor" stop-opacity="0.04" />
        <stop offset="42%" stop-color="currentColor" stop-opacity="0.12" />
        <stop offset="100%" stop-color="currentColor" stop-opacity="0.78" />
      </linearGradient>
      <linearGradient id="fbiobBottom" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#020617" stop-opacity="0" />
        <stop offset="48%" stop-color="#020617" stop-opacity="0.12" />
        <stop offset="100%" stop-color="#020617" stop-opacity="0.72" />
      </linearGradient>
    </defs>
    <rect width="1920" height="1080" fill="url(#fbiobWash)" />
    <rect width="1920" height="1080" fill="url(#fbiobBottom)" />
    <rect x="${barX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="#FFFFFF" fill-opacity="0.95" />
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
      align: 'center',
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
  }
}

function buildElements({ canvasW, canvasH, title, subtitle, body, imageUrl, accent, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  return [
    {
      id: prev.BACKGROUND_IMAGE?.id || 'slot-BACKGROUND_IMAGE',
      slotId: 'BACKGROUND_IMAGE',
      type: 'image',
      role: 'background',
      layer: 0,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        ...(imageUrl ? { url: imageUrl, src: imageUrl } : {}),
        fit: 'cover',
        alt: '',
      },
    },
    {
      id: prev.OVERLAY_SCRIM?.id || 'slot-OVERLAY_SCRIM',
      slotId: 'OVERLAY_SCRIM',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildFullBgImageOverlayBottomChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    textEl({
      slotId: 'MAIN_TITLE',
      prev: prev.MAIN_TITLE,
      x: GEOM.titleX,
      y: GEOM.titleY,
      w: GEOM.titleW,
      h: GEOM.titleH,
      text: title,
      fontSize: 40,
      fontWeight: 800,
      color: '#FFFFFF',
      lineHeight: 1.12,
      maxLines: 2,
      role: 'heading',
      sx, sy, scale,
    }),
    textEl({
      slotId: 'SUBTITLE',
      prev: prev.SUBTITLE,
      x: GEOM.subX,
      y: GEOM.subY,
      w: GEOM.subW,
      h: GEOM.subH,
      text: subtitle,
      fontSize: 18,
      fontWeight: 600,
      color: 'rgba(255,255,255,0.88)',
      lineHeight: 1.3,
      maxLines: 1,
      role: 'subheading',
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
      fontSize: 16,
      fontWeight: 400,
      color: 'rgba(255,255,255,0.78)',
      lineHeight: 1.45,
      maxLines: 3,
      role: 'body',
      sx, sy, scale,
    }),
  ]
}

function layoutFullBgImageOverlayBottom(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent } = paletteColors(palette)
  const titleEl = findEl(elements, ['MAIN_TITLE', 'HEADING', 'HEADLINE', 'TITLE'])
  const subEl = findEl(elements, ['SUBTITLE'])
  const bodyEl = findEl(elements, ['BODY'])
  const imageEl = findEl(elements, ['BACKGROUND_IMAGE', 'HERO_IMAGE', 'IMAGE'])
  const overlayEl = findEl(elements, ['OVERLAY_SCRIM', 'IMAGE_CARD_BG'])
  const out = buildElements({
    canvasW,
    canvasH,
    title: textOf(titleEl, FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS.MAIN_TITLE),
    subtitle: textOf(subEl, FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS.SUBTITLE),
    body: textOf(bodyEl, FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS.BODY),
    imageUrl: imageEl?.content?.url || imageEl?.content?.src || null,
    accent: resolveStoredColor(overlayEl, accent),
    prev: {
      BACKGROUND_IMAGE: imageEl,
      OVERLAY_SCRIM: overlayEl,
      MAIN_TITLE: titleEl,
      SUBTITLE: subEl,
      BODY: bodyEl,
    },
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildFullBgImageOverlayBottomCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    title: String(bySlot.MAIN_TITLE || bySlot.HEADING || content.heading || content.title || FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS.MAIN_TITLE).trim(),
    subtitle: String(bySlot.SUBTITLE || content.subtitle || FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS.SUBTITLE).trim(),
    body: String(bySlot.BODY || content.body || FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS.BODY).trim(),
    imageUrl:
      bySlot.BACKGROUND_IMAGE__url ||
      bySlot.BACKGROUND_IMAGE_url ||
      bySlot.HERO_IMAGE__url ||
      content.imageUrl ||
      content.imageRef?.url ||
      null,
    accent,
  })
}

module.exports = {
  isFullBgImageOverlayBottomLayout,
  layoutFullBgImageOverlayBottom,
  buildFullBgImageOverlayBottomChromeSvg,
  FULL_BG_IMAGE_OVERLAY_BOTTOM_DEFAULTS,
};
