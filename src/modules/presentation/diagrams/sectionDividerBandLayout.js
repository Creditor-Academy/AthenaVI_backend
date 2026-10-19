/**
 * Section Divider Band
 * Layout ID: section_divider_band_v1
 *
 * Horizontal chapter band with a centered heading.
 * Twin `section_divider_band_full_v1` has its own full-bleed engine.
 */

function isSectionDividerBandLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  if (id.includes('_full')) return false
  return id === 'section_divider_band_v1' || id === 'section_divider_band'
}

const SECTION_DIVIDER_BAND_DEFAULTS = {
  HEADING: 'Section break',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  bandY: 390,
  bandH: 300,
  headX: 160,
  headY: 430,
  headW: 1600,
  headH: 220,
}

function buildSectionDividerBandChromeSvg() {
  const { bandY, bandH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <rect width="1920" height="1080" fill="currentColor" opacity="0.04" />
    <circle cx="1760" cy="140" r="160" fill="currentColor" opacity="0.07" />
    <circle cx="160" cy="940" r="140" fill="currentColor" opacity="0.06" />
    <rect x="0" y="${bandY}" width="1920" height="${bandH}" fill="currentColor" />
    <rect x="0" y="${bandY}" width="1920" height="8" fill="#FFFFFF" opacity="0.18" />
    <rect x="0" y="${bandY + bandH - 8}" width="1920" height="8" fill="#000000" opacity="0.12" />
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

function paletteColors(palette) {
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  return {
    accent: pal.primary || pal.accent || '#6366F1',
  }
}

function buildElements({ canvasW, canvasH, heading, accent, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  return [
    {
      id: prev.BAND?.id || prev.IMAGE_CARD_BG?.id || 'slot-BAND',
      slotId: 'BAND',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildSectionDividerBandChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    {
      id: prev.HEADING?.id || 'slot-HEADING',
      slotId: 'HEADING',
      type: 'text',
      role: 'heading',
      layer: 10,
      placement: {
        x: Math.round(GEOM.headX * sx),
        y: Math.round(GEOM.headY * sy),
        width: Math.round(GEOM.headW * sx),
        height: Math.round(GEOM.headH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: heading,
        fontSize: Math.round(40 * scale),
        fontWeight: 800,
        color: '#FFFFFF',
        align: 'center',
        verticalAlign: 'center',
        lineHeight: 1.15,
        clipToSlot: true,
        maxLines: 2,
      },
    },
  ]
}

function layoutSectionDividerBand(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'HEADLINE', 'TITLE', 'MAIN_TITLE'])
  const bandEl = findEl(elements, ['BAND', 'IMAGE_CARD_BG'])
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, SECTION_DIVIDER_BAND_DEFAULTS.HEADING),
    accent: resolveStoredColor(bandEl, accent),
    prev: { BAND: bandEl, IMAGE_CARD_BG: bandEl, HEADING: headingEl },
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildSectionDividerBandCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || SECTION_DIVIDER_BAND_DEFAULTS.HEADING).trim(),
    accent,
  })
}

module.exports = {
  isSectionDividerBandLayout,
  layoutSectionDividerBand,
  buildSectionDividerBandCanvasElements,
  buildSectionDividerBandChromeSvg,
  SECTION_DIVIDER_BAND_DEFAULTS,
};
