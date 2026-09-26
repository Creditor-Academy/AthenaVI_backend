/**
 * Overlay Image CTA
 * Layout ID: overlay_image_cta_v1
 *
 * Full-bleed photo, bottom wash, centered Thank you / body / Get in touch pill.
 * Para Image CTA, Image Para CTA, and full-bg overlay twins keep their own look.
 */

function isOverlayImageCtaLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/para_image|image_para|full_bg|_bottom|_side/i.test(id)) return false
  return id === 'overlay_image_cta_v1' || id === 'overlay_image_cta'
}

const OVERLAY_IMAGE_CTA_DEFAULTS = {
  HEADING: 'Thank you',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  CTA: 'Get in touch',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headingX: 160,
  headingY: 260,
  headingW: 1600,
  headingH: 140,
  bodyX: 220,
  bodyY: 412,
  bodyW: 1480,
  bodyH: 220,
  pillX: 690,
  pillY: 700,
  pillW: 540,
  pillH: 88,
}

function buildOverlayImageCtaChromeSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="oictaWash" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="currentColor" stop-opacity="0.22"/>
        <stop offset="45%" stop-color="#020617" stop-opacity="0.28"/>
        <stop offset="100%" stop-color="#020617" stop-opacity="0.78"/>
      </linearGradient>
    </defs>
    <rect width="1920" height="1080" fill="url(#oictaWash)"/>
  </svg>`
}

function buildOverlayImageCtaPillSvg() {
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

function buildElements({ canvasW, canvasH, heading, body, cta, imageUrl, accent, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = OVERLAY_IMAGE_CTA_DEFAULTS
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
        svg: buildOverlayImageCtaChromeSvg(),
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
        svg: buildOverlayImageCtaPillSvg(),
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
      layer: 12,
      placement: {
        x: Math.round(GEOM.headingX * sx),
        y: Math.round(GEOM.headingY * sy),
        width: Math.round(GEOM.headingW * sx),
        height: Math.round(GEOM.headingH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: heading || d.HEADING,
        fontSize: Math.round(72 * scale),
        fontWeight: 800,
        color: '#FFFFFF',
        align: 'center',
        verticalAlign: 'middle',
        lineHeight: 1.15,
        clipToSlot: true,
        maxLines: 2,
      },
    },
    {
      id: prev.BODY?.id || 'slot-BODY',
      slotId: 'BODY',
      type: 'text',
      role: 'body',
      layer: 12,
      placement: {
        x: Math.round(GEOM.bodyX * sx),
        y: Math.round(GEOM.bodyY * sy),
        width: Math.round(GEOM.bodyW * sx),
        height: Math.round(GEOM.bodyH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: body || d.BODY,
        fontSize: Math.round(22 * scale),
        fontWeight: 500,
        color: 'rgba(255,255,255,0.82)',
        align: 'center',
        verticalAlign: 'flex-start',
        lineHeight: 1.45,
        clipToSlot: true,
        maxLines: 3,
      },
    },
    {
      id: prev.CTA?.id || 'slot-CTA',
      slotId: 'CTA',
      type: 'text',
      role: 'cta',
      layer: 12,
      placement: {
        x: Math.round(GEOM.pillX * sx),
        y: Math.round(GEOM.pillY * sy),
        width: Math.round(GEOM.pillW * sx),
        height: Math.round(GEOM.pillH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: cta || d.CTA,
        fontSize: Math.round(24 * scale),
        fontWeight: 700,
        color: '#FFFFFF',
        align: 'center',
        verticalAlign: 'middle',
        lineHeight: 1.2,
        clipToSlot: true,
        maxLines: 1,
      },
    },
  ]
}

function layoutOverlayImageCta(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || '#6366F1'
  const prev = {
    BACKGROUND_IMAGE: findEl(elements, ['BACKGROUND_IMAGE', 'HERO_IMAGE', 'IMAGE']),
    OVERLAY_SCRIM: findEl(elements, ['OVERLAY_SCRIM', 'IMAGE_CARD_BG']),
    CTA_BG: findEl(elements, ['CTA_BG']),
    HEADING: findEl(elements, ['HEADING']),
    BODY: findEl(elements, ['BODY']),
    CTA: findEl(elements, ['CTA']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, OVERLAY_IMAGE_CTA_DEFAULTS.HEADING),
    body: textOf(prev.BODY, OVERLAY_IMAGE_CTA_DEFAULTS.BODY),
    cta: textOf(prev.CTA, OVERLAY_IMAGE_CTA_DEFAULTS.CTA),
    imageUrl: prev.BACKGROUND_IMAGE?.content?.url || prev.BACKGROUND_IMAGE?.content?.src || null,
    accent: resolveStoredColor(prev.CTA_BG, accent) || resolveStoredColor(prev.OVERLAY_SCRIM, accent),
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildOverlayImageCtaCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = OVERLAY_IMAGE_CTA_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
    body: String(by.BODY || content.body || d.BODY).trim(),
    cta: String(by.CTA || content.cta || d.CTA).trim(),
    imageUrl:
      by.BACKGROUND_IMAGE__url ||
      by.BACKGROUND_IMAGE_url ||
      by.HERO_IMAGE__url ||
      content.imageUrl ||
      content.imageRef?.url ||
      null,
    accent: pal.primary || pal.accent || '#6366F1',
  })
}

function xmlText(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function overlayImageCtaPreviewSvg() {
  const chrome = buildOverlayImageCtaChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const d = OVERLAY_IMAGE_CTA_DEFAULTS
  const { headingX, headingY, headingW, headingH, bodyX, bodyY, bodyW, pillX, pillY, pillW, pillH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <defs>
      <linearGradient id="oictaSky" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#7EC8E8"/>
        <stop offset="55%" stop-color="#B7D4E8"/>
        <stop offset="100%" stop-color="#D0E3EF"/>
      </linearGradient>
      <linearGradient id="oictaHill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#8FBF8E"/>
        <stop offset="100%" stop-color="#5E945D"/>
      </linearGradient>
    </defs>
    <rect width="1920" height="1080" fill="url(#oictaSky)"/>
    <ellipse cx="420" cy="220" rx="90" ry="42" fill="#FFFFFF" opacity="0.95"/>
    <ellipse cx="500" cy="220" rx="64" ry="32" fill="#FFFFFF" opacity="0.95"/>
    <ellipse cx="1280" cy="180" rx="110" ry="48" fill="#FFFFFF" opacity="0.95"/>
    <path d="M0 620 C420 480 780 580 1100 520 C1420 460 1680 560 1920 500 L1920 1080 L0 1080 Z" fill="url(#oictaHill)"/>
    ${chrome}
    <text x="${headingX + headingW / 2}" y="${headingY + headingH * 0.7}" text-anchor="middle" fill="#FFFFFF" font-size="72" font-weight="800" font-family="system-ui,sans-serif">${xmlText(d.HEADING)}</text>
    <text x="${bodyX + bodyW / 2}" y="${bodyY + 40}" text-anchor="middle" fill="rgba(255,255,255,0.85)" font-size="22" font-weight="500" font-family="system-ui,sans-serif">Supporting paragraph with three to four lines of</text>
    <text x="${bodyX + bodyW / 2}" y="${bodyY + 76}" text-anchor="middle" fill="rgba(255,255,255,0.85)" font-size="22" font-weight="500" font-family="system-ui,sans-serif">scannable copy that explains the key idea without</text>
    <text x="${bodyX + bodyW / 2}" y="${bodyY + 112}" text-anchor="middle" fill="rgba(255,255,255,0.85)" font-size="22" font-weight="500" font-family="system-ui,sans-serif">overwhelming the slide.</text>
    <rect x="${pillX}" y="${pillY}" width="${pillW}" height="${pillH}" rx="${pillH / 2}" fill="#6366F1"/>
    <text x="${pillX + pillW / 2}" y="${pillY + pillH * 0.64}" text-anchor="middle" fill="#FFFFFF" font-size="24" font-weight="700" font-family="system-ui,sans-serif">${xmlText(d.CTA)}</text>
  </svg>`
}

module.exports = {
  isOverlayImageCtaLayout,
  OVERLAY_IMAGE_CTA_DEFAULTS,
  buildOverlayImageCtaChromeSvg,
  buildOverlayImageCtaPillSvg,
  layoutOverlayImageCta,
  buildOverlayImageCtaCanvasElements,
  overlayImageCtaPreviewSvg,
};
