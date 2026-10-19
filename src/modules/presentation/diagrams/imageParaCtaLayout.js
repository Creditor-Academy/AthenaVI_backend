/**
 * Image Para CTA
 * Layout ID: image_para_cta_v1
 *
 * Tall rounded photo on the left, body + Book a demo pill on the right.
 * Para Image CTA and Overlay Image CTA keep their own look.
 */

function isImageParaCtaLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/para_image|overlay/i.test(id)) return false
  return id === 'image_para_cta_v1' || id === 'image_para_cta'
}

const IMAGE_PARA_CTA_DEFAULTS = {
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  CTA: 'Book a demo',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 80,
  imgY: 88,
  imgW: 832,
  imgH: 904,
  radius: 36,
  pad: 14,
  barX: 1008,
  barY: 168,
  barW: 72,
  barH: 6,
  bodyX: 1008,
  bodyY: 204,
  bodyW: 820,
  bodyH: 360,
  pillX: 1008,
  pillY: 640,
  pillW: 440,
  pillH: 80,
}

function buildImageParaCtaChromeSvg() {
  const { barX, barY, barW, barH, imgX, imgY, imgW, imgH, radius, pad } = GEOM
  const frameX = imgX - pad
  const frameY = imgY - pad
  const frameW = imgW + pad * 2
  const frameH = imgH + pad * 2
  const frameR = radius + 8
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="ipctaShadow" x="-10%" y="-8%" width="122%" height="124%">
        <feDropShadow dx="0" dy="16" stdDeviation="20" flood-color="#94A3B8" flood-opacity="0.2" />
      </filter>
    </defs>
    <ellipse cx="1760" cy="80" rx="220" ry="120" fill="currentColor" opacity="0.08"/>
    <rect x="${barX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor"/>
    <rect x="${frameX}" y="${frameY}" width="${frameW}" height="${frameH}" rx="${frameR}" fill="#FFFFFF" filter="url(#ipctaShadow)"/>
  </svg>`
}

function buildImageParaCtaPillSvg() {
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

function buildElements({ canvasW, canvasH, body, cta, imageUrl, accent, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = IMAGE_PARA_CTA_DEFAULTS
  const radius = Math.round(GEOM.radius * scale)
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildImageParaCtaChromeSvg(),
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
        borderRadius: radius,
        alt: '',
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
        svg: buildImageParaCtaPillSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
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
        fontSize: Math.round(28 * scale),
        fontWeight: 500,
        color: mutedColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.4,
        clipToSlot: true,
        maxLines: 4,
      },
    },
    {
      id: prev.CTA?.id || 'slot-CTA',
      slotId: 'CTA',
      role: 'cta',
      type: 'text',
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
        fontSize: Math.round(22 * scale),
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

function layoutImageParaCta(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || '#6366F1'
  const mutedColor = pal.muted || '#64748B'
  const prev = {
    IMAGE_CARD_BG: findEl(elements, ['IMAGE_CARD_BG']),
    HERO_IMAGE: findEl(elements, ['HERO_IMAGE', 'IMAGE']),
    CTA_BG: findEl(elements, ['CTA_BG']),
    BODY: findEl(elements, ['BODY', 'PARAGRAPH']),
    CTA: findEl(elements, ['CTA']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    body: textOf(prev.BODY, IMAGE_PARA_CTA_DEFAULTS.BODY),
    cta: textOf(prev.CTA, IMAGE_PARA_CTA_DEFAULTS.CTA),
    imageUrl: prev.HERO_IMAGE?.content?.url || prev.HERO_IMAGE?.content?.src || null,
    accent: resolveStoredColor(prev.CTA_BG, accent) || resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildImageParaCtaCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = IMAGE_PARA_CTA_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    body: String(by.BODY || content.body || d.BODY).trim(),
    cta: String(by.CTA || content.cta || d.CTA).trim(),
    imageUrl: by.HERO_IMAGE__url || by.HERO_IMAGE_url || content.imageUrl || content.imageRef?.url || null,
    accent: pal.primary || pal.accent || '#6366F1',
    mutedColor: pal.muted || '#64748B',
  })
}

function xmlText(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function imageParaCtaPreviewSvg() {
  const chrome = buildImageParaCtaChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const d = IMAGE_PARA_CTA_DEFAULTS
  const { bodyX, bodyY, pillX, pillY, pillW, pillH, imgX, imgY, imgW, imgH, radius } = GEOM
  const lines = [
    'Supporting paragraph with three to four',
    'lines of scannable copy that explains',
    'the key idea without overwhelming',
    'the slide.',
  ]
  const bodyMarkup = lines
    .map((line, i) => `<text x="${bodyX}" y="${bodyY + 40 + i * 42}" fill="#64748B" font-size="28" font-weight="500" font-family="system-ui,sans-serif">${xmlText(line)}</text>`)
    .join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    <defs>
      <clipPath id="ipctaClip"><rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" rx="${radius}"/></clipPath>
      <linearGradient id="ipctaSky" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#7EC8E8"/>
        <stop offset="55%" stop-color="#B7D4E8"/>
        <stop offset="100%" stop-color="#D0E3EF"/>
      </linearGradient>
      <linearGradient id="ipctaHill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#8FBF8E"/>
        <stop offset="100%" stop-color="#5E945D"/>
      </linearGradient>
    </defs>
    ${chrome}
    <g clip-path="url(#ipctaClip)">
      <rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" fill="url(#ipctaSky)"/>
      <ellipse cx="${imgX + 180}" cy="${imgY + 160}" rx="80" ry="38" fill="#FFFFFF" opacity="0.95"/>
      <ellipse cx="${imgX + 240}" cy="${imgY + 160}" rx="58" ry="30" fill="#FFFFFF" opacity="0.95"/>
      <ellipse cx="${imgX + 520}" cy="${imgY + 130}" rx="96" ry="42" fill="#FFFFFF" opacity="0.95"/>
      <path d="M${imgX} ${imgY + 520} C${imgX + 180} ${imgY + 400} ${imgX + 360} ${imgY + 480} ${imgX + 520} ${imgY + 450} C${imgX + 680} ${imgY + 420} ${imgX + 760} ${imgY + 500} ${imgX + imgW} ${imgY + 430} L${imgX + imgW} ${imgY + imgH} L${imgX} ${imgY + imgH} Z" fill="url(#ipctaHill)"/>
    </g>
    ${bodyMarkup}
    <rect x="${pillX}" y="${pillY}" width="${pillW}" height="${pillH}" rx="${pillH / 2}" fill="#6366F1"/>
    <text x="${pillX + pillW / 2}" y="${pillY + pillH * 0.64}" text-anchor="middle" fill="#FFFFFF" font-size="22" font-weight="700" font-family="system-ui,sans-serif">${xmlText(d.CTA)}</text>
  </svg>`
}

module.exports = {
  isImageParaCtaLayout,
  IMAGE_PARA_CTA_DEFAULTS,
  buildImageParaCtaChromeSvg,
  buildImageParaCtaPillSvg,
  layoutImageParaCta,
  buildImageParaCtaCanvasElements,
  imageParaCtaPreviewSvg,
};
