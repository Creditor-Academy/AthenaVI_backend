/**
 * Contact Image Bottom
 * Layout ID: contact_image_bottom_v1
 *
 * Centered contact row on top, wide rounded photo below.
 * Left / right twins keep their own engines.
 */

function isContactImageBottomLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/left|right/i.test(id) && !/bottom/i.test(id)) return false
  return id === 'contact_image_bottom_v1' || id === 'contact_image_bottom'
}

const CONTACT_IMAGE_BOTTOM_DEFAULTS = {
  HEADING: 'Contact me',
  CONTACT_ADDRESS: '123 Main Street\nCity, State 12345',
  CONTACT_PHONE: '+1 (555) 123-4567',
  CONTACT_EMAIL: 'hello@example.com',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 72,
  imgY: 520,
  imgW: 1776,
  imgH: 492,
  radius: 36,
  pad: 16,
  headingX: 200,
  headingY: 48,
  headingW: 1520,
  headingH: 78,
  barW: 88,
  barH: 6,
  colXs: [160, 700, 1240],
  colW: 520,
  iconY: 168,
  iconSize: 64,
  labelY: 248,
  valueY: 282,
  addressH: 132,
  valueH: 64,
}

function iconPaths(cx, cy) {
  return {
    pin: `M ${cx} ${cy - 13} c -9 0 -16 7 -16 16 c 0 13 16 26 16 26 s 16 -13 16 -26 c 0 -9 -7 -16 -16 -16 z M ${cx} ${cy + 1} a 5 5 0 1 1 0.01 0`,
    phone: `M ${cx - 11} ${cy - 7} h 7 l 4 5 h 11 v 15 h -22 z M ${cx - 3} ${cy - 13} h 7`,
    mail: `M ${cx - 15} ${cy - 9} h 30 v 20 h -30 z M ${cx - 15} ${cy - 9} l 15 11 l 15 -11`,
  }
}

function buildContactImageBottomChromeSvg() {
  const { imgX, imgY, imgW, imgH, radius, pad, colXs, colW, iconY, iconSize } = GEOM
  const frameX = imgX - pad
  const frameY = imgY - pad
  const frameW = imgW + pad * 2
  const frameH = imgH + pad * 2
  const frameR = radius + 8
  const icons = ['pin', 'phone', 'mail']
  const labels = ['Address', 'Phone', 'Email']
  const colMarkup = colXs.map((x, i) => {
    const cx = x + colW / 2
    const cy = iconY + iconSize / 2
    const d = iconPaths(cx, cy)[icons[i]]
    return `<circle cx="${cx}" cy="${cy}" r="${iconSize / 2}" fill="currentColor" opacity="0.12"/>
      <circle cx="${cx}" cy="${cy}" r="${iconSize / 2}" fill="none" stroke="currentColor" stroke-width="2.2" opacity="0.35"/>
      <path d="${d}" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      <text x="${cx}" y="${GEOM.labelY + 18}" text-anchor="middle" fill="#64748B" stroke="none" font-size="15" font-weight="700" font-family="system-ui,sans-serif">${labels[i]}</text>`
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="cibShadow" x="-6%" y="-8%" width="112%" height="120%">
        <feDropShadow dx="0" dy="14" stdDeviation="18" flood-color="#94A3B8" flood-opacity="0.2" />
      </filter>
    </defs>
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    <ellipse cx="120" cy="40" rx="240" ry="120" fill="currentColor" opacity="0.07"/>
    <ellipse cx="1800" cy="60" rx="220" ry="110" fill="currentColor" opacity="0.07"/>
    ${colMarkup}
    <rect x="${frameX}" y="${frameY}" width="${frameW}" height="${frameH}" rx="${frameR}" fill="#FFFFFF" filter="url(#cibShadow)"/>
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

function textEl({ id, slotId, role, x, y, w, h, text, fontSize, fontWeight, color, maxLines, lineHeight = 1.3 }) {
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

function buildElements({ canvasW, canvasH, heading, address, phone, email, imageUrl, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = CONTACT_IMAGE_BOTTOM_DEFAULTS
  const fields = [
    { slotId: 'CONTACT_ADDRESS', text: address || d.CONTACT_ADDRESS, prev: prev.CONTACT_ADDRESS, h: GEOM.addressH, maxLines: 3, fontSize: 20 },
    { slotId: 'CONTACT_PHONE', text: phone || d.CONTACT_PHONE, prev: prev.CONTACT_PHONE, h: GEOM.valueH, maxLines: 1, fontSize: 22 },
    { slotId: 'CONTACT_EMAIL', text: email || d.CONTACT_EMAIL, prev: prev.CONTACT_EMAIL, h: GEOM.valueH, maxLines: 1, fontSize: 22 },
  ]

  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 3,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildContactImageBottomChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    {
      id: prev.CONTACT_IMAGE?.id || 'slot-CONTACT_IMAGE',
      slotId: 'CONTACT_IMAGE',
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
        borderRadius: Math.round(GEOM.radius * scale),
        alt: '',
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
      fontSize: Math.round(48 * scale),
      fontWeight: 800,
      color: textColor,
      maxLines: 1,
    }),
    ...fields.map((field, i) => textEl({
      id: field.prev?.id || `slot-${field.slotId}`,
      slotId: field.slotId,
      role: 'body',
      x: Math.round(GEOM.colXs[i] * sx),
      y: Math.round(GEOM.valueY * sy),
      w: Math.round(GEOM.colW * sx),
      h: Math.round(field.h * sy),
      text: field.text,
      fontSize: Math.round(field.fontSize * scale),
      fontWeight: 600,
      color: textColor,
      maxLines: field.maxLines,
    })),
  ]
}

function layoutContactImageBottom(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || '#6366F1'
  const textColor = pal.text || '#0F172A'
  const mutedColor = pal.muted || '#64748B'
  const prev = {
    IMAGE_CARD_BG: findEl(elements, ['IMAGE_CARD_BG']),
    CONTACT_IMAGE: findEl(elements, ['CONTACT_IMAGE', 'HERO_IMAGE', 'IMAGE']),
    HEADING: findEl(elements, ['HEADING']),
    CONTACT_ADDRESS: findEl(elements, ['CONTACT_ADDRESS']),
    CONTACT_PHONE: findEl(elements, ['CONTACT_PHONE']),
    CONTACT_EMAIL: findEl(elements, ['CONTACT_EMAIL']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, CONTACT_IMAGE_BOTTOM_DEFAULTS.HEADING),
    address: textOf(prev.CONTACT_ADDRESS, CONTACT_IMAGE_BOTTOM_DEFAULTS.CONTACT_ADDRESS),
    phone: textOf(prev.CONTACT_PHONE, CONTACT_IMAGE_BOTTOM_DEFAULTS.CONTACT_PHONE),
    email: textOf(prev.CONTACT_EMAIL, CONTACT_IMAGE_BOTTOM_DEFAULTS.CONTACT_EMAIL),
    imageUrl: prev.CONTACT_IMAGE?.content?.url || prev.CONTACT_IMAGE?.content?.src || null,
    accent: resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildContactImageBottomCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = CONTACT_IMAGE_BOTTOM_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
    address: String(by.CONTACT_ADDRESS || content.address || d.CONTACT_ADDRESS).trim(),
    phone: String(by.CONTACT_PHONE || content.phone || d.CONTACT_PHONE).trim(),
    email: String(by.CONTACT_EMAIL || content.email || d.CONTACT_EMAIL).trim(),
    imageUrl:
      by.CONTACT_IMAGE__url ||
      by.CONTACT_IMAGE_url ||
      content.imageUrl ||
      content.imageRef?.url ||
      null,
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

function contactImageBottomPreviewSvg() {
  const chrome = buildContactImageBottomChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { headingX, headingY, headingH, headingW, colXs, colW, valueY, imgX, imgY, imgW, imgH, radius } = GEOM
  const values = [
    ['123 Main Street', 'City, State 12345'],
    ['+1 (555) 123-4567'],
    ['hello@example.com'],
  ]
  const valueMarkup = values.map((lines, i) => {
    const x = colXs[i] + colW / 2
    return lines.map((line, li) =>
      `<text x="${x}" y="${valueY + 26 + li * 26}" text-anchor="middle" fill="#0F172A" font-size="20" font-weight="600" font-family="system-ui,sans-serif">${xmlText(line)}</text>`
    ).join('')
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <defs>
      <clipPath id="cibClip"><rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" rx="${radius}"/></clipPath>
      <linearGradient id="cibSky" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#7EC8E8"/>
        <stop offset="55%" stop-color="#B7D4E8"/>
        <stop offset="100%" stop-color="#D0E3EF"/>
      </linearGradient>
      <linearGradient id="cibHill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#8FBF8E"/>
        <stop offset="100%" stop-color="#5E945D"/>
      </linearGradient>
    </defs>
    ${chrome}
    <text x="${headingX + headingW / 2}" y="${headingY + headingH * 0.72}" text-anchor="middle" fill="#0F172A" font-size="48" font-weight="800" font-family="system-ui,sans-serif">Contact me</text>
    ${valueMarkup}
    <g clip-path="url(#cibClip)">
      <rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" fill="url(#cibSky)"/>
      <ellipse cx="${imgX + 280}" cy="${imgY + 90}" rx="120" ry="44" fill="#FFFFFF" opacity="0.95"/>
      <ellipse cx="${imgX + 400}" cy="${imgY + 90}" rx="80" ry="32" fill="#FFFFFF" opacity="0.95"/>
      <path d="M${imgX} ${imgY + 220} C${imgX + 360} ${imgY + 140} ${imgX + 720} ${imgY + 260} ${imgX + 1080} ${imgY + 180} C${imgX + 1400} ${imgY + 120} ${imgX + 1600} ${imgY + 240} ${imgX + imgW} ${imgY + 160} L${imgX + imgW} ${imgY + imgH} L${imgX} ${imgY + imgH} Z" fill="url(#cibHill)"/>
    </g>
  </svg>`
}


module.exports = {
  isContactImageBottomLayout,
  CONTACT_IMAGE_BOTTOM_DEFAULTS,
  buildContactImageBottomChromeSvg,
  layoutContactImageBottom,
  buildContactImageBottomCanvasElements,
  contactImageBottomPreviewSvg,
};
