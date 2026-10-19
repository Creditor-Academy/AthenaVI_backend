/**
 * Contact Right Image
 * Layout ID: contact_right_image_v1
 *
 * Contact card on the left, full-bleed photo on the right.
 * Left / bottom twins keep their own engines.
 */

function isContactRightImageLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/left|bottom/i.test(id)) return false
  return id === 'contact_right_image_v1' || id === 'contact_right_image'
}

const CONTACT_RIGHT_IMAGE_DEFAULTS = {
  HEADING: 'Contact me',
  CONTACT_ADDRESS_LABEL: 'Address',
  CONTACT_ADDRESS: '123 Main Street\nCity, State 12345',
  CONTACT_PHONE_LABEL: 'Phone',
  CONTACT_PHONE: '+1 (555) 123-4567',
  CONTACT_EMAIL_LABEL: 'Email',
  CONTACT_EMAIL: 'hello@example.com',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 1000,
  imgW: 920,
  panelX: 64,
  panelY: 72,
  panelW: 1072,
  panelH: 936,
  panelR: 44,
  accentX: 128,
  accentY: 164,
  accentW: 8,
  accentH: 76,
  headingX: 168,
  headingY: 148,
  headingW: 860,
  headingH: 96,
  iconX: 168,
  iconSize: 72,
  rowYs: [312, 548, 756],
  labelX: 272,
  labelW: 760,
  labelH: 34,
  valueYOff: 36,
  valueH: 72,
  addressValueH: 148,
}

function iconPaths(cx, cy) {
  return {
    pin: `M ${cx} ${cy - 14} c -10 0 -18 8 -18 18 c 0 14 18 28 18 28 s 18 -14 18 -28 c 0 -10 -8 -18 -18 -18 z M ${cx} ${cy + 2} a 6 6 0 1 1 0.01 0`,
    phone: `M ${cx - 12} ${cy - 8} h 8 l 4 6 h 12 v 16 h -24 z M ${cx - 4} ${cy - 14} h 8`,
    mail: `M ${cx - 16} ${cy - 10} h 32 v 22 h -32 z M ${cx - 16} ${cy - 10} l 16 12 l 16 -12`,
  }
}

function buildContactRightImageChromeSvg() {
  const {
    panelX, panelY, panelW, panelH, panelR, accentX, accentY, accentW, accentH, iconX, iconSize, rowYs,
  } = GEOM
  const icons = ['pin', 'phone', 'mail']
  const iconMarkup = rowYs.map((y, i) => {
    const cx = iconX + iconSize / 2
    const cy = y + iconSize / 2
    const d = iconPaths(cx, cy)[icons[i]]
    return `<circle cx="${cx}" cy="${cy}" r="${iconSize / 2}" fill="currentColor" opacity="0.12"/>
      <circle cx="${cx}" cy="${cy}" r="${iconSize / 2}" fill="none" stroke="currentColor" stroke-width="2.2" opacity="0.35"/>
      <path d="${d}" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>`
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="criShadow" x="-8%" y="-6%" width="120%" height="120%">
        <feDropShadow dx="0" dy="18" stdDeviation="22" flood-color="#94A3B8" flood-opacity="0.22" />
      </filter>
    </defs>
    <ellipse cx="160" cy="80" rx="280" ry="160" fill="currentColor" opacity="0.08"/>
    <ellipse cx="240" cy="1040" rx="240" ry="140" fill="currentColor" opacity="0.06"/>
    <rect x="${panelX}" y="${panelY}" width="${panelW}" height="${panelH}" rx="${panelR}" fill="#FFFFFF" filter="url(#criShadow)"/>
    <rect x="${accentX}" y="${accentY}" width="${accentW}" height="${accentH}" rx="4" fill="currentColor"/>
    ${iconMarkup}
    <rect x="168" y="980" width="220" height="6" rx="3" fill="currentColor" opacity="0.85"/>
    <rect x="400" y="980" width="72" height="6" rx="3" fill="currentColor" opacity="0.35"/>
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

function textEl({ id, slotId, role, x, y, w, h, text, fontSize, fontWeight, color, maxLines, lineHeight = 1.25 }) {
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
      align: 'left',
      verticalAlign: 'flex-start',
      lineHeight,
      clipToSlot: true,
      maxLines,
    },
  }
}

function buildElements({
  canvasW, canvasH, heading, addressLabel, address, phoneLabel, phone, emailLabel, email,
  imageUrl, accent, textColor, mutedColor, prev = {},
}) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = CONTACT_RIGHT_IMAGE_DEFAULTS
  const rows = [
    { labelId: 'CONTACT_ADDRESS_LABEL', valueId: 'CONTACT_ADDRESS', label: addressLabel || d.CONTACT_ADDRESS_LABEL, value: address || d.CONTACT_ADDRESS, y: GEOM.rowYs[0], labelPrev: prev.CONTACT_ADDRESS_LABEL, valuePrev: prev.CONTACT_ADDRESS, valueLines: 3, valueH: GEOM.addressValueH, fontSize: 20 },
    { labelId: 'CONTACT_PHONE_LABEL', valueId: 'CONTACT_PHONE', label: phoneLabel || d.CONTACT_PHONE_LABEL, value: phone || d.CONTACT_PHONE, y: GEOM.rowYs[1], labelPrev: prev.CONTACT_PHONE_LABEL, valuePrev: prev.CONTACT_PHONE, valueLines: 1, valueH: GEOM.valueH, fontSize: 22 },
    { labelId: 'CONTACT_EMAIL_LABEL', valueId: 'CONTACT_EMAIL', label: emailLabel || d.CONTACT_EMAIL_LABEL, value: email || d.CONTACT_EMAIL, y: GEOM.rowYs[2], labelPrev: prev.CONTACT_EMAIL_LABEL, valuePrev: prev.CONTACT_EMAIL, valueLines: 1, valueH: GEOM.valueH, fontSize: 22 },
  ]

  const texts = rows.flatMap((row) => [
    textEl({
      id: row.labelPrev?.id || `slot-${row.labelId}`,
      slotId: row.labelId,
      role: 'caption',
      x: Math.round(GEOM.labelX * sx),
      y: Math.round(row.y * sy),
      w: Math.round(GEOM.labelW * sx),
      h: Math.round(GEOM.labelH * sy),
      text: row.label,
      fontSize: Math.round(15 * scale),
      fontWeight: 700,
      color: mutedColor,
      maxLines: 1,
    }),
    textEl({
      id: row.valuePrev?.id || `slot-${row.valueId}`,
      slotId: row.valueId,
      role: 'body',
      x: Math.round(GEOM.labelX * sx),
      y: Math.round((row.y + GEOM.valueYOff) * sy),
      w: Math.round(GEOM.labelW * sx),
      h: Math.round(row.valueH * sy),
      text: row.value,
      fontSize: Math.round(row.fontSize * scale),
      fontWeight: 600,
      color: textColor,
      maxLines: row.valueLines,
      lineHeight: 1.3,
    }),
  ])

  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 8,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildContactRightImageChromeSvg(),
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
      layer: 4,
      placement: {
        x: Math.round(GEOM.imgX * sx),
        y: 0,
        width: Math.round(GEOM.imgW * sx),
        height: canvasH,
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
      id: prev.HEADING?.id || 'slot-HEADING',
      slotId: 'HEADING',
      role: 'heading',
      x: Math.round(GEOM.headingX * sx),
      y: Math.round(GEOM.headingY * sy),
      w: Math.round(GEOM.headingW * sx),
      h: Math.round(GEOM.headingH * sy),
      text: heading || d.HEADING,
      fontSize: Math.round(52 * scale),
      fontWeight: 800,
      color: textColor,
      maxLines: 2,
    }),
    ...texts,
  ]
}

function layoutContactRightImage(docOrElements, schema = {}, palette = {}, canvas = {}) {
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
    CONTACT_ADDRESS_LABEL: findEl(elements, ['CONTACT_ADDRESS_LABEL']),
    CONTACT_ADDRESS: findEl(elements, ['CONTACT_ADDRESS']),
    CONTACT_PHONE_LABEL: findEl(elements, ['CONTACT_PHONE_LABEL']),
    CONTACT_PHONE: findEl(elements, ['CONTACT_PHONE']),
    CONTACT_EMAIL_LABEL: findEl(elements, ['CONTACT_EMAIL_LABEL']),
    CONTACT_EMAIL: findEl(elements, ['CONTACT_EMAIL']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(prev.HEADING, CONTACT_RIGHT_IMAGE_DEFAULTS.HEADING),
    addressLabel: textOf(prev.CONTACT_ADDRESS_LABEL, CONTACT_RIGHT_IMAGE_DEFAULTS.CONTACT_ADDRESS_LABEL),
    address: textOf(prev.CONTACT_ADDRESS, CONTACT_RIGHT_IMAGE_DEFAULTS.CONTACT_ADDRESS),
    phoneLabel: textOf(prev.CONTACT_PHONE_LABEL, CONTACT_RIGHT_IMAGE_DEFAULTS.CONTACT_PHONE_LABEL),
    phone: textOf(prev.CONTACT_PHONE, CONTACT_RIGHT_IMAGE_DEFAULTS.CONTACT_PHONE),
    emailLabel: textOf(prev.CONTACT_EMAIL_LABEL, CONTACT_RIGHT_IMAGE_DEFAULTS.CONTACT_EMAIL_LABEL),
    email: textOf(prev.CONTACT_EMAIL, CONTACT_RIGHT_IMAGE_DEFAULTS.CONTACT_EMAIL),
    imageUrl: prev.CONTACT_IMAGE?.content?.url || prev.CONTACT_IMAGE?.content?.src || null,
    accent: resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildContactRightImageCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = CONTACT_RIGHT_IMAGE_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    heading: String(by.HEADING || content.heading || content.title || d.HEADING).trim(),
    addressLabel: String(by.CONTACT_ADDRESS_LABEL || d.CONTACT_ADDRESS_LABEL).trim(),
    address: String(by.CONTACT_ADDRESS || content.address || d.CONTACT_ADDRESS).trim(),
    phoneLabel: String(by.CONTACT_PHONE_LABEL || d.CONTACT_PHONE_LABEL).trim(),
    phone: String(by.CONTACT_PHONE || content.phone || d.CONTACT_PHONE).trim(),
    emailLabel: String(by.CONTACT_EMAIL_LABEL || d.CONTACT_EMAIL_LABEL).trim(),
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

function contactRightImagePreviewSvg() {
  const chrome = buildContactRightImageChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { headingX, headingY, headingH, labelX, rowYs, valueYOff, imgX } = GEOM
  const rows = [
    ['Address', ['123 Main Street', 'City, State 12345']],
    ['Phone', ['+1 (555) 123-4567']],
    ['Email', ['hello@example.com']],
  ]
  const rowMarkup = rows.map(([label, lines], i) => {
    const y = rowYs[i]
    const valueLines = lines.map((line, li) =>
      `<text x="${labelX}" y="${y + valueYOff + 24 + li * 26}" fill="#0F172A" font-size="20" font-weight="600" font-family="system-ui,sans-serif">${xmlText(line)}</text>`
    ).join('')
    return `<text x="${labelX}" y="${y + 22}" fill="#64748B" font-size="15" font-weight="700" font-family="system-ui,sans-serif">${xmlText(label)}</text>${valueLines}`
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    <defs>
      <linearGradient id="criSky" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#7EC8E8"/>
        <stop offset="55%" stop-color="#B7D4E8"/>
        <stop offset="100%" stop-color="#D0E3EF"/>
      </linearGradient>
      <linearGradient id="criHill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#8FBF8E"/>
        <stop offset="100%" stop-color="#5E945D"/>
      </linearGradient>
    </defs>
    <rect x="${imgX}" width="920" height="1080" fill="url(#criSky)"/>
    <ellipse cx="${imgX + 220}" cy="180" rx="110" ry="48" fill="#FFFFFF" opacity="0.95"/>
    <ellipse cx="${imgX + 320}" cy="180" rx="80" ry="36" fill="#FFFFFF" opacity="0.95"/>
    <path d="M${imgX} 520 C${imgX + 180} 400 ${imgX + 360} 480 ${imgX + 540} 430 C${imgX + 700} 390 ${imgX + 780} 500 ${imgX + 920} 440 L${imgX + 920} 1080 L${imgX} 1080 Z" fill="url(#criHill)"/>
    ${chrome}
    <text x="${headingX}" y="${headingY + headingH * 0.7}" fill="#0F172A" font-size="52" font-weight="800" font-family="system-ui,sans-serif">Contact me</text>
    ${rowMarkup}
  </svg>`
}


module.exports = {
  isContactRightImageLayout,
  CONTACT_RIGHT_IMAGE_DEFAULTS,
  buildContactRightImageChromeSvg,
  layoutContactRightImage,
  buildContactRightImageCanvasElements,
  contactRightImagePreviewSvg,
};
