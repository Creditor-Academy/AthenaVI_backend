/**
 * Speaker Bio Centered
 * Layout ID: speaker_bio_centered_v1
 *
 * Circular portrait on top, name / role / bio stacked and centered.
 * Left and image-right twins keep their own engines.
 */

function isSpeakerBioCenteredLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/right|team_speaker/i.test(id)) return false
  return id === 'speaker_bio_centered_v1' || id === 'speaker_bio_centered'
}

const SPEAKER_BIO_CENTERED_DEFAULTS = {
  MEMBER_1_NAME: 'Speaker name',
  MEMBER_1_ROLE: 'Title · Organization',
  MEMBER_1_BIO: 'Speaker bio with credentials and talk focus. Share the story, the proof, and why this session matters for the audience.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 780,
  imgY: 56,
  imgW: 360,
  imgH: 360,
  radius: 180,
  ringPad: 10,
  nameX: 240,
  nameY: 452,
  nameW: 1440,
  nameH: 88,
  roleX: 240,
  roleY: 548,
  roleW: 1440,
  roleH: 48,
  bioX: 340,
  bioY: 620,
  bioW: 1240,
  bioH: 380,
}

function buildSpeakerBioCenteredChromeSvg() {
  const { imgX, imgY, imgW, ringPad } = GEOM
  const cx = imgX + imgW / 2
  const cy = imgY + imgW / 2
  const r = imgW / 2 + ringPad
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <ellipse cx="160" cy="80" rx="260" ry="140" fill="currentColor" opacity="0.08"/>
    <ellipse cx="1760" cy="80" rx="260" ry="140" fill="currentColor" opacity="0.08"/>
    <ellipse cx="960" cy="1040" rx="420" ry="140" fill="currentColor" opacity="0.05"/>
    <circle cx="${cx}" cy="${cy}" r="${r + 8}" fill="#FFFFFF"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="currentColor" stroke-width="4"/>
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

function buildElements({ canvasW, canvasH, name, role, bio, imageUrl, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const d = SPEAKER_BIO_CENTERED_DEFAULTS
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 3,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildSpeakerBioCenteredChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    {
      id: prev.MEMBER_1_IMAGE?.id || 'slot-MEMBER_1_IMAGE',
      slotId: 'MEMBER_1_IMAGE',
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
      id: prev.MEMBER_1_NAME?.id || 'slot-MEMBER_1_NAME',
      slotId: 'MEMBER_1_NAME',
      role: 'heading',
      x: Math.round(GEOM.nameX * sx),
      y: Math.round(GEOM.nameY * sy),
      w: Math.round(GEOM.nameW * sx),
      h: Math.round(GEOM.nameH * sy),
      text: name || d.MEMBER_1_NAME,
      fontSize: Math.round(44 * scale),
      fontWeight: 800,
      color: textColor,
      maxLines: 2,
    }),
    textEl({
      id: prev.MEMBER_1_ROLE?.id || 'slot-MEMBER_1_ROLE',
      slotId: 'MEMBER_1_ROLE',
      role: 'subheading',
      x: Math.round(GEOM.roleX * sx),
      y: Math.round(GEOM.roleY * sy),
      w: Math.round(GEOM.roleW * sx),
      h: Math.round(GEOM.roleH * sy),
      text: role || d.MEMBER_1_ROLE,
      fontSize: Math.round(22 * scale),
      fontWeight: 600,
      color: mutedColor,
      maxLines: 1,
    }),
    textEl({
      id: prev.MEMBER_1_BIO?.id || 'slot-MEMBER_1_BIO',
      slotId: 'MEMBER_1_BIO',
      role: 'body',
      x: Math.round(GEOM.bioX * sx),
      y: Math.round(GEOM.bioY * sy),
      w: Math.round(GEOM.bioW * sx),
      h: Math.round(GEOM.bioH * sy),
      text: bio || d.MEMBER_1_BIO,
      fontSize: Math.round(22 * scale),
      fontWeight: 400,
      color: textColor,
      maxLines: 8,
      lineHeight: 1.45,
    }),
  ]
}

function layoutSpeakerBioCentered(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  const accent = pal.primary || pal.accent || '#6366F1'
  const textColor = pal.text || '#0F172A'
  const mutedColor = pal.muted || '#64748B'
  const prev = {
    IMAGE_CARD_BG: findEl(elements, ['IMAGE_CARD_BG']),
    MEMBER_1_IMAGE: findEl(elements, ['MEMBER_1_IMAGE', 'CONTACT_IMAGE', 'HERO_IMAGE']),
    MEMBER_1_NAME: findEl(elements, ['MEMBER_1_NAME', 'HEADING']),
    MEMBER_1_ROLE: findEl(elements, ['MEMBER_1_ROLE', 'SUBTITLE']),
    MEMBER_1_BIO: findEl(elements, ['MEMBER_1_BIO', 'BODY']),
  }
  const out = buildElements({
    canvasW,
    canvasH,
    name: textOf(prev.MEMBER_1_NAME, SPEAKER_BIO_CENTERED_DEFAULTS.MEMBER_1_NAME),
    role: textOf(prev.MEMBER_1_ROLE, SPEAKER_BIO_CENTERED_DEFAULTS.MEMBER_1_ROLE),
    bio: textOf(prev.MEMBER_1_BIO, SPEAKER_BIO_CENTERED_DEFAULTS.MEMBER_1_BIO),
    imageUrl: prev.MEMBER_1_IMAGE?.content?.url || prev.MEMBER_1_IMAGE?.content?.src || null,
    accent: resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildSpeakerBioCenteredCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = SPEAKER_BIO_CENTERED_DEFAULTS
  return buildElements({
    canvasW,
    canvasH,
    name: String(by.MEMBER_1_NAME || content.name || content.title || d.MEMBER_1_NAME).trim(),
    role: String(by.MEMBER_1_ROLE || content.role || d.MEMBER_1_ROLE).trim(),
    bio: String(by.MEMBER_1_BIO || content.bio || content.body || d.MEMBER_1_BIO).trim(),
    imageUrl:
      by.MEMBER_1_IMAGE__url ||
      by.MEMBER_1_IMAGE_url ||
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

function speakerBioCenteredPreviewSvg() {
  const chrome = buildSpeakerBioCenteredChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { imgX, imgY, imgW, imgH, radius, nameX, nameY, nameW, roleY, roleX, roleW, bioX, bioY, bioW } = GEOM
  const bioLines = [
    'Speaker bio with credentials and talk focus.',
    'Share the story, the proof, and why this session',
    'matters for the audience.',
  ]
  const bioMarkup = bioLines.map((line, i) =>
    `<text x="${bioX + bioW / 2}" y="${bioY + 32 + i * 34}" text-anchor="middle" fill="#0F172A" font-size="22" font-family="system-ui,sans-serif">${xmlText(line)}</text>`
  ).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    <defs>
      <clipPath id="sbcClip"><circle cx="${imgX + imgW / 2}" cy="${imgY + imgH / 2}" r="${radius}"/></clipPath>
      <linearGradient id="sbcSky" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#7EC8E8"/>
        <stop offset="55%" stop-color="#B7D4E8"/>
        <stop offset="100%" stop-color="#D0E3EF"/>
      </linearGradient>
      <linearGradient id="sbcHill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#8FBF8E"/>
        <stop offset="100%" stop-color="#5E945D"/>
      </linearGradient>
    </defs>
    ${chrome}
    <g clip-path="url(#sbcClip)">
      <rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" fill="url(#sbcSky)"/>
      <ellipse cx="${imgX + 110}" cy="${imgY + 90}" rx="70" ry="28" fill="#FFFFFF" opacity="0.95"/>
      <ellipse cx="${imgX + 180}" cy="${imgY + 90}" rx="48" ry="22" fill="#FFFFFF" opacity="0.95"/>
      <path d="M${imgX} ${imgY + 210} C${imgX + 80} ${imgY + 160} ${imgX + 180} ${imgY + 200} ${imgX + 260} ${imgY + 170} C${imgX + 320} ${imgY + 150} ${imgX + 340} ${imgY + 210} ${imgX + imgW} ${imgY + 180} L${imgX + imgW} ${imgY + imgH} L${imgX} ${imgY + imgH} Z" fill="url(#sbcHill)"/>
    </g>
    <text x="${nameX + nameW / 2}" y="${nameY + 62}" text-anchor="middle" fill="#0F172A" font-size="44" font-weight="800" font-family="system-ui,sans-serif">Speaker name</text>
    <text x="${roleX + roleW / 2}" y="${roleY + 34}" text-anchor="middle" fill="#64748B" font-size="22" font-weight="600" font-family="system-ui,sans-serif">Title · Organization</text>
    ${bioMarkup}
  </svg>`
}


module.exports = {
  isSpeakerBioCenteredLayout,
  SPEAKER_BIO_CENTERED_DEFAULTS,
  buildSpeakerBioCenteredChromeSvg,
  layoutSpeakerBioCentered,
  buildSpeakerBioCenteredCanvasElements,
  speakerBioCenteredPreviewSvg,
};
