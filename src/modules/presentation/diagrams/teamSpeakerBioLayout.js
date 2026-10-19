/**
 * Team Speaker Bio
 * Layout ID: team_speaker_bio_v1
 *
 * Portrait on the left, name / role / bio on an overlapping card.
 * Image-right and centered twins keep their own look.
 */

function isTeamSpeakerBioLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  if (/right|centered/i.test(id)) return false
  return id === 'team_speaker_bio_v1' || id === 'team_speaker_bio'
}

const TEAM_SPEAKER_BIO_DEFAULTS = {
  MEMBER_1_NAME: 'Speaker name',
  MEMBER_1_ROLE: 'Title · Organization',
  MEMBER_1_BIO: 'Speaker bio with credentials and talk focus. Share the story, the proof, and why this session matters for the audience.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 72,
  imgY: 88,
  imgW: 760,
  imgH: 904,
  radius: 40,
  pad: 16,
  panelX: 740,
  panelY: 128,
  panelW: 1108,
  panelH: 824,
  panelR: 40,
  accentX: 804,
  accentY: 196,
  accentW: 8,
  accentH: 72,
  nameX: 844,
  nameY: 176,
  nameW: 900,
  nameH: 100,
  roleX: 844,
  roleY: 288,
  roleW: 900,
  roleH: 52,
  bioX: 844,
  bioY: 368,
  bioW: 900,
  bioH: 500,
}

function buildTeamSpeakerBioChromeSvg() {
  const { panelX, panelY, panelW, panelH, panelR, accentX, accentY, accentW, accentH } = GEOM
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="tsbShadow" x="-8%" y="-8%" width="120%" height="120%">
        <feDropShadow dx="0" dy="16" stdDeviation="20" flood-color="#94A3B8" flood-opacity="0.2" />
      </filter>
    </defs>
    <ellipse cx="1760" cy="70" rx="260" ry="140" fill="currentColor" opacity="0.08"/>
    <ellipse cx="1680" cy="1040" rx="220" ry="120" fill="currentColor" opacity="0.06"/>
    <rect x="${panelX}" y="${panelY}" width="${panelW}" height="${panelH}" rx="${panelR}" fill="#FFFFFF" filter="url(#tsbShadow)"/>
    <rect x="${accentX}" y="${accentY}" width="${accentW}" height="${accentH}" rx="4" fill="currentColor"/>
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
      align: 'left',
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
  const d = TEAM_SPEAKER_BIO_DEFAULTS
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 8,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildTeamSpeakerBioChromeSvg(),
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
      layer: 4,
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
      fontSize: Math.round(46 * scale),
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
      maxLines: 10,
      lineHeight: 1.45,
    }),
  ]
}

function layoutTeamSpeakerBio(docOrElements, schema = {}, palette = {}, canvas = {}) {
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
    name: textOf(prev.MEMBER_1_NAME, TEAM_SPEAKER_BIO_DEFAULTS.MEMBER_1_NAME),
    role: textOf(prev.MEMBER_1_ROLE, TEAM_SPEAKER_BIO_DEFAULTS.MEMBER_1_ROLE),
    bio: textOf(prev.MEMBER_1_BIO, TEAM_SPEAKER_BIO_DEFAULTS.MEMBER_1_BIO),
    imageUrl: prev.MEMBER_1_IMAGE?.content?.url || prev.MEMBER_1_IMAGE?.content?.src || null,
    accent: resolveStoredColor(prev.IMAGE_CARD_BG, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildTeamSpeakerBioCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const by = options.contentBySlotId || {}
  const pal = options.palette || {}
  const d = TEAM_SPEAKER_BIO_DEFAULTS
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

function teamSpeakerBioPreviewSvg() {
  const chrome = buildTeamSpeakerBioChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const { imgX, imgY, imgW, imgH, radius, nameX, nameY, roleX, roleY, bioX, bioY } = GEOM
  const bioLines = [
    'Speaker bio with credentials and talk focus.',
    'Share the story, the proof, and why this',
    'session matters for the audience.',
  ]
  const bioMarkup = bioLines.map((line, i) =>
    `<text x="${bioX}" y="${bioY + 32 + i * 34}" fill="#0F172A" font-size="22" font-family="system-ui,sans-serif">${xmlText(line)}</text>`
  ).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    <rect width="1920" height="1080" fill="#F8FAFC"/>
    <defs>
      <clipPath id="tsbClip"><rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" rx="${radius}"/></clipPath>
      <linearGradient id="tsbSky" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#7EC8E8"/>
        <stop offset="55%" stop-color="#B7D4E8"/>
        <stop offset="100%" stop-color="#D0E3EF"/>
      </linearGradient>
      <linearGradient id="tsbHill" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#8FBF8E"/>
        <stop offset="100%" stop-color="#5E945D"/>
      </linearGradient>
    </defs>
    <g clip-path="url(#tsbClip)">
      <rect x="${imgX}" y="${imgY}" width="${imgW}" height="${imgH}" fill="url(#tsbSky)"/>
      <ellipse cx="${imgX + 200}" cy="${imgY + 140}" rx="100" ry="42" fill="#FFFFFF" opacity="0.95"/>
      <ellipse cx="${imgX + 300}" cy="${imgY + 140}" rx="70" ry="32" fill="#FFFFFF" opacity="0.95"/>
      <path d="M${imgX} ${imgY + 420} C${imgX + 180} ${imgY + 300} ${imgX + 380} ${imgY + 380} ${imgX + 560} ${imgY + 320} C${imgX + 680} ${imgY + 280} ${imgX + 720} ${imgY + 400} ${imgX + imgW} ${imgY + 340} L${imgX + imgW} ${imgY + imgH} L${imgX} ${imgY + imgH} Z" fill="url(#tsbHill)"/>
    </g>
    ${chrome}
    <text x="${nameX}" y="${nameY + 68}" fill="#0F172A" font-size="46" font-weight="800" font-family="system-ui,sans-serif">Speaker name</text>
    <text x="${roleX}" y="${roleY + 36}" fill="#64748B" font-size="22" font-weight="600" font-family="system-ui,sans-serif">Title · Organization</text>
    ${bioMarkup}
  </svg>`
}


module.exports = {
  isTeamSpeakerBioLayout,
  TEAM_SPEAKER_BIO_DEFAULTS,
  buildTeamSpeakerBioChromeSvg,
  layoutTeamSpeakerBio,
  buildTeamSpeakerBioCanvasElements,
  teamSpeakerBioPreviewSvg,
};
