/** Team featured lead: circular portrait on the left, curved split, name/role/bio on the right. */

const TEAM_DECO = /^TEAM_LEAD_(BAND|CURVE|PANEL|RING|DOT)_/i
const SAMPLE = {
  heading: 'LEADERSHIP',
  name: 'JOHANNA DOE',
  role: 'CO-FOUNDER & CEO',
  bio: 'Leads the company with a clear point of view. She sets the product direction and keeps the team focused on work that matters.',
}

function filledText(el, fallback) {
  const t = String(el?.content?.text || '').replace(/\s+/g, ' ').trim()
  if (!t || /^(double[- ]click to edit|click to (add|edit)|enter (your )?(sub[- ]?headline|text)|founder name)/i.test(t)) return fallback
  return t
}

function isTeamFeaturedLeadLayout(layoutId) {
  return /team_featured_lead_v1/i.test(String(layoutId || ''))
}

function parseHex(hex) {
  const raw = String(hex || '').replace('#', '')
  if (raw.length !== 6) return null
  const n = Number.parseInt(raw, 16)
  if (Number.isNaN(n)) return null
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

function toHex(r, g, b) {
  return `#${[r, g, b].map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('')}`
}

function mixHex(a, b, t) {
  const A = parseHex(a) || [79, 111, 106]
  const B = parseHex(b) || [255, 255, 255]
  return toHex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t)
}

function teamFeaturedLeadGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const splitX = Math.round(canvasW * 0.5)
  const bumpD = Math.min(canvasH, splitX * 2)
  const bumpX = splitX - Math.round(bumpD / 2)
  const bumpY = Math.round((canvasH - bumpD) / 2)
  const photo = Math.round(Math.min(500 * Math.min(sx, sy), splitX - Math.round(48 * sx)))
  const photoX = Math.round(Math.max(48 * sx, (splitX - photo) * 0.35))
  const photoY = Math.round((canvasH - photo) / 2)
  const cx = photoX + Math.round(photo / 2)
  const cy = photoY + Math.round(photo / 2)
  const ringOuter = photo + Math.round(72 * Math.min(sx, sy))
  const ringInner = photo + Math.round(32 * Math.min(sx, sy))
  const dot = Math.round(56 * Math.min(sx, sy))
  const textX = Math.min(
    canvasW - Math.round(720 * sx),
    Math.max(photoX + photo + Math.round(64 * sx), Math.round(canvasW * 0.42)),
  )
  const textW = canvasW - textX - Math.round(72 * sx)
  const labelH = Math.round(40 * sy)
  const nameH = Math.round(64 * sy)
  const roleH = Math.round(48 * sy)
  const bioH = Math.round(260 * sy)
  const gapLabel = Math.round(18 * sy)
  const gapName = Math.round(14 * sy)
  const gapRole = Math.round(28 * sy)
  const textBlockH = labelH + gapLabel + nameH + gapName + roleH + gapRole + bioH
  const textY = Math.max(
    Math.round(56 * sy),
    Math.min(photoY + Math.round((photo - textBlockH) / 2), canvasH - textBlockH - Math.round(56 * sy)),
  )
  const nameY = textY + labelH + gapLabel
  const roleY = nameY + nameH + gapName
  const bioY = roleY + roleH + gapRole

  return {
    labelH,
    nameH,
    roleH,
    bioH,
    band: { x: 0, y: 0, w: splitX + Math.round(24 * sx), h: canvasH },
    bump: { x: bumpX, y: bumpY, w: bumpD, h: bumpD },
    ringOuter: {
      x: cx - Math.round(ringOuter / 2),
      y: cy - Math.round(ringOuter / 2),
      w: ringOuter,
      h: ringOuter,
    },
    ringInner: {
      x: cx - Math.round(ringInner / 2),
      y: cy - Math.round(ringInner / 2),
      w: ringInner,
      h: ringInner,
    },
    img: { x: photoX, y: photoY, w: photo, h: photo },
    dot: {
      x: photoX + photo - Math.round(dot / 2),
      y: cy - Math.round(dot / 2),
      w: dot,
      h: dot,
    },
    heading: { x: textX, y: textY, w: textW, h: labelH },
    name: { x: textX, y: nameY, w: textW, h: nameH },
    role: { x: textX, y: roleY, w: textW, h: roleH },
    bio: { x: textX, y: bioY, w: textW, h: bioH },
  }
}

function place(el, box, extraContent = {}, layer = 16) {
  const nextContent = {
    ...(el.content || {}),
    ...extraContent,
  }
  if (extraContent.text != null) nextContent.runs = null
  if (extraContent.align) nextContent.textAlign = extraContent.align
  return {
    ...el,
    layer,
    placement: {
      ...(el.placement || {}),
      x: box.x,
      y: box.y,
      width: box.w,
      height: box.h,
      rotation: 0,
      opacity: extraContent.opacity != null ? extraContent.opacity : 1,
    },
    content: nextContent,
  }
}

function decoShape(id, slotId, box, layer, content) {
  return {
    id,
    type: 'shape',
    layer,
    role: 'decoration',
    slotId,
    placement: {
      x: box.x,
      y: box.y,
      width: box.w,
      height: box.h,
      rotation: 0,
      opacity: 1,
    },
    content,
  }
}

function layoutTeamFeaturedLeadElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = teamFeaturedLeadGeom(canvasW, canvasH)
  const headingColor = (palette && (palette.heading || palette.text)) || '#1F2937'
  const muted = (palette && palette.muted) || '#6B7280'
  const accent = (palette && (palette.primary || palette.accent)) || '#4F6F6A'
  const wash = mixHex(accent, '#ffffff', 0.78)

  const next = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || ''))).flatMap((el) => {
    const sid = String(el.slotId || '').toUpperCase()
    if (el.type === 'icon' || el.kind === 'icon' || el.type === 'shape') return []
    if (sid === 'HEADING') {
      return [place(el, g.heading, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 22,
        fontWeight: 700,
        letterSpacing: 3,
        lineHeight: 1.1,
        color: accent,
        text: filledText(el, SAMPLE.heading).toUpperCase(),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.labelH,
      })]
    }
    if (sid === 'MEMBER_1_IMAGE' || (el.type === 'image' && /MEMBER_1/.test(sid))) {
      return [place(el, g.img, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: 999,
        clipPath: 'circle(50% at 50% 50%)',
        imageMask: { type: 'circle' },
      }, 10)]
    }
    if (sid === 'MEMBER_1_NAME') {
      return [place(el, g.name, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 32,
        fontWeight: 800,
        letterSpacing: 1,
        lineHeight: 1.1,
        color: headingColor,
        text: filledText(el, SAMPLE.name).toUpperCase(),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.nameH,
      })]
    }
    if (sid === 'MEMBER_1_ROLE') {
      return [place(el, g.role, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 26,
        fontWeight: 500,
        letterSpacing: 1.5,
        lineHeight: 1.2,
        color: muted,
        text: filledText(el, SAMPLE.role).toUpperCase(),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.roleH,
      })]
    }
    if (sid === 'MEMBER_1_BIO' || sid === 'MEMBER_1_BODY' || sid === 'MEMBER_1_DESC' || sid === 'BODY') {
      return [place(el, g.bio, {
        align: 'left',
        verticalAlign: 'top',
        fontSize: 22,
        fontWeight: 400,
        lineHeight: 1.5,
        color: muted,
        text: filledText(el, SAMPLE.bio),
        padding: 0,
        wrap: 'wrap',
        clipToSlot: false,
        slotMaxHeight: g.bioH,
      })]
    }
    return []
  })

  const deco = [
    decoShape('shp-team-lead-band', 'TEAM_LEAD_BAND', g.band, 1, {
      shape: 'rect',
      fill: wash,
      borderRadius: 0,
    }),
    decoShape('shp-team-lead-ring-o', 'TEAM_LEAD_RING_1', g.ringOuter, 2, {
      shape: 'circle',
      variant: 'outlined',
      fill: 'transparent',
      stroke: mixHex(accent, '#ffffff', 0.4),
      strokeWidth: 8,
      borderRadius: 999,
    }),
    decoShape('shp-team-lead-ring-i', 'TEAM_LEAD_RING_2', g.ringInner, 3, {
      shape: 'circle',
      variant: 'outlined',
      fill: 'transparent',
      stroke: mixHex(accent, '#ffffff', 0.28),
      strokeWidth: 6,
      borderRadius: 999,
    }),
    decoShape('shp-team-lead-curve', 'TEAM_LEAD_CURVE', g.bump, 4, {
      shape: 'circle',
      fill: '#FFFFFF',
      borderRadius: 999,
    }),
    decoShape('shp-team-lead-dot', 'TEAM_LEAD_DOT', g.dot, 12, {
      shape: 'circle',
      fill: accent,
      borderRadius: 999,
    }),
  ]

  return [...deco, ...next]
}

function layoutTeamFeaturedLead(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  const palette = themeTokens?.palette || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTeamFeaturedLeadElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTeamFeaturedLeadLayout,
  layoutTeamFeaturedLead,
}
