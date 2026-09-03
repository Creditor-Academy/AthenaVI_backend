/** Team six: left heading + subheading, 2×3 cards. Circle avatar overlaps top-left. Theme-accent shades. */

const TEAM_DECO = /^TEAM_SIX_(CARD|HEADER|RING)_/i
const SAMPLE_SUBHEADING = 'Enter your sub headline here'
const SAMPLE_MEMBERS = [
  { name: 'Johanna Doe', role: 'CEO', bio: 'This is a sample text that you can edit. You can change font, colour, or apply any desired formatting.' },
  { name: 'Jane Doe', role: 'Director', bio: 'This is a sample text that you can edit. You can change font, colour, or apply any desired formatting.' },
  { name: 'Joe Doe', role: 'Manager', bio: 'This is a sample text that you can edit. You can change font, colour, or apply any desired formatting.' },
  { name: 'Jenny Doe', role: 'Lead', bio: 'This is a sample text that you can edit. You can change font, colour, or apply any desired formatting.' },
  { name: 'John Doe', role: 'Designer', bio: 'This is a sample text that you can edit. You can change font, colour, or apply any desired formatting.' },
  { name: 'James Doe', role: 'Engineer', bio: 'This is a sample text that you can edit. You can change font, colour, or apply any desired formatting.' },
]

function filledText(el, fallback) {
  const t = String(el?.content?.text || '').replace(/\s+/g, ' ').trim()
  if (!t || /^(double[- ]click to edit|click to (add|edit)|enter (your )?(sub[- ]?headline|text)|6\s*team members)$/i.test(t)) return fallback
  return t
}

function isTeamSixLayout(layoutId) {
  return /team_six_v1/i.test(String(layoutId || ''))
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
  const A = parseHex(a) || [59, 130, 246]
  const B = parseHex(b) || [255, 255, 255]
  return toHex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t)
}

function cardShades(accent) {
  const theme = parseHex(accent) ? accent : '#3B82F6'
  return [
    mixHex(theme, '#ffffff', 0.48),
    mixHex(theme, '#ffffff', 0.28),
    mixHex(theme, '#ffffff', 0.08),
    mixHex(theme, '#000000', 0.18),
    mixHex(theme, '#000000', 0.34),
    mixHex(theme, '#000000', 0.50),
  ]
}

function teamSixGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const padX = Math.round(68 * sx)
  const headingY = Math.round(36 * sy)
  const headingH = Math.round(40 * sy)
  const subY = headingY + headingH + Math.round(10 * sy)
  const subH = Math.round(24 * sy)
  const availableTop = subY + subH + Math.round(22 * sy)
  const bottomPad = Math.round(44 * sy)
  const gapX = Math.round(48 * sx)
  const gapY = Math.round(44 * sy)
  const cols = 3
  const cardW = Math.round((canvasW - padX * 2 - gapX * (cols - 1)) / cols)
  const avatar = Math.round(132 * Math.min(sx, sy))
  const hang = Math.round(avatar * 0.2)
  const ring = Math.max(5, Math.round(6 * Math.min(sx, sy)))
  const availableH = canvasH - availableTop - bottomPad
  const maxCardH = Math.floor((availableH - hang - gapY) / 2)
  const cardH = Math.round(Math.min(maxCardH * 0.86, 348 * sy))
  const headerH = Math.round(104 * sy)
  const bodyH = cardH - headerH
  const nameH = Math.round(32 * sy)
  const roleH = Math.round(24 * sy)
  const stackH = hang + cardH * 2 + gapY
  const groupY = availableTop + Math.max(0, Math.round((availableH - stackH) / 2))
  const radius = Math.round(18 * Math.min(sx, sy))
  const bioPadX = Math.round(28 * sx)
  const bioPadY = Math.round(22 * sy)

  const rows = [0, 1, 2, 3, 4, 5].map((i) => {
    const col = i % cols
    const row = Math.floor(i / cols)
    const cardX = padX + col * (cardW + gapX)
    const cardY = groupY + hang + row * (cardH + gapY)
    const imgX = cardX - hang
    const imgY = cardY - hang
    const textX = imgX + avatar + Math.round(16 * sx)
    const textW = Math.max(80, cardX + cardW - textX - Math.round(18 * sx))
    const nameY = cardY + Math.round(16 * sy)
    const roleY = nameY + nameH + Math.round(2 * sy)
    return {
      card: { x: cardX, y: cardY, w: cardW, h: cardH },
      header: { x: cardX, y: cardY, w: cardW, h: headerH },
      ring: { x: imgX - ring, y: imgY - ring, w: avatar + ring * 2, h: avatar + ring * 2 },
      img: { x: imgX, y: imgY, w: avatar, h: avatar },
      name: { x: textX, y: nameY, w: textW, h: nameH },
      role: { x: textX, y: roleY, w: textW, h: roleH },
      bio: {
        x: cardX + bioPadX,
        y: cardY + headerH + bioPadY,
        w: cardW - bioPadX * 2,
        h: bodyH - bioPadY * 2,
      },
      email: { x: -10000 - i * 48, y: -10000 - i * 48, w: 8, h: 8 },
    }
  })

  return {
    padX,
    headingY,
    headingH,
    subY,
    subH,
    nameH,
    roleH,
    bioH: bodyH - bioPadY * 2,
    radius,
    rows,
  }
}

function place(el, box, extraContent = {}, layer = 16) {
  const nextContent = {
    ...(el.content || {}),
    ...extraContent,
  }
  if (extraContent.text != null) nextContent.runs = null
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

function injectExtras(next, g, muted) {
  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()))
  const extras = []
  if (!have.has('SUBHEADING')) {
    extras.push({
      id: 'txt-team-six-subheading',
      type: 'text',
      layer: 16,
      role: 'subheading',
      slotId: 'SUBHEADING',
      placement: {
        x: g.padX,
        y: g.subY,
        width: 900,
        height: g.subH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: SAMPLE_SUBHEADING,
        align: 'left',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 500,
        lineHeight: 1.2,
        color: muted,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.subH,
      },
    })
  }
  for (let n = 1; n <= 6; n += 1) {
    if (have.has(`MEMBER_${n}_BIO`)) continue
    const m = g.rows[n - 1]
    extras.push({
      id: `txt-team-six-bio-${n}`,
      type: 'text',
      layer: 18,
      role: 'body',
      slotId: `MEMBER_${n}_BIO`,
      placement: {
        x: m.bio.x,
        y: m.bio.y,
        width: m.bio.w,
        height: m.bio.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: SAMPLE_MEMBERS[n - 1].bio,
        align: 'left',
        verticalAlign: 'flex-start',
        fontSize: 14,
        fontWeight: 400,
        lineHeight: 1.5,
        color: '#FFFFFF',
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.bioH,
      },
    })
  }
  return extras.length ? [...next, ...extras] : next
}

function layoutTeamSixElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = teamSixGeom(canvasW, canvasH)
  const headingColor = (palette && (palette.heading || palette.text)) || '#0F172A'
  const muted = (palette && palette.muted) || '#64748B'
  const accent = (palette && (palette.primary || palette.accent)) || '#3B82F6'
  const shades = cardShades(accent)
  const white = '#FFFFFF'

  const stripped = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || '')))
  let next = stripped.flatMap((el) => {
    const sid = String(el.slotId || '').toUpperCase()
    if (el.type === 'icon' || el.kind === 'icon' || el.type === 'shape') return []
    if (sid === 'HEADING') {
      return [place(el, {
        x: g.padX,
        y: g.headingY,
        w: Math.round(canvasW * 0.7),
        h: g.headingH,
      }, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 28,
        fontWeight: 800,
        lineHeight: 1.1,
        color: headingColor,
        text: filledText(el, 'TEAM MEMBERS'),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      })]
    }
    if (sid === 'SUBHEADING') {
      return [place(el, {
        x: g.padX,
        y: g.subY,
        w: Math.round(canvasW * 0.55),
        h: g.subH,
      }, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 500,
        lineHeight: 1.2,
        color: muted,
        text: filledText(el, SAMPLE_SUBHEADING),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.subH,
      })]
    }

    const memberMatch = sid.match(/^MEMBER_([1-6])_(IMAGE|AVATAR|NAME|ROLE|EMAIL|BIO|BODY|DESC)$/)
    if (!memberMatch) return []
    const memberIndex = Number(memberMatch[1]) - 1
    const m = g.rows[memberIndex]
    const sample = SAMPLE_MEMBERS[memberIndex]
    const field = memberMatch[2]
    if (field === 'EMAIL') return []

    if (field === 'IMAGE' || field === 'AVATAR') {
      return [place(el, m.img, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: 999,
        clipPath: 'circle(50% at 50% 50%)',
        imageMask: { type: 'circle' },
      }, 8)]
    }
    if (field === 'NAME') {
      return [place(el, m.name, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 18,
        fontWeight: 800,
        lineHeight: 1.15,
        color: white,
        text: filledText(el, sample.name),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.nameH,
      }, 18)]
    }
    if (field === 'ROLE') {
      return [place(el, m.role, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        lineHeight: 1.2,
        color: 'rgba(255,255,255,0.88)',
        text: filledText(el, sample.role),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.roleH,
      }, 18)]
    }
    return [place(el, m.bio, {
      align: 'left',
      verticalAlign: 'flex-start',
      fontSize: 14,
      fontWeight: 400,
      lineHeight: 1.5,
      color: white,
      text: filledText(el, sample.bio),
      padding: 0,
      wrap: 'pre-wrap',
      clipToSlot: true,
      slotMaxHeight: g.bioH,
    }, 18)]
  })

  next = injectExtras(next, g, muted)

  const deco = []
  g.rows.forEach((m, i) => {
    const n = i + 1
    const body = shades[i]
    const header = mixHex(body, '#000000', 0.2)
    const ring = mixHex(body, '#ffffff', 0.35)
    deco.push({
      id: `shp-team-six-card-${n}`,
      type: 'shape',
      layer: 4,
      role: 'decoration',
      slotId: `TEAM_SIX_CARD_${n}`,
      placement: {
        x: m.card.x,
        y: m.card.y,
        width: m.card.w,
        height: m.card.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: body,
        borderRadius: g.radius,
        shadow: '0 10px 28px rgba(15, 23, 42, 0.18)',
      },
    })
    deco.push({
      id: `shp-team-six-header-${n}`,
      type: 'shape',
      layer: 5,
      role: 'decoration',
      slotId: `TEAM_SIX_HEADER_${n}`,
      placement: {
        x: m.header.x,
        y: m.header.y,
        width: m.header.w,
        height: m.header.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: header,
        borderRadius: `${g.radius}px ${g.radius}px 0 0`,
      },
    })
    deco.push({
      id: `shp-team-six-ring-${n}`,
      type: 'shape',
      layer: 7,
      role: 'decoration',
      slotId: `TEAM_SIX_RING_${n}`,
      placement: {
        x: m.ring.x,
        y: m.ring.y,
        width: m.ring.w,
        height: m.ring.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'circle',
        fill: ring,
        borderRadius: 999,
      },
    })
  })

  return [...deco, ...next]
}

function layoutTeamSix(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  const palette = themeTokens?.palette || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTeamSixElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTeamSixLayout,
  layoutTeamSix,
}
