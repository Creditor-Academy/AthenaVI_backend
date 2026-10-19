/** Team five: 2+3 white cards, circular avatars, name/role/line/bio, gray footer. No social icons. */

const TEAM_DECO = /^TEAM_FIVE_(CARD|RING|FOOTER|LINE)_/i
const AVATAR_PRESETS = ['#F472B6', '#FB923C', '#EAB308', '#34D399', '#38BDF8']
const SAMPLE_MEMBERS = [
  { name: 'Johanna Doe', role: 'Co-founder & CEO', bio: 'Leads product vision and keeps the team focused on what matters.' },
  { name: 'Jane Doe', role: 'Co-founder & CTO', bio: 'Builds the platform and sets the technical bar for the work we ship.' },
  { name: 'Joe Doe', role: 'Co-founder & COO', bio: 'Runs day-to-day operations so the team can move with clarity.' },
  { name: 'Jenny Doe', role: 'President', bio: 'Guides partnerships and growth with a steady, practical point of view.' },
  { name: 'John Doe', role: 'Head of Design', bio: 'Shapes the visual language and makes every slide feel considered.' },
]

function filledText(el, fallback) {
  const t = String(el?.content?.text || '').trim()
  if (!t || /^double-?click to edit$/i.test(t)) return fallback
  return t
}

function isTeamFiveLayout(layoutId) {
  return /team_five_v1/i.test(String(layoutId || ''))
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
  const A = parseHex(a) || [244, 114, 182]
  const B = parseHex(b) || [255, 255, 255]
  return toHex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t)
}

function avatarPalette(accent) {
  const theme = parseHex(accent) ? accent : AVATAR_PRESETS[0]
  return AVATAR_PRESETS.map((p, i) => (i === 0 ? mixHex(p, theme, 0.28) : mixHex(p, theme, 0.12)))
}

function teamFiveGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const headingY = Math.round(52 * sy)
  const headingH = Math.round(44 * sy)
  const availableTop = headingY + headingH + Math.round(18 * sy)
  const bottomPad = Math.round(28 * sy)
  const availableH = canvasH - availableTop - bottomPad
  const padX = Math.round(80 * sx)
  const gap = Math.round(28 * sx)
  const gapY = Math.round(40 * sy)
  const bandW = canvasW - padX * 2
  const cardWBottom = Math.round((bandW - gap * 2) / 3)
  const cardWTop = Math.round((bandW - gap) / 2)
  const avatar = Math.round(136 * Math.min(sx, sy))
  const ring = Math.max(6, Math.round(8 * Math.min(sx, sy)))
  const overlap = Math.round(avatar * 0.46)
  const footerH = Math.round(30 * sy)
  const nameH = Math.round(36 * sy)
  const roleH = Math.round(24 * sy)
  const lineH = Math.max(2, Math.round(3 * sy))
  const lineW = Math.round(52 * sx)
  const bioH = Math.round(96 * sy)
  const afterAvatar = Math.round(14 * sy)
  const cardH =
    (avatar - overlap) + afterAvatar + nameH + Math.round(6 * sy) + roleH + Math.round(10 * sy) + lineH + Math.round(14 * sy) + bioH + Math.round(16 * sy) + footerH
  const rowH = overlap + cardH
  const stackH = rowH * 2 + gapY
  const groupY = availableTop + Math.max(0, Math.round((availableH - stackH) / 2))
  const y0 = groupY
  const y1 = groupY + rowH + gapY
  const widths = [cardWTop, cardWTop, cardWBottom, cardWBottom, cardWBottom]
  const xs = [
    padX,
    padX + cardWTop + gap,
    padX,
    padX + cardWBottom + gap,
    padX + (cardWBottom + gap) * 2,
  ]
  const ys = [y0, y0, y1, y1, y1]
  const radius = Math.round(16 * Math.min(sx, sy))

  const rows = xs.map((cardX, i) => {
    const cardW = widths[i]
    const cardY = ys[i] + overlap
    const imgX = cardX + Math.round((cardW - avatar) / 2)
    const imgY = ys[i]
    const textX = cardX + Math.round(18 * sx)
    const textW = cardW - Math.round(36 * sx)
    const nameY = cardY + (avatar - overlap) + afterAvatar
    const roleY = nameY + nameH + Math.round(6 * sy)
    const lineY = roleY + roleH + Math.round(10 * sy)
    const bioY = lineY + lineH + Math.round(14 * sy)
    return {
      colorIndex: i,
      card: { x: cardX, y: cardY, w: cardW, h: cardH },
      footer: { x: cardX, y: cardY + cardH - footerH, w: cardW, h: footerH },
      ring: { x: imgX - ring, y: imgY - ring, w: avatar + ring * 2, h: avatar + ring * 2 },
      img: { x: imgX, y: imgY, w: avatar, h: avatar },
      name: { x: textX, y: nameY, w: textW, h: nameH },
      role: { x: textX, y: roleY, w: textW, h: roleH },
      line: {
        x: cardX + Math.round((cardW - lineW) / 2),
        y: lineY,
        w: lineW,
        h: lineH,
      },
      bio: { x: textX, y: bioY, w: textW, h: bioH },
      email: { x: -820 - i * 48, y: -820 - i * 48, w: 8, h: 8 },
    }
  })

  return {
    headingY,
    headingH,
    nameH,
    roleH,
    bioH,
    radius,
    avatar,
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

function injectMissingBios(next, g, textColor) {
  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()))
  const extras = []
  for (let n = 1; n <= 5; n += 1) {
    if (have.has(`MEMBER_${n}_BIO`)) continue
    const m = g.rows[n - 1]
    extras.push({
      id: `txt-team-five-bio-${n}`,
      type: 'text',
      layer: 16,
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
        align: 'center',
        verticalAlign: 'flex-start',
        fontSize: 13,
        fontWeight: 400,
        lineHeight: 1.4,
        color: textColor,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.bioH,
      },
    })
  }
  return extras.length ? [...next, ...extras] : next
}

function layoutTeamFiveElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = teamFiveGeom(canvasW, canvasH)
  const textColor = (palette && palette.text) || '#1F2937'
  const muted = (palette && palette.muted) || '#6B7280'
  const accent = (palette && (palette.primary || palette.accent)) || '#F472B6'
  const colors = avatarPalette(accent)
  const cardFill = (palette && (palette.surface || palette.card)) || '#FFFFFF'
  const footerFill = mixHex('#E5E7EB', cardFill, 0.35)

  const stripped = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || '')))
  let next = stripped.map((el) => {
    const sid = String(el.slotId || '').toUpperCase()
    if (sid === 'HEADING') {
      return place(el, {
        x: Math.round(canvasW * 0.12),
        y: g.headingY,
        w: Math.round(canvasW * 0.76),
        h: g.headingH,
      }, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 28,
        fontWeight: 800,
        lineHeight: 1.1,
        color: textColor,
        text: filledText(el, 'Meet the team'),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      })
    }

    const memberMatch = sid.match(/^MEMBER_([12345])_(IMAGE|NAME|ROLE|EMAIL|BIO|BODY|DESC)$/)
    if (!memberMatch) return el
    const memberIndex = Number(memberMatch[1]) - 1
    const m = g.rows[memberIndex]
    const sample = SAMPLE_MEMBERS[memberIndex]
    const tint = colors[memberIndex]
    const field = memberMatch[2]

    if (field === 'IMAGE') {
      return place(el, m.img, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: 999,
        clipPath: 'circle(50% at 50% 50%)',
        imageMask: { type: 'circle' },
      }, 8)
    }

    if (field === 'NAME') {
      return place(el, m.name, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 20,
        fontWeight: 800,
        lineHeight: 1.15,
        color: tint,
        text: filledText(el, sample.name),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.nameH,
      }, 18)
    }

    if (field === 'ROLE') {
      return place(el, m.role, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 400,
        italic: true,
        lineHeight: 1.2,
        color: muted,
        text: filledText(el, sample.role),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.roleH,
      }, 18)
    }

    if (field === 'EMAIL') {
      return place(el, m.email, { opacity: 0 }, 0)
    }

    return place(el, m.bio, {
      align: 'center',
      verticalAlign: 'flex-start',
      fontSize: 13,
      fontWeight: 400,
      lineHeight: 1.4,
      color: textColor,
      text: filledText(el, sample.bio),
      padding: 0,
      wrap: 'pre-wrap',
      clipToSlot: true,
      slotMaxHeight: g.bioH,
    }, 18)
  })

  next = injectMissingBios(next, g, textColor)

  const deco = []
  g.rows.forEach((m, i) => {
    const n = i + 1
    const tint = colors[i]
    deco.push({
      id: `shp-team-five-card-${n}`,
      type: 'shape',
      layer: 4,
      role: 'decoration',
      slotId: `TEAM_FIVE_CARD_${n}`,
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
        fill: cardFill,
        borderRadius: g.radius,
        shadow: '0 10px 28px rgba(15, 23, 42, 0.08)',
      },
    })
    deco.push({
      id: `shp-team-five-footer-${n}`,
      type: 'shape',
      layer: 5,
      role: 'decoration',
      slotId: `TEAM_FIVE_FOOTER_${n}`,
      placement: {
        x: m.footer.x,
        y: m.footer.y,
        width: m.footer.w,
        height: m.footer.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: footerFill,
        borderRadius: `0 0 ${g.radius}px ${g.radius}px`,
      },
    })
    deco.push({
      id: `shp-team-five-ring-${n}`,
      type: 'shape',
      layer: 7,
      role: 'decoration',
      slotId: `TEAM_FIVE_RING_${n}`,
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
        fill: tint,
        borderRadius: 999,
      },
    })
    deco.push({
      id: `shp-team-five-line-${n}`,
      type: 'shape',
      layer: 12,
      role: 'decoration',
      slotId: `TEAM_FIVE_LINE_${n}`,
      placement: {
        x: m.line.x,
        y: m.line.y,
        width: m.line.w,
        height: m.line.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: tint,
        borderRadius: 2,
      },
    })
  })

  return [...deco, ...next]
}

function layoutTeamFive(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  };
  return { ...doc, elements: layoutTeamFiveElements(doc.elements || [], layoutSchema, palette, size) };
}

module.exports = {
  isTeamFiveLayout,
  layoutTeamFive,
};