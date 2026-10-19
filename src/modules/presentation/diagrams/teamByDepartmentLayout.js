/** Team by department: sharp left rail half under the card, circular photos. */

const TEAM_DECO = /^TEAM_DEPT_(BAR|PILL|RING|LINE|ROW)_/i
const SAMPLE_DEPTS = ['Leadership', 'Engineering', 'Design']
const SAMPLE_SUBHEADING = 'The people behind each part of the work.'
const SAMPLE_MEMBERS = [
  { name: 'Johanna Doe', role: 'Co-founder & CEO' },
  { name: 'Jane Doe', role: 'Co-founder & CTO' },
  { name: 'Joe Doe', role: 'Head of Engineering' },
  { name: 'Jenny Doe', role: 'Staff Engineer' },
  { name: 'John Doe', role: 'Head of Design' },
  { name: 'James Doe', role: 'Product Designer' },
]

function filledText(el, fallback) {
  const t = String(el?.content?.text || '').replace(/\s+/g, ' ').trim()
  if (!t || /^(double[- ]click to edit|click to (add|edit)|enter (your )?(sub[- ]?headline|text))/i.test(t)) return fallback
  return t
}

function isTeamByDepartmentLayout(layoutId) {
  return /team_by_department_v1/i.test(String(layoutId || ''))
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
  const A = parseHex(a) || [99, 102, 241]
  const B = parseHex(b) || [255, 255, 255]
  return toHex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t)
}

function deptShades(accent) {
  const theme = parseHex(accent) ? accent : '#4F6F6A'
  return [
    mixHex(theme, '#000000', 0.12),
    mixHex(theme, '#ffffff', 0.08),
    mixHex(theme, '#D4A017', 0.55),
  ]
}

function teamByDepartmentGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const padX = Math.round(96 * sx)
  const gapX = Math.round(80 * sx)
  const colW = Math.round((canvasW - padX * 2 - gapX * 2) / 3)
  const headingY = Math.round(44 * sy)
  const headingH = Math.round(52 * sy)
  const subY = headingY + headingH + Math.round(10 * sy)
  const subH = Math.round(28 * sy)
  const afterHeading = subY + subH + Math.round(32 * sy)
  const deptH = Math.round(40 * sy)
  const afterDept = Math.round(20 * sy)
  const barW = Math.round(36 * sx)
  const ring = Math.max(7, Math.round(8 * Math.min(sx, sy)))
  const avatar = Math.round(136 * Math.min(sx, sy))
  const photoRadius = Math.round(avatar / 2)
  const cardRadius = Math.round(18 * Math.min(sx, sy))
  const gapY = Math.round(28 * sy)
  const nameH = Math.round(34 * sy)
  const roleH = Math.round(30 * sy)
  const textW = Math.round(248 * sx)
  const cardPadR = Math.round(28 * sx)
  const photoOnCard = Math.round(avatar * 0.58)
  const cardW = Math.min(colW - Math.round(barW * 0.2), photoOnCard + Math.round(20 * sx) + textW + cardPadR)
  const bottomLimit = canvasH - Math.round(64 * sy)
  const deptBlock = deptH + afterDept
  const maxCards = Math.max(Math.round(160 * sy), bottomLimit - afterHeading - deptBlock)
  const cardH = Math.round(Math.min(200 * sy, (maxCards - gapY) / 2))
  const stackH = deptBlock + cardH * 2 + gapY
  const restH = bottomLimit - afterHeading
  const groupY = afterHeading + Math.max(0, Math.round((restH - stackH) / 2))
  const cols = [0, 1, 2].map((i) => padX + i * (colW + gapX))

  const depts = cols.map((x) => {
    const deptY = groupY
    const cardsY = deptY + deptH + afterDept
    const members = [0, 1].map((ri) => {
      const cardY = cardsY + ri * (cardH + gapY)
      const halfBar = Math.round(barW / 2)
      const cardX = x + halfBar
      const imgX = cardX - Math.round(avatar / 2)
      const imgY = cardY + Math.round((cardH - avatar) / 2)
      const textX = imgX + avatar + Math.round(16 * sx)
      const nameY = cardY + Math.round((cardH - nameH - roleH - 8) / 2)
      return {
        pill: { x: cardX, y: cardY, w: cardW, h: cardH },
        ring: {
          x: imgX - ring,
          y: imgY - ring,
          w: avatar + ring * 2,
          h: avatar + ring * 2,
        },
        img: { x: imgX, y: imgY, w: avatar, h: avatar },
        name: { x: textX, y: nameY, w: textW, h: nameH },
        role: { x: textX, y: nameY + nameH + 8, w: textW, h: roleH },
      }
    })
    const first = members[0].pill
    const last = members[1].pill
    const barY = first.y
    const barH = Math.min(last.y + last.h - first.y, bottomLimit - barY)
    return {
      heading: { x, y: deptY, w: colW, h: deptH },
      bar: { x, y: barY, w: barW, h: Math.max(1, barH) },
      members,
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
    photoRadius,
    cardRadius,
    depts,
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

function injectSubheading(next, g, muted) {
  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()))
  if (have.has('SUBHEADING')) return next
  return [
    ...next,
    {
      id: 'txt-team-dept-subheading',
      type: 'text',
      layer: 16,
      role: 'subheading',
      slotId: 'SUBHEADING',
      placement: {
        x: g.padX,
        y: g.subY,
        width: 820,
        height: g.subH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: SAMPLE_SUBHEADING,
        align: 'left',
        textAlign: 'left',
        verticalAlign: 'center',
        fontSize: 18,
        fontWeight: 400,
        lineHeight: 1.3,
        color: muted,
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.subH,
      },
    },
  ]
}

function layoutTeamByDepartmentElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = teamByDepartmentGeom(canvasW, canvasH)
  const headingColor = (palette && (palette.heading || palette.text)) || '#1F2937'
  const muted = (palette && palette.muted) || '#6B7280'
  const accent = (palette && (palette.primary || palette.accent)) || '#4F6F6A'
  const shades = deptShades(accent)

  const stripped = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || '')))
  const memberBoxes = g.depts.flatMap((d) => d.members)

  let next = stripped.flatMap((el) => {
    const sid = String(el.slotId || '').toUpperCase()
    if (el.type === 'icon' || el.kind === 'icon' || el.type === 'shape') return []
    if (sid === 'HEADING') {
      return [place(el, {
        x: g.padX,
        y: g.headingY,
        w: Math.round(canvasW * 0.55),
        h: g.headingH,
      }, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 36,
        fontWeight: 800,
        lineHeight: 1.1,
        color: headingColor,
        text: filledText(el, 'Team by department'),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      })]
    }
    if (sid === 'SUBHEADING') {
      return [place(el, {
        x: g.padX,
        y: g.subY,
        w: Math.round(720 * (canvasW / 1920)),
        h: g.subH,
      }, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 18,
        fontWeight: 400,
        lineHeight: 1.3,
        color: muted,
        text: filledText(el, SAMPLE_SUBHEADING),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.subH,
      })]
    }
    const deptMatch = sid.match(/^DEPT_([123])_HEADING$/)
    if (deptMatch) {
      const di = Number(deptMatch[1]) - 1
      return [place(el, g.depts[di].heading, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 20,
        fontWeight: 800,
        lineHeight: 1.15,
        color: headingColor,
        text: filledText(el, SAMPLE_DEPTS[di]),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.depts[di].heading.h,
      })]
    }
    const memberMatch = sid.match(/^MEMBER_([1-6])_(IMAGE|NAME|ROLE|EMAIL|BIO|BODY|DESC)$/)
    if (!memberMatch) return []
    const memberIndex = Number(memberMatch[1]) - 1
    const m = memberBoxes[memberIndex]
    const sample = SAMPLE_MEMBERS[memberIndex]
    const field = memberMatch[2]
    if (!m || field === 'EMAIL' || field === 'BIO' || field === 'BODY' || field === 'DESC') return []
    if (field === 'IMAGE') {
      return [place(el, m.img, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: 999,
        clipPath: 'circle(50% at 50% 50%)',
        imageMask: { type: 'circle' },
      }, 10)]
    }
    if (field === 'NAME') {
      return [place(el, m.name, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 20,
        fontWeight: 800,
        lineHeight: 1.15,
        color: headingColor,
        text: filledText(el, sample.name),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.nameH,
      }, 18)]
    }
    return [place(el, m.role, {
      align: 'left',
      verticalAlign: 'top',
      fontSize: 15,
      fontWeight: 500,
      lineHeight: 1.25,
      color: shades[Math.floor(memberIndex / 2)],
      text: filledText(el, sample.role),
      padding: 0,
      wrap: 'nowrap',
      clipToSlot: false,
      slotMaxHeight: g.roleH,
    }, 18)]
  })

  next = injectSubheading(next, g, muted)

  const deco = []
  g.depts.forEach((d, di) => {
    const tint = shades[di]
    deco.push({
      id: `shp-team-dept-bar-${di + 1}`,
      type: 'shape',
      layer: 4,
      role: 'decoration',
      slotId: `TEAM_DEPT_BAR_${di + 1}`,
      placement: {
        x: d.bar.x,
        y: d.bar.y,
        width: d.bar.w,
        height: d.bar.h,
        rotation: 0,
        opacity: 1,
      },
      content: { shape: 'rect', fill: tint, borderRadius: 0 },
    })
    d.members.forEach((m, ri) => {
      const n = di * 2 + ri + 1
      deco.push({
        id: `shp-team-dept-pill-${n}`,
        type: 'shape',
        layer: 5,
        role: 'decoration',
        slotId: `TEAM_DEPT_PILL_${n}`,
        placement: {
          x: m.pill.x,
          y: m.pill.y,
          width: m.pill.w,
          height: m.pill.h,
          rotation: 0,
          opacity: 1,
        },
        content: {
          shape: 'rect',
          fill: mixHex(tint, '#ffffff', 0.9),
          stroke: mixHex(tint, '#94A3B8', 0.35),
          strokeWidth: 1.5,
          borderRadius: g.cardRadius,
          shadow: '0 8px 20px rgba(15, 23, 42, 0.08)',
        },
      })
      deco.push({
        id: `shp-team-dept-ring-${n}`,
        type: 'shape',
        layer: 8,
        role: 'decoration',
        slotId: `TEAM_DEPT_RING_${n}`,
        placement: {
          x: m.ring.x,
          y: m.ring.y,
          width: m.ring.w,
          height: m.ring.h,
          rotation: 0,
          opacity: 1,
        },
        content: { shape: 'circle', fill: '#FFFFFF', borderRadius: 999 },
      })
    })
  })

  return [...deco, ...next]
}

function layoutTeamByDepartment(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  const palette = themeTokens?.palette || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTeamByDepartmentElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTeamByDepartmentLayout,
  layoutTeamByDepartment,
}

