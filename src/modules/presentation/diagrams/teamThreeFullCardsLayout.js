/** Team three full cards: centered heading, three square photos, name/role/email under each. */

const TEAM_DECO = /^TEAM_FULL_(CARD|FRAME)_/i
const SAMPLE_MEMBERS = [
  { name: 'Johanna Doe', role: 'Co-founder & CEO', email: 'johanna@example.com' },
  { name: 'Jane Doe', role: 'Co-founder & CTO', email: 'jane@example.com' },
  { name: 'Joe Doe', role: 'Co-founder & COO', email: 'joe@example.com' },
]

function filledText(el, fallback) {
  const t = String(el?.content?.text || '').replace(/\s+/g, ' ').trim()
  if (!t || /^(double[- ]click to edit|click to (add|edit)|enter (your )?(sub[- ]?headline|text))/i.test(t)) return fallback
  return t
}

function isTeamThreeFullCardsLayout(layoutId) {
  return /team_three_full_cards_v1/i.test(String(layoutId || ''))
}

function teamThreeFullCardsGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const padX = Math.round(88 * sx)
  const gap = Math.round(72 * sx)
  const widthImg = Math.round((canvasW - padX * 2 - gap * 2) / 3)
  const headingH = Math.round(52 * sy)
  const gapAfterHeading = Math.round(36 * sy)
  const nameH = Math.round(42 * sy)
  const roleH = Math.round(32 * sy)
  const emailH = Math.round(36 * sy)
  const gapImgText = Math.round(18 * sy)
  const gapText = Math.round(6 * sy)
  const textBlockH = nameH + gapText + roleH + gapText + emailH
  const topPad = Math.round(48 * sy)
  const bottomPad = Math.round(48 * sy)
  const headingY = topPad
  const maxImg = canvasH - headingY - headingH - gapAfterHeading - gapImgText - textBlockH - bottomPad
  const imgSize = Math.max(Math.round(280 * Math.min(sx, sy)), Math.min(widthImg, maxImg))
  const colW = imgSize
  const innerPadX = Math.round((canvasW - imgSize * 3 - gap * 2) / 2)
  const afterHeading = headingY + headingH + gapAfterHeading
  const cardStackH = imgSize + gapImgText + textBlockH
  const restH = canvasH - afterHeading - bottomPad
  const groupY = afterHeading + Math.max(0, Math.round((restH - cardStackH) / 2))
  const radius = Math.round(28 * Math.min(sx, sy))
  const cols = [0, 1, 2].map((i) => innerPadX + i * (colW + gap))

  const rows = cols.map((x) => {
    const imgY = groupY
    const nameY = imgY + imgSize + gapImgText
    const roleY = nameY + nameH + gapText
    const emailY = roleY + roleH + gapText
    return {
      img: { x, y: imgY, w: imgSize, h: imgSize },
      name: { x, y: nameY, w: colW, h: nameH },
      role: { x, y: roleY, w: colW, h: roleH },
      email: { x, y: emailY, w: colW, h: emailH },
    }
  })

  return {
    padX: innerPadX,
    headingY,
    headingH,
    nameH,
    roleH,
    emailH,
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

function injectEmails(next, g, muted) {
  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()))
  const extras = []
  for (let n = 1; n <= 3; n += 1) {
    if (have.has(`MEMBER_${n}_EMAIL`)) continue
    const m = g.rows[n - 1]
    extras.push({
      id: `txt-team-full-email-${n}`,
      type: 'text',
      layer: 18,
      role: 'caption',
      slotId: `MEMBER_${n}_EMAIL`,
      placement: {
        x: m.email.x,
        y: m.email.y,
        width: m.email.w,
        height: m.email.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: SAMPLE_MEMBERS[n - 1].email,
        align: 'left',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 400,
        lineHeight: 1.25,
        color: muted,
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.emailH,
      },
    })
  }
  return extras.length ? [...next, ...extras] : next
}

function layoutTeamThreeFullCardsElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = teamThreeFullCardsGeom(canvasW, canvasH)
  const headingColor = (palette && (palette.heading || palette.text)) || '#111827'
  const muted = (palette && palette.muted) || '#6B7280'

  const stripped = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || '')))
  let next = stripped.flatMap((el) => {
    const sid = String(el.slotId || '').toUpperCase()
    if (el.type === 'icon' || el.kind === 'icon' || el.type === 'shape') return []
    if (sid === 'HEADING') {
      return [place(el, {
        x: g.padX,
        y: g.headingY,
        w: canvasW - g.padX * 2,
        h: g.headingH,
      }, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 32,
        fontWeight: 800,
        lineHeight: 1.1,
        color: headingColor,
        text: filledText(el, 'Meet the team'),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      })]
    }

    const memberMatch = sid.match(/^MEMBER_([123])_(IMAGE|NAME|ROLE|EMAIL|BIO|BODY|DESC)$/)
    if (!memberMatch) return []
    const memberIndex = Number(memberMatch[1]) - 1
    const m = g.rows[memberIndex]
    const sample = SAMPLE_MEMBERS[memberIndex]
    const field = memberMatch[2]
    if (field === 'BIO' || field === 'BODY' || field === 'DESC') return []

    if (field === 'IMAGE') {
      return [place(el, m.img, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: g.radius,
      }, 8)]
    }
    if (field === 'NAME') {
      return [place(el, m.name, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 22,
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
    if (field === 'ROLE') {
      return [place(el, m.role, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 400,
        lineHeight: 1.25,
        color: muted,
        text: filledText(el, sample.role),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.roleH,
      }, 18)]
    }
    return [place(el, m.email, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 16,
      fontWeight: 400,
      lineHeight: 1.25,
      color: muted,
      text: filledText(el, sample.email),
      padding: 0,
      wrap: 'nowrap',
      clipToSlot: false,
      slotMaxHeight: g.emailH,
    }, 18)]
  })

  return injectEmails(next, g, muted)
}

function layoutTeamThreeFullCards(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  const palette = themeTokens?.palette || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTeamThreeFullCardsElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTeamThreeFullCardsLayout,
  layoutTeamThreeFullCards,
}
