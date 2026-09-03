/** Team org simple: left title, circular portraits, colored rings, name + designation only. */

const TEAM_DECO = /^TEAM_ORG_(HALO|RING|LINE)_/i
const LEGACY_ORG_LABELS = /^(organization|team structure|ceo|engineering|product|design|sales|marketing|ops)$/i
const SAMPLE_HEADING = 'Team Structure'
const SAMPLE_MEMBERS = [
  { name: 'Jonas', role: 'Designation' },
  { name: 'Maria', role: 'Designation' },
  { name: 'Harry', role: 'Designation' },
  { name: 'Warner', role: 'Designation' },
  { name: 'Zenda', role: 'Designation' },
  { name: 'Tony', role: 'Designation' },
  { name: 'Peter', role: 'Designation' },
]
const BRANCH_HEX = ['#5BA3E0', '#F08A3A', '#8B6BC9']
const LEAD_HEX = '#E85A3C'

function filledText(el, fallback) {
  const t = String(el?.content?.text || '').replace(/\s+/g, ' ').trim()
  if (!t || LEGACY_ORG_LABELS.test(t) || /^(double[- ]click to edit|click to (add|edit)|enter (your )?(sub[- ]?headline|text)|founder name)$/i.test(t)) {
    return fallback
  }
  return t
}

function isTeamOrgSimpleLayout(layoutId) {
  return /team_org_simple_v1/i.test(String(layoutId || ''))
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
  const A = parseHex(a) || [232, 90, 60]
  const B = parseHex(b) || [255, 255, 255]
  return toHex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t)
}

function circleBox(cx, cy, d) {
  const size = Math.round(d)
  return {
    x: Math.round(cx - size / 2),
    y: Math.round(cy - size / 2),
    w: size,
    h: size,
  }
}

function branchColor(i, accent) {
  const base = BRANCH_HEX[i] || BRANCH_HEX[0]
  return mixHex(base, accent, 0.12)
}

function teamOrgSimpleGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const s = Math.min(sx, sy)
  const padX = Math.round(72 * sx)
  const padY = Math.round(48 * sy)
  const headingW = Math.round(470 * sx)
  const headingH = Math.round(128 * sy)
  const headingSize = Math.round(42 * s)
  const nameH = Math.round(36 * sy)
  const roleH = Math.round(28 * sy)
  const nameSize = Math.round(20 * s)
  const roleSize = Math.round(15 * s)
  const textGap = Math.round(12 * sy)
  const labelBlock = textGap + nameH + Math.round(4 * sy) + roleH
  const ringExtra = Math.round(22 * s)
  const leadD = Math.round(200 * s)
  const nodeD = Math.round(176 * s)
  const leadR = leadD / 2
  const nodeR = nodeD / 2
  const chartGap = Math.round(64 * sx)
  const leadCx = padX + headingW + chartGap + leadR
  const lastCx = canvasW - Math.round(72 * sx) - nodeR
  const colGap = (lastCx - leadCx) / 2
  const topLimit = padY + nodeR + Math.round(ringExtra / 2)
  const bottomLimit = canvasH - padY - nodeR - labelBlock
  const leadCy = Math.round((topLimit + bottomLimit) / 2)
  const rowGap = (bottomLimit - topLimit) / 2
  const heading = {
    x: padX,
    y: Math.round(leadCy - headingH / 2),
    w: headingW,
    h: headingH,
  }

  const centers = [
    { cx: leadCx, cy: leadCy, d: leadD, r: leadR, branch: -1 },
    { cx: leadCx + colGap, cy: leadCy - rowGap, d: nodeD, r: nodeR, branch: 0 },
    { cx: leadCx + colGap * 2, cy: leadCy - rowGap, d: nodeD, r: nodeR, branch: 0 },
    { cx: leadCx + colGap, cy: leadCy, d: nodeD, r: nodeR, branch: 1 },
    { cx: leadCx + colGap * 2, cy: leadCy, d: nodeD, r: nodeR, branch: 1 },
    { cx: leadCx + colGap, cy: leadCy + rowGap, d: nodeD, r: nodeR, branch: 2 },
    { cx: leadCx + colGap * 2, cy: leadCy + rowGap, d: nodeD, r: nodeR, branch: 2 },
  ]

  const nodes = centers.map((n) => {
    const photo = circleBox(n.cx, n.cy, n.d)
    const halo = circleBox(n.cx, n.cy, n.d + Math.round(12 * s))
    const ring = circleBox(n.cx, n.cy, n.d + ringExtra)
    const textW = Math.round(Math.min(n.d + Math.round(72 * sx), Math.max(200 * sx, n.d * 1.15)))
    const name = {
      x: Math.round(n.cx - textW / 2),
      y: Math.round(n.cy + n.r + textGap),
      w: textW,
      h: nameH,
    }
    const role = {
      x: name.x,
      y: name.y + nameH + Math.round(4 * sy),
      w: textW,
      h: roleH,
    }
    return { ...n, photo, halo, ring, name, role }
  })

  return {
    canvasW,
    canvasH,
    headingH,
    headingSize,
    nameH,
    nameSize,
    roleH,
    roleSize,
    heading,
    nodes,
    curveNudge: Math.round(Math.max(18, rowGap * 0.07)),
    stroke: Math.max(3, Math.round(4.5 * s)),
    ringStroke: Math.max(8, Math.round(11 * s)),
    dot: Math.max(4, Math.round(6 * s)),
  }
}

function orgConnectorsSvg(g, leadColor, branchColors) {
  const lead = g.nodes[0]
  const startX = lead.cx + lead.r
  const branches = [
    { l2: 1, l3: 2, color: branchColors[0], curve: -1 },
    { l2: 3, l3: 4, color: branchColors[1], curve: 0 },
    { l2: 5, l3: 6, color: branchColors[2], curve: 1 },
  ]
  const parts = []
  const sw = g.stroke
  const dr = g.dot
  branches.forEach((b, i) => {
    const a = g.nodes[b.l2]
    const c = g.nodes[b.l3]
    const y0 = lead.cy + b.curve * g.curveNudge
    const x1 = a.cx - a.r
    const x2 = a.cx + a.r
    const x3 = c.cx - c.r
    if (b.curve === 0) {
      parts.push(`<path d="M ${startX} ${lead.cy} L ${x1} ${a.cy}" fill="none" stroke="${b.color}" stroke-width="${sw}" stroke-linecap="round"/>`)
    } else {
      const cpx = startX + (x1 - startX) * 0.42
      const cpy = a.cy
      parts.push(`<path d="M ${startX} ${y0} Q ${cpx} ${cpy} ${x1} ${a.cy}" fill="none" stroke="${b.color}" stroke-width="${sw}" stroke-linecap="round"/>`)
    }
    parts.push(`<path d="M ${x2} ${a.cy} L ${x3} ${c.cy}" fill="none" stroke="${b.color}" stroke-width="${sw}" stroke-linecap="round"/>`)
    const dots = [
      [startX, b.curve === 0 ? lead.cy : y0],
      [x1, a.cy],
      [x2, a.cy],
      [x3, c.cy],
    ]
    dots.forEach(([dx, dy]) => {
      parts.push(`<circle cx="${dx}" cy="${dy}" r="${dr}" fill="#ffffff" stroke="${i === 0 && dx === startX ? leadColor : b.color}" stroke-width="${Math.max(2, sw * 0.6)}"/>`)
    })
  })
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.canvasW} ${g.canvasH}" width="${g.canvasW}" height="${g.canvasH}">${parts.join('')}</svg>`
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

function memberIndex(sid) {
  const m = String(sid || '').match(/MEMBER_(\d+)/i)
  if (!m) return -1
  return Number.parseInt(m[1], 10) - 1
}

function layoutTeamOrgSimpleElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = teamOrgSimpleGeom(canvasW, canvasH)
  const headingColor = (palette && (palette.heading || palette.text)) || '#374151'
  const muted = (palette && palette.muted) || '#9CA3AF'
  const accent = (palette && (palette.primary || palette.accent)) || LEAD_HEX
  const leadColor = mixHex(LEAD_HEX, accent, 0.18)
  const branchColors = [0, 1, 2].map((i) => branchColor(i, accent))

  const next = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || ''))).flatMap((el) => {
    const sid = String(el.slotId || '').toUpperCase()
    if (el.type === 'icon' || el.kind === 'icon' || el.type === 'shape') return []
    if (/_EMAIL$|_BIO$|_BODY$|_DESC$/i.test(sid)) return []
    if (sid === 'HEADING') {
      return [place(el, g.heading, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: g.headingSize,
        fontWeight: 800,
        letterSpacing: -0.2,
        lineHeight: 1.12,
        color: headingColor,
        text: filledText(el, SAMPLE_HEADING).replace(/^team structure$/i, 'Team\nStructure'),
        padding: 0,
        wrap: 'pre-wrap',
        wordBreak: 'keep-all',
        overflowWrap: 'normal',
        hyphens: 'none',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      })]
    }
    const idx = memberIndex(sid)
    const node = idx >= 0 ? g.nodes[idx] : null
    const sample = idx >= 0 ? SAMPLE_MEMBERS[idx] : null
    if (node && (/_IMAGE$/.test(sid) || (el.type === 'image' && idx >= 0))) {
      return [place(el, node.photo, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: 999,
        clipPath: 'circle(50% at 50% 50%)',
        imageMask: { type: 'circle' },
      }, 10)]
    }
    if (node && /_NAME$/.test(sid)) {
      return [place(el, node.name, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: g.nameSize,
        fontWeight: 800,
        lineHeight: 1.15,
        color: headingColor,
        text: filledText(el, sample.name),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.nameH,
      })]
    }
    if (node && /_ROLE$/.test(sid)) {
      return [place(el, node.role, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: g.roleSize,
        fontWeight: 400,
        lineHeight: 1.2,
        color: muted,
        text: filledText(el, sample.role),
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.roleH,
      })]
    }
    return []
  })

  for (let i = 0; i < g.nodes.length; i += 1) {
    const n = i + 1
    const node = g.nodes[i]
    const sample = SAMPLE_MEMBERS[i]
    const has = (suffix) => next.some((el) => String(el.slotId || '').toUpperCase() === `MEMBER_${n}_${suffix}`)
    if (!has('IMAGE')) {
      next.push(place({
        id: `img-team-org-${n}`,
        type: 'image',
        slotId: `MEMBER_${n}_IMAGE`,
        role: 'image',
        content: {},
      }, node.photo, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: 999,
        clipPath: 'circle(50% at 50% 50%)',
        imageMask: { type: 'circle' },
      }, 10))
    }
    if (!has('NAME')) {
      next.push(place({
        id: `txt-team-org-name-${n}`,
        type: 'text',
        slotId: `MEMBER_${n}_NAME`,
        role: 'heading',
        content: {},
      }, node.name, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: g.nameSize,
        fontWeight: 800,
        lineHeight: 1.15,
        color: headingColor,
        text: sample.name,
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.nameH,
      }))
    }
    if (!has('ROLE')) {
      next.push(place({
        id: `txt-team-org-role-${n}`,
        type: 'text',
        slotId: `MEMBER_${n}_ROLE`,
        role: 'caption',
        content: {},
      }, node.role, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: g.roleSize,
        fontWeight: 400,
        lineHeight: 1.2,
        color: muted,
        text: sample.role,
        padding: 0,
        wrap: 'nowrap',
        clipToSlot: false,
        slotMaxHeight: g.roleH,
      }))
    }
  }

  const deco = [
    {
      id: 'shp-team-org-lines',
      type: 'graphic',
      layer: 4,
      role: 'decoration',
      slotId: 'TEAM_ORG_LINE_1',
      placement: {
        x: 0,
        y: 0,
        width: canvasW,
        height: canvasH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: orgConnectorsSvg(g, leadColor, branchColors),
        colorMode: 'original',
        alt: 'Team structure connectors',
      },
    },
  ]

  g.nodes.forEach((node, i) => {
    const color = node.branch < 0 ? leadColor : branchColors[node.branch]
    deco.push(decoShape(`shp-team-org-halo-${i + 1}`, `TEAM_ORG_HALO_${i + 1}`, node.halo, 6, {
      shape: 'circle',
      fill: '#FFFFFF',
      borderRadius: 999,
    }))
    deco.push(decoShape(`shp-team-org-ring-${i + 1}`, `TEAM_ORG_RING_${i + 1}`, node.ring, 7, {
      shape: 'circle',
      variant: 'outlined',
      fill: 'transparent',
      stroke: color,
      strokeWidth: g.ringStroke,
      borderRadius: 999,
    }))
  })

  return [...deco, ...next]
}

function layoutTeamOrgSimple(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc
  const palette = themeTokens?.palette || {}
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  }
  return { ...doc, elements: layoutTeamOrgSimpleElements(doc.elements || [], layoutSchema, palette, size) }
}

module.exports = {
  isTeamOrgSimpleLayout,
  layoutTeamOrgSimple,
}
