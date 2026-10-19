/**
 * Bullet List Dense Layout Engine (Frontend)
 * Layout IDs: bullet_list_dense_v1, bullet_list_dense
 *
 * Compact 5-row chevron list matching the PPT reference:
 *  - Small orange title
 *  - Five thin color bars
 *  - Darker left chevron tab with a unique icon per row
 *  - Small white body copy clipped inside each bar
 */

const BULLET_LIST_DENSE_GEOM = {
  viewW: 1000,
  viewH: 560,

  headingX: 52,
  headingY: 26,
  headingW: 896,
  headingH: 32,

  barX: 52,
  barW: 896,
  barH: 78,
  barGap: 10,
  barStartY: 72,
  barRadius: 10,
  numW: 82,
  chevron: 16,
}

const BULLET_LIST_DENSE_BARS = [
  { fill: '#FF8A1A', numFill: '#E07010', icon: 'check' },
  { fill: '#E53935', numFill: '#C62828', icon: 'bulb' },
  { fill: '#43A047', numFill: '#2E7D32', icon: 'target' },
  { fill: '#C6D32F', numFill: '#9EAE14', icon: 'star' },
  { fill: '#26A69A', numFill: '#00897B', icon: 'chart' },
]

const BULLET_LIST_DENSE_DEFAULTS = {
  HEADING: '5 BULLET POINTS',
  ITEM:
    'You can easily replace this text with your own text. You can easily replace this text with your own text.',
}

function isBulletListDenseLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return id === 'bullet_list_dense_v1' || id === 'bullet_list_dense'
}

function barY(index) {
  const { barStartY, barH, barGap } = BULLET_LIST_DENSE_GEOM
  return barStartY + index * (barH + barGap)
}

function wrapLines(text, maxChars, maxLines) {
  const words = String(text || '').split(/\s+/).filter(Boolean)
  const lines = []
  let current = ''
  words.forEach((word) => {
    const next = current ? `${current} ${word}` : word
    if (next.length > maxChars && current) {
      lines.push(current)
      current = word
    } else {
      current = next
    }
  })
  if (current) lines.push(current)
  return lines.slice(0, maxLines)
}

function escapeXml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function denseBulletIconPath(kind) {
  switch (kind) {
    case 'bulb':
      return `<path d="M9 21h6M10 17h4M12 3a6 6 0 0 0-3.5 10.8c.7.6 1.1 1.4 1.2 2.2h4.6c.1-.8.5-1.6 1.2-2.2A6 6 0 0 0 12 3z" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />`
    case 'target':
      return `<circle cx="12" cy="12" r="8" fill="none" stroke="#FFFFFF" stroke-width="2" /><circle cx="12" cy="12" r="4" fill="none" stroke="#FFFFFF" stroke-width="2" /><circle cx="12" cy="12" r="1.6" fill="#FFFFFF" />`
    case 'star':
      return `<path d="M12 3.2l2.2 4.6 5 .7-3.6 3.6.9 5.1L12 15.2 7.5 17.2l.9-5.1L4.8 8.5l5-.7L12 3.2z" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linejoin="round" />`
    case 'chart':
      return `<path d="M4 19V11M10 19V7M16 19v-6M22 19H2" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />`
    case 'check':
    default:
      return `<circle cx="12" cy="12" r="8.2" fill="none" stroke="#FFFFFF" stroke-width="2" /><path d="M8.2 12.2l2.4 2.4 5.2-5.4" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" />`
  }
}

function denseBulletIconSvg(kind, cx, cy, size) {
  const s = size / 24
  return `<g transform="translate(${cx - size / 2}, ${cy - size / 2}) scale(${s})">${denseBulletIconPath(kind)}</g>`
}

/**
 * Single-row SVG: rounded bar + chevron number tab + optional body copy.
 * Body is baked in for preview; canvas overlays editable text on top of a chrome-only bar.
 */
function buildDenseBarSvg({
  width,
  height,
  radius,
  fill,
  numFill,
  icon = 'check',
  bodyLines = [],
  includeBody = false,
}) {
  const numW = Math.round(height * 1.08)
  const tip = Math.round(height * 0.22)
  const r = Math.min(radius, height / 3)
  const iconSize = Math.round(height * 0.42)
  const bodySize = Math.round(height * 0.2)
  const bodyX = numW + tip + 14
  const bodyStartY = Math.round(height * 0.38)

  const bodySvg = includeBody
    ? bodyLines
        .map(
          (line, i) =>
            `<text x="${bodyX}" y="${bodyStartY + i * Math.round(bodySize * 1.28)}" fill="#FFFFFF" font-size="${bodySize}" font-weight="600" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`
        )
        .join('\n')
    : ''

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%" preserveAspectRatio="none">
    <rect x="0" y="0" width="${width}" height="${height}" rx="${r}" fill="${fill}" />
    <path d="M ${r} 0 H ${numW} L ${numW + tip} ${height / 2} L ${numW} ${height} H ${r} Q 0 ${height} 0 ${height - r} V ${r} Q 0 0 ${r} 0 Z" fill="${numFill}" />
    ${denseBulletIconSvg(icon, Math.round(numW * 0.48), height / 2, iconSize)}
    ${bodySvg}
  </svg>`
}

function stripListPrefix(text) {
  return String(text || '')
    .replace(/^\s*(?:[•●▪–—-]|\d+[.)]|0\d)\s+/u, '')
    .trim()
}

function parseBulletLines(text) {
  return String(text || '')
    .split(/\n+/)
    .map((line) => stripListPrefix(line))
    .filter(Boolean)
}

function layoutBulletListDense(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const geom = BULLET_LIST_DENSE_GEOM
  const scaleX = canvasW / geom.viewW
  const scaleY = canvasH / geom.viewH

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => {
      const sid = String(e.slotId || '').toUpperCase()
      const role = String(e.role || '').toUpperCase()
      return matcher(sid, role)
    })
    const txt = el?.content?.text || el?.text || el?.content?.heading || el?.content?.title
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const headingRaw = findText(
    (s) => s === 'HEADING' || s === 'TITLE' || s === 'MAIN_TITLE',
    BULLET_LIST_DENSE_DEFAULTS.HEADING
  )
  const heading = String(headingRaw || BULLET_LIST_DENSE_DEFAULTS.HEADING).toUpperCase()

  const items = [1, 2, 3, 4, 5].map((n) => {
    const slotted = findText((s) => s === `ITEM_${n}` || s === `POINT_${n}` || s === `BULLET_${n}`)
    return slotted ? stripListPrefix(slotted) : ''
  })

  if (items.filter(Boolean).length < 3) {
    const blob = findText((s) => s === 'BULLETS' || s === 'BODY' || s === 'LIST')
    const lines = parseBulletLines(blob)
    for (let i = 0; i < 5; i += 1) {
      if (!items[i] && lines[i]) items[i] = lines[i]
    }
  }

  for (let i = 0; i < 5; i += 1) {
    if (!items[i]) items[i] = BULLET_LIST_DENSE_DEFAULTS.ITEM
  }

  const outElements = []

  const pushText = (config) => {
    const placement = {
      x: Math.round(config.x),
      y: Math.round(config.y),
      width: Math.max(1, Math.round(config.width)),
      height: Math.max(1, Math.round(config.height)),
      rotation: 0,
      opacity: 1,
    }
    outElements.push({
      id: config.id,
      type: 'text',
      slotId: config.slotId,
      role: config.role || 'body',
      layer: config.layer || 10,
      placement,
      rect: { ...placement },
      content: {
        text: config.text,
        fontSize: config.fontSize,
        fontWeight: config.fontWeight || 600,
        color: config.color,
        align: config.align || 'left',
        lineHeight: config.lineHeight || 1.25,
        letterSpacing: config.letterSpacing || 'normal',
        clipToSlot: true,
        maxLines: config.maxLines || 2,
      },
    })
  }

  const pushGraphic = (config) => {
    const placement = {
      x: Math.round(config.x),
      y: Math.round(config.y),
      width: Math.max(1, Math.round(config.width)),
      height: Math.max(1, Math.round(config.height)),
      rotation: 0,
      opacity: 1,
    }
    outElements.push({
      id: config.id,
      type: 'graphic',
      slotId: config.slotId,
      role: 'decoration',
      layer: config.layer || 2,
      placement,
      rect: { ...placement },
      content: {
        svg: config.svg,
        preserveAspectRatio: 'none',
      },
    })
  }

  pushGraphic({
    id: 'bld_bg',
    slotId: 'SLIDE_BG',
    layer: 0,
    x: 0,
    y: 0,
    width: canvasW,
    height: canvasH,
    svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${canvasW} ${canvasH}" width="100%" height="100%"><rect width="100%" height="100%" fill="#FFFFFF" /></svg>`,
  })

  pushText({
    id: 'bld_heading',
    slotId: 'HEADING',
    role: 'caption',
    text: heading,
    x: geom.headingX * scaleX,
    y: geom.headingY * scaleY,
    width: geom.headingW * scaleX,
    height: geom.headingH * scaleY,
    fontSize: 20,
    fontWeight: 800,
    color: '#E67E22',
    letterSpacing: '0.04em',
    maxLines: 1,
  })

  for (let i = 0; i < 5; i += 1) {
    const theme = BULLET_LIST_DENSE_BARS[i]
    const y = barY(i)
    const barW = geom.barW * scaleX
    const barH = geom.barH * scaleY
    const radius = geom.barRadius * Math.min(scaleX, scaleY)

    pushGraphic({
      id: `bld_bar_${i + 1}`,
      slotId: `BAR_${i + 1}`,
      layer: 2,
      x: geom.barX * scaleX,
      y: y * scaleY,
      width: barW,
      height: barH,
      svg: buildDenseBarSvg({
        width: Math.round(barW),
        height: Math.round(barH),
        radius: Math.max(6, radius),
        fill: theme.fill,
        numFill: theme.numFill,
        icon: theme.icon,
        includeBody: false,
      }),
    })

    const numW = barH * 1.08
    const tip = barH * 0.22
    const textH = barH * 0.64
    const fitSize = Math.max(10, Math.min(15, Math.floor(textH / (2 * 1.32))))
    pushText({
      id: `bld_item_${i + 1}`,
      slotId: `ITEM_${i + 1}`,
      role: 'body',
      text: items[i],
      x: geom.barX * scaleX + numW + tip + 12,
      y: y * scaleY + barH * 0.18,
      width: barW - numW - tip - 28,
      height: textH,
      fontSize: fitSize,
      fontWeight: 600,
      color: '#FFFFFF',
      lineHeight: 1.28,
      maxLines: 2,
    })
  }

  if (Array.isArray(docOrElements)) {
    return outElements
  }
  return { ...docOrElements, elements: outElements }
}

function bulletListDensePreviewSvg() {
  const geom = BULLET_LIST_DENSE_GEOM
  const defaults = BULLET_LIST_DENSE_DEFAULTS
  const bodyLines = wrapLines(defaults.ITEM, 54, 2)

  const bars = BULLET_LIST_DENSE_BARS.map((theme, i) => {
    const y = barY(i)
    const svg = buildDenseBarSvg({
      width: geom.barW,
      height: geom.barH,
      radius: geom.barRadius,
      fill: theme.fill,
      numFill: theme.numFill,
      icon: theme.icon,
      bodyLines,
      includeBody: true,
    })
    const inner = svg.replace(/^<svg[^>]*>/, '').replace(/<\/svg>$/, '')
    return `<g transform="translate(${geom.barX}, ${y})">${inner}</g>`
  }).join('\n')

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${geom.viewW} ${geom.viewH}" width="100%" height="100%">
    <rect width="100%" height="100%" fill="#FFFFFF" />
    <text x="${geom.headingX}" y="${geom.headingY + 22}" fill="#E67E22" font-size="20" font-weight="800" font-family="Inter, Arial, sans-serif" letter-spacing="0.04em">${defaults.HEADING}</text>
    ${bars}
  </svg>`
}

module.exports = {
  BULLET_LIST_DENSE_GEOM,
  BULLET_LIST_DENSE_BARS,
  BULLET_LIST_DENSE_DEFAULTS,
  isBulletListDenseLayout,
  buildDenseBarSvg,
  layoutBulletListDense,
  bulletListDensePreviewSvg,
};
