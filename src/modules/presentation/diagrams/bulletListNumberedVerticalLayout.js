/**
 * Bullet List Numbered Vertical Layout Engine
 * Layout IDs: bullet_list_numbered_vertical_v1
 *
 * 6-step curved block list:
 *  - Left chevron icon tabs (staggered down-right)
 *  - Soft pastel bars with a matching diagonal join
 *  - Title + body + 01–06 on the right
 */

const BULLET_LIST_NUMBERED_VERTICAL_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 48,
  headingY: 18,
  headingW: 904,
  headingH: 36,
  rowStartY: 64,
  rowH: 70,
  rowGap: 7,
  stagger: 30,
  baseX: 44,
  right: 956,
  tabW: 76,
  slant: 18,
  tabGap: 7,
  radius: 18,
}

const BULLET_LIST_NUMBERED_VERTICAL_ROWS = [
  { fill: '#2F4F86', icon: 'bulb' },
  { fill: '#F0A12A', icon: 'gears' },
  { fill: '#E45B4C', icon: 'pulse' },
  { fill: '#4CAF50', icon: 'target' },
  { fill: '#2EC4D6', icon: 'user' },
  { fill: '#D94A7A', icon: 'hourglass' },
]

const BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS = {
  HEADING: '6-Step Curved Block List',
  TITLE: 'Lorem Ipsum',
  ITEM: 'Lorem ipsum dolor sit amet, nibh est. A magna maecenas, quam magna nec quis.',
}

function isBulletListNumberedVerticalLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return id === 'bullet_list_numbered_vertical_v1' || id === 'bullet_list_numbered_vertical'
}

function rowY(index) {
  const g = BULLET_LIST_NUMBERED_VERTICAL_GEOM
  return g.rowStartY + index * (g.rowH + g.rowGap)
}

function rowX(index) {
  const g = BULLET_LIST_NUMBERED_VERTICAL_GEOM
  return g.baseX + index * g.stagger
}

function escapeXml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
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

function verticalRowIcon(kind) {
  switch (kind) {
    case 'gears':
      return `<circle cx="10" cy="12" r="3.2" fill="none" stroke="#FFFFFF" stroke-width="1.8" /><circle cx="15.5" cy="14.2" r="2.4" fill="none" stroke="#FFFFFF" stroke-width="1.8" /><circle cx="10" cy="12" r="1.1" fill="#FFFFFF" /><circle cx="15.5" cy="14.2" r="0.8" fill="#FFFFFF" />`
    case 'pulse':
      return `<path d="M4 13h3l2-5 3 10 2-5h6" fill="none" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />`
    case 'target':
      return `<circle cx="12" cy="12" r="7" fill="none" stroke="#FFFFFF" stroke-width="1.8" /><circle cx="12" cy="12" r="3.6" fill="none" stroke="#FFFFFF" stroke-width="1.8" /><circle cx="12" cy="12" r="1.3" fill="#FFFFFF" />`
    case 'user':
      return `<circle cx="12" cy="9" r="3.2" fill="none" stroke="#FFFFFF" stroke-width="1.8" /><path d="M6.5 19c.8-3.4 2.8-5 5.5-5s4.7 1.6 5.5 5" fill="none" stroke="#FFFFFF" stroke-width="1.8" stroke-linecap="round" />`
    case 'hourglass':
      return `<path d="M8 5h8M8 19h8M8 5c0 4 2.2 5.2 4 7 1.8 1.8 4 3 4 7M8 19c0-4 2.2-5.2 4-7" fill="none" stroke="#FFFFFF" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />`
    case 'bulb':
    default:
      return `<path d="M9.2 20h5.6M10 16.6h4M12 4.2a5.2 5.2 0 0 0-3.1 9.4c.6.5 1 1.2 1.1 1.9h4c.1-.7.5-1.4 1.1-1.9A5.2 5.2 0 0 0 12 4.2z" fill="none" stroke="#FFFFFF" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />`
  }
}

function buildVerticalBlockRowSvg({
  width,
  height,
  tabW,
  slant,
  tabGap,
  radius,
  icon,
  number,
  includeCopy = false,
  title = '',
  bodyLines = [],
}) {
  const h = height
  const r = Math.min(radius, h / 2)
  const tabRight = tabW
  const barX = tabW + tabGap
  const barW = width - barX
  const iconSize = Math.round(h * 0.42)
  const iconCx = tabW * 0.42
  const iconS = iconSize / 24
  const numSize = Math.round(h * 0.42)

  const tabPath = `M ${r} 0 H ${tabRight} L ${tabRight + slant} ${h / 2} L ${tabRight} ${h} H ${r} Q 0 ${h} 0 ${h - r} V ${r} Q 0 0 ${r} 0 Z`
  const barPath = `M ${barX + slant} 0 H ${barX + barW - r} Q ${barX + barW} 0 ${barX + barW} ${r} V ${h - r} Q ${barX + barW} ${h} ${barX + barW - r} ${h} H ${barX + slant} L ${barX} ${h / 2} Z`

  const copySvg = includeCopy
    ? `
      ${bodyLines
        .map(
          (line, i) =>
            `<text x="${barX + slant + 16}" y="${Math.round(h * 0.62) + i * 12}" fill="currentColor" fill-opacity="0.62" font-size="11" font-weight="400" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`
        )
        .join('\n')}
      <text x="${width - 78}" y="${Math.round(h * 0.4)}" text-anchor="end" fill="currentColor" font-size="13" font-weight="800" font-family="Inter, Arial, sans-serif">${escapeXml(title)}</text>
    `
    : ''

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%" overflow="visible">
    <path d="${barPath}" fill="currentColor" fill-opacity="0.22" pointer-events="all" />
    <path d="${tabPath}" fill="currentColor" pointer-events="all" />
    <g transform="translate(${iconCx - iconSize / 2}, ${h / 2 - iconSize / 2}) scale(${iconS})" pointer-events="none">${verticalRowIcon(icon)}</g>
    <text x="${width - 22}" y="${h / 2}" dy="0.35em" text-anchor="end" fill="currentColor" font-size="${numSize}" font-weight="800" font-family="Inter, Arial, sans-serif" pointer-events="none">${number}</text>
    ${copySvg}
  </svg>`
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill
  if (fill && typeof fill === 'object' && fill.color) return fill.color
  const stroke = el?.content?.stroke
  if (typeof stroke === 'string' && stroke) return stroke
  return fallback
}

function stripListPrefix(text) {
  return String(text || '')
    .replace(/^\s*(?:[•●▪–—-]|\d+[.)]|0\d)\s+/u, '')
    .trim()
}

function layoutBulletListNumberedVertical(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const g = BULLET_LIST_NUMBERED_VERTICAL_GEOM
  const scaleX = canvasW / g.viewW
  const scaleY = canvasH / g.viewH

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => {
      const sid = String(e.slotId || '').toUpperCase()
      return matcher(sid)
    })
    const txt = el?.content?.text || el?.text || el?.content?.heading || el?.content?.title
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const heading = findText(
    (s) => s === 'HEADING' || s === 'TITLE' || s === 'MAIN_TITLE',
    BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS.HEADING
  )

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
      layer: 10,
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
        colorMode: config.colorMode || 'recolorable',
        fill: config.fill,
        stroke: config.stroke || config.fill,
      },
    })
  }

  pushGraphic({
    id: 'blnv_bg',
    slotId: 'SLIDE_BG',
    layer: 0,
    x: 0,
    y: 0,
    width: canvasW,
    height: canvasH,
    colorMode: 'fixed',
    fill: '#F4F5F7',
    svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${canvasW} ${canvasH}"><rect width="100%" height="100%" fill="#F4F5F7" /></svg>`,
  })

  pushText({
    id: 'blnv_heading',
    slotId: 'HEADING',
    role: 'caption',
    text: heading,
    x: g.headingX * scaleX,
    y: g.headingY * scaleY,
    width: g.headingW * scaleX,
    height: g.headingH * scaleY,
    fontSize: 24,
    fontWeight: 800,
    color: '#111827',
    maxLines: 1,
  })

  for (let i = 0; i < 6; i += 1) {
    const theme = BULLET_LIST_NUMBERED_VERTICAL_ROWS[i]
    const x = rowX(i)
    const y = rowY(i)
    const w = g.right - x
    const h = g.rowH
    const slotId = `ROW_${i + 1}`
    const prev = elements.find((e) => String(e.slotId || '').toUpperCase() === slotId)
    const color = resolveStoredColor(prev, theme.fill)
    const title = findText((s) => s === `TITLE_${i + 1}` || s === `HEADING_${i + 1}`, '') ||
      BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS.TITLE
    const itemRaw = findText((s) => s === `ITEM_${i + 1}` || s === `BODY_${i + 1}`, '')
    const item = itemRaw ? stripListPrefix(itemRaw) : BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS.ITEM

    pushGraphic({
      id: prev?.id || `blnv_row_${i + 1}`,
      slotId,
      layer: 2,
      x: x * scaleX,
      y: y * scaleY,
      width: w * scaleX,
      height: h * scaleY,
      fill: color,
      stroke: color,
      svg: buildVerticalBlockRowSvg({
        width: w,
        height: h,
        tabW: g.tabW,
        slant: g.slant,
        tabGap: g.tabGap,
        radius: g.radius,
        icon: theme.icon,
        number: String(i + 1).padStart(2, '0'),
      }),
    })

    const barLeft = x + g.tabW + g.tabGap + g.slant + 14
    pushText({
      id: `blnv_item_${i + 1}`,
      slotId: `ITEM_${i + 1}`,
      role: 'body',
      text: item,
      x: barLeft * scaleX,
      y: (y + h * 0.42) * scaleY,
      width: (w - g.tabW - g.tabGap - g.slant - 150) * scaleX,
      height: (h * 0.48) * scaleY,
      fontSize: 11,
      fontWeight: 400,
      color: color,
      lineHeight: 1.25,
      maxLines: 2,
    })

    pushText({
      id: `blnv_title_${i + 1}`,
      slotId: `TITLE_${i + 1}`,
      role: 'body',
      text: title,
      x: (x + w - 168) * scaleX,
      y: (y + 8) * scaleY,
      width: 92 * scaleX,
      height: 22 * scaleY,
      fontSize: 13,
      fontWeight: 800,
      color: color,
      align: 'right',
      maxLines: 1,
    })
  }

  if (Array.isArray(docOrElements)) return outElements
  return { ...docOrElements, elements: outElements }
}

function bulletListNumberedVerticalPreviewSvg() {
  const g = BULLET_LIST_NUMBERED_VERTICAL_GEOM
  const rows = BULLET_LIST_NUMBERED_VERTICAL_ROWS.map((theme, i) => {
    const x = rowX(i)
    const y = rowY(i)
    const w = g.right - x
    const inner = buildVerticalBlockRowSvg({
      width: w,
      height: g.rowH,
      tabW: g.tabW,
      slant: g.slant,
      tabGap: g.tabGap,
      radius: g.radius,
      icon: theme.icon,
      number: String(i + 1).padStart(2, '0'),
      includeCopy: true,
      title: BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS.TITLE,
      bodyLines: wrapLines(BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS.ITEM, 52, 1),
    }).replace(/^<svg[^>]*>/, '').replace(/<\/svg>$/, '')
    return `<g transform="translate(${x}, ${y})" color="${theme.fill}">${inner}</g>`
  }).join('\n')

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    <rect width="100%" height="100%" fill="#F4F5F7" />
    <text x="${g.headingX}" y="${g.headingY + 26}" fill="#111827" font-size="24" font-weight="800" font-family="Inter, Arial, sans-serif">${BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS.HEADING}</text>
    ${rows}
  </svg>`
}

module.exports = {
  BULLET_LIST_NUMBERED_VERTICAL_GEOM,
  BULLET_LIST_NUMBERED_VERTICAL_ROWS,
  BULLET_LIST_NUMBERED_VERTICAL_DEFAULTS,
  isBulletListNumberedVerticalLayout,
  buildVerticalBlockRowSvg,
  layoutBulletListNumberedVertical,
  bulletListNumberedVerticalPreviewSvg,
};
