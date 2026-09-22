/**
 * Bullet List Split Layout Engine
 * Layout IDs: bullet_list_split_v1, bullet_list_split
 *
 * Two independent column cards (not one shared panel):
 *  - Slide heading
 *  - Left card with its own header, icon, title, and bullets
 *  - Right card with a different accent, icon, title, and bullets
 */

const BULLET_LIST_SPLIT_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 52,
  headingY: 24,
  headingW: 896,
  headingH: 40,
  cardY: 84,
  cardH: 436,
  cardW: 436,
  cardGap: 24,
  cardX: 52,
  radius: 18,
  headerH: 72,
  rows: 6,
  rowGap: 48,
  listStart: 96,
  dotX: 28,
  textX: 48,
}

const BULLET_LIST_SPLIT_CARDS = [
  { fill: '#148A80', icon: 'list' },
  { fill: '#2F4F86', icon: 'flag' },
]

const BULLET_LIST_SPLIT_DEFAULTS = {
  HEADING: 'Two-column agenda',
  LEFT_TITLE: 'Column A',
  RIGHT_TITLE: 'Column B',
  LEFT: [
    'Put your text here',
    'Add an item description',
    'Put your text here',
    'Add an item description',
    'Put your text here',
    'Add an item description',
  ],
  RIGHT: [
    'Add an item description',
    'Put your text here',
    'Add an item description',
    'Put your text here',
    'Add an item description',
    'Put your text here',
  ],
}

function isBulletListSplitLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return id === 'bullet_list_split_v1' || id === 'bullet_list_split'
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

function cardIcon(kind, cx, cy) {
  if (kind === 'flag') {
    return `
      <g fill="none" stroke="#FFFFFF" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
        <path d="M${cx - 1} ${cy - 9}v18" />
        <path d="M${cx - 1} ${cy - 9}h10l-2.2 4.5 2.2 4.5H${cx - 1}" />
      </g>`
  }
  return `
    <g fill="none" stroke="#FFFFFF" stroke-width="1.9" stroke-linecap="round">
      <path d="M${cx - 7} ${cy - 6}h14M${cx - 7} ${cy}h14M${cx - 7} ${cy + 6}h10" />
      <circle cx="${cx - 10}" cy="${cy - 6}" r="1.2" fill="#FFFFFF" stroke="none" />
      <circle cx="${cx - 10}" cy="${cy}" r="1.2" fill="#FFFFFF" stroke="none" />
      <circle cx="${cx - 10}" cy="${cy + 6}" r="1.2" fill="#FFFFFF" stroke="none" />
    </g>`
}

function buildSplitCardSvg({ width, height, radius, headerH, rows, rowGap, listStart, dotX, icon, includeCopy = false, title = '', items = [] }) {
  const r = radius
  const dots = []
  for (let i = 0; i < rows; i += 1) {
    const y = listStart + 12 + i * rowGap
    dots.push(`<circle cx="${dotX}" cy="${y}" r="5" fill="currentColor" />`)
  }
  const titleSvg = includeCopy
    ? `<text x="64" y="${Math.round(headerH * 0.62)}" fill="#FFFFFF" font-size="18" font-weight="700" font-family="Inter, Arial, sans-serif">${escapeXml(title)}</text>`
    : ''
  const itemsSvg = includeCopy
    ? items
        .map((text, i) => {
          const y = listStart + 16 + i * rowGap
          return `<text x="48" y="${y}" fill="#1F2937" font-size="14" font-weight="500" font-family="Inter, Arial, sans-serif">${escapeXml(text)}</text>`
        })
        .join('\n')
    : ''

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <path d="M ${r} 0 H ${width - r} Q ${width} 0 ${width} ${r} V ${height - r} Q ${width} ${height} ${width - r} ${height} H ${r} Q 0 ${height} 0 ${height - r} V ${r} Q 0 0 ${r} 0 Z" fill="#F7F8FA" stroke="currentColor" stroke-opacity="0.18" stroke-width="1.5" pointer-events="all" />
    <path d="M ${r} 0 H ${width - r} Q ${width} 0 ${width} ${r} V ${headerH} H 0 V ${r} Q 0 0 ${r} 0 Z" fill="currentColor" pointer-events="all" />
    <circle cx="36" cy="${headerH / 2}" r="16" fill="rgba(255,255,255,0.18)" />
    ${cardIcon(icon, 36, headerH / 2)}
    ${dots.join('\n')}
    ${titleSvg}
    ${itemsSvg}
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

function parseList(text, fallback) {
  const lines = String(text || '')
    .split(/\n+/)
    .map((line) => line.replace(/^\s*[•●▪–—-]\s*/, '').trim())
    .filter(Boolean)
  if (lines.length >= 3) return lines.slice(0, 6)
  return fallback
}

function layoutBulletListSplit(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const g = BULLET_LIST_SPLIT_GEOM
  const scaleX = canvasW / g.viewW
  const scaleY = canvasH / g.viewH

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => matcher(String(e.slotId || '').toUpperCase()))
    const txt = el?.content?.text || el?.text || el?.content?.heading
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const heading = findText((s) => s === 'HEADING' || s === 'TITLE' || s === 'MAIN_TITLE', BULLET_LIST_SPLIT_DEFAULTS.HEADING)
  const leftTitle = findText((s) => s === 'LEFT_TITLE' || s === 'TITLE_1', '') || BULLET_LIST_SPLIT_DEFAULTS.LEFT_TITLE
  const rightTitle = findText((s) => s === 'RIGHT_TITLE' || s === 'TITLE_2', '') || BULLET_LIST_SPLIT_DEFAULTS.RIGHT_TITLE

  const left = []
  const right = []
  for (let i = 1; i <= 6; i += 1) {
    left.push(findText((s) => s === `LEFT_${i}`, ''))
    right.push(findText((s) => s === `RIGHT_${i}`, ''))
  }
  if (left.filter(Boolean).length < 3) {
    parseList(findText((s) => s === 'LEFT_BODY' || s === 'LEFT', ''), BULLET_LIST_SPLIT_DEFAULTS.LEFT).forEach((line, i) => {
      if (!left[i]) left[i] = line
    })
  }
  if (right.filter(Boolean).length < 3) {
    parseList(findText((s) => s === 'RIGHT_BODY' || s === 'RIGHT', ''), BULLET_LIST_SPLIT_DEFAULTS.RIGHT).forEach((line, i) => {
      if (!right[i]) right[i] = line
    })
  }
  for (let i = 0; i < 6; i += 1) {
    if (!left[i]) left[i] = BULLET_LIST_SPLIT_DEFAULTS.LEFT[i]
    if (!right[i]) right[i] = BULLET_LIST_SPLIT_DEFAULTS.RIGHT[i]
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
      layer: 10,
      placement,
      rect: { ...placement },
      content: {
        text: config.text,
        fontSize: config.fontSize,
        fontWeight: config.fontWeight || 500,
        color: config.color,
        align: config.align || 'left',
        lineHeight: 1.25,
        clipToSlot: true,
        maxLines: 1,
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
      role: config.role || 'decoration',
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
    id: 'bls_bg',
    slotId: 'SLIDE_BG',
    layer: 0,
    x: 0,
    y: 0,
    width: canvasW,
    height: canvasH,
    colorMode: 'fixed',
    fill: '#FFFFFF',
    svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${canvasW} ${canvasH}"><rect width="100%" height="100%" fill="#FFFFFF" /></svg>`,
  })

  pushText({
    id: 'bls_heading',
    slotId: 'HEADING',
    role: 'caption',
    text: heading,
    x: g.headingX * scaleX,
    y: g.headingY * scaleY,
    width: g.headingW * scaleX,
    height: g.headingH * scaleY,
    fontSize: 26,
    fontWeight: 700,
    color: '#111827',
  })

  const columns = [
    { key: 'LEFT', title: leftTitle, items: left, theme: BULLET_LIST_SPLIT_CARDS[0], x: g.cardX },
    { key: 'RIGHT', title: rightTitle, items: right, theme: BULLET_LIST_SPLIT_CARDS[1], x: g.cardX + g.cardW + g.cardGap },
  ]

  columns.forEach((col, colIdx) => {
    const slotId = `CARD_${col.key}`
    const prev = elements.find((e) => String(e.slotId || '').toUpperCase() === slotId)
    const color = resolveStoredColor(prev, col.theme.fill)

    pushGraphic({
      id: prev?.id || `bls_card_${col.key.toLowerCase()}`,
      slotId,
      layer: 2,
      x: col.x * scaleX,
      y: g.cardY * scaleY,
      width: g.cardW * scaleX,
      height: g.cardH * scaleY,
      fill: color,
      svg: buildSplitCardSvg({
        width: g.cardW,
        height: g.cardH,
        radius: g.radius,
        headerH: g.headerH,
        rows: g.rows,
        rowGap: g.rowGap,
        listStart: g.listStart,
        dotX: g.dotX,
        icon: col.theme.icon,
      }),
    })

    pushText({
      id: `bls_title_${col.key.toLowerCase()}`,
      slotId: `${col.key}_TITLE`,
      role: 'body',
      text: col.title,
      x: (col.x + 60) * scaleX,
      y: (g.cardY + 22) * scaleY,
      width: 340 * scaleX,
      height: 28 * scaleY,
      fontSize: 18,
      fontWeight: 700,
      color: '#FFFFFF',
    })

    for (let i = 0; i < 6; i += 1) {
      pushText({
        id: `bls_${col.key.toLowerCase()}_${i + 1}`,
        slotId: `${col.key}_${i + 1}`,
        text: col.items[i],
        x: (col.x + g.textX) * scaleX,
        y: (g.cardY + g.listStart + i * g.rowGap - 6) * scaleY,
        width: 360 * scaleX,
        height: 28 * scaleY,
        fontSize: 14,
        color: '#1F2937',
      })
    }
  })

  if (Array.isArray(docOrElements)) return outElements
  return { ...docOrElements, elements: outElements }
}

function bulletListSplitPreviewSvg() {
  const g = BULLET_LIST_SPLIT_GEOM
  const headingLines = wrapLines(BULLET_LIST_SPLIT_DEFAULTS.HEADING, 40, 1)
  const cards = [
    { x: g.cardX, theme: BULLET_LIST_SPLIT_CARDS[0], title: BULLET_LIST_SPLIT_DEFAULTS.LEFT_TITLE, items: BULLET_LIST_SPLIT_DEFAULTS.LEFT },
    { x: g.cardX + g.cardW + g.cardGap, theme: BULLET_LIST_SPLIT_CARDS[1], title: BULLET_LIST_SPLIT_DEFAULTS.RIGHT_TITLE, items: BULLET_LIST_SPLIT_DEFAULTS.RIGHT },
  ]
    .map((card) => {
      const inner = buildSplitCardSvg({
        width: g.cardW,
        height: g.cardH,
        radius: g.radius,
        headerH: g.headerH,
        rows: g.rows,
        rowGap: g.rowGap,
        listStart: g.listStart,
        dotX: g.dotX,
        icon: card.theme.icon,
        includeCopy: true,
        title: card.title,
        items: card.items,
      }).replace(/^<svg[^>]*>/, '').replace(/<\/svg>$/, '')
      return `<g transform="translate(${card.x}, ${g.cardY})" color="${card.theme.fill}">${inner}</g>`
    })
    .join('\n')

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    <rect width="100%" height="100%" fill="#FFFFFF" />
    ${headingLines
      .map((line, i) => `<text x="${g.headingX}" y="${g.headingY + 26 + i * 26}" fill="#111827" font-size="26" font-weight="700" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`)
      .join('\n')}
    ${cards}
  </svg>`
}

module.exports = {
  BULLET_LIST_SPLIT_GEOM,
  BULLET_LIST_SPLIT_CARDS,
  BULLET_LIST_SPLIT_DEFAULTS,
  isBulletListSplitLayout,
  buildSplitCardSvg,
  layoutBulletListSplit,
  bulletListSplitPreviewSvg,
};
