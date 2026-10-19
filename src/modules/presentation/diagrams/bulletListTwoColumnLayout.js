/**
 * Bullet List Two Column Layout Engine
 * Layout IDs:
 *  - bullet_list_two_column_v1
 *  - bullet_list_two_column
 *
 * Long agenda list: title, accent rule with a centered icon badge,
 * and two even columns of bullets on a soft gray panel.
 */

const BULLET_LIST_TWO_COLUMN_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 56,
  headingY: 28,
  headingW: 888,
  headingH: 44,
  panelX: 72,
  panelY: 132,
  panelW: 856,
  panelH: 384,
  iconR: 38,
  cols: 7,
  rowGap: 44,
  listStartY: 44,
  leftX: 48,
  rightX: 456,
  dotR: 5.5,
}

const BULLET_LIST_TWO_COLUMN_ACCENT = '#148A80'

const BULLET_LIST_TWO_COLUMN_DEFAULTS = {
  HEADING: 'Long Agenda List with Two Column Bullet Points',
  LEFT: [
    'Put your text here',
    'Add an item description',
    'Put your text here',
    'Add an item description',
    'Put your text here',
    'Add an item description',
    'Put your text here',
  ],
  RIGHT: [
    'Add an item description',
    'Put your text here',
    'Add an item description',
    'Put your text here',
    'Add an item description',
    'Put your text here',
    'Add an item description',
  ],
}

function isBulletListTwoColumnLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return (
    id === 'bullet_list_two_column_v1' ||
    id === 'bullet_list_two_column'
  )
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

function presentationIcon(cx, cy) {
  return `
    <g fill="none" stroke="#FFFFFF" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
      <rect x="${cx - 9}" y="${cy - 12}" width="18" height="12" rx="1.6" />
      <path d="M${cx - 4} ${cy - 8}h8M${cx - 4} ${cy - 4}h5" />
      <path d="M${cx - 6} ${cy}L${cx - 9} ${cy + 11}M${cx + 6} ${cy}L${cx + 9} ${cy + 11}" />
      <path d="M${cx - 3} ${cy + 6}h6" />
    </g>
  `
}

function buildTwoColumnPanelSvg({ width, height, iconR, panelH, accentDots = true, includeCopy = false, left = [], right = [] }) {
  const g = BULLET_LIST_TWO_COLUMN_GEOM
  const panelY = iconR
  const cx = width / 2
  const dots = []
  for (let i = 0; i < g.cols; i += 1) {
    const y = panelY + g.listStartY + 10 + i * g.rowGap
    dots.push(`<circle cx="${g.leftX}" cy="${y}" r="${g.dotR}" fill="currentColor" />`)
    dots.push(`<circle cx="${g.rightX}" cy="${y}" r="${g.dotR}" fill="currentColor" />`)
  }

  const copy = includeCopy
    ? [...left, ...right]
        .map((text, idx) => {
          const isRight = idx >= g.cols
          const i = idx % g.cols
          const x = (isRight ? g.rightX : g.leftX) + 16
          const y = panelY + g.listStartY + 14 + i * g.rowGap
          return `<text x="${x}" y="${y}" fill="#1F2937" font-size="15" font-weight="500" font-family="Inter, Arial, sans-serif">${escapeXml(text)}</text>`
        })
        .join('\n')
    : ''

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect x="0" y="${panelY}" width="${width}" height="${panelH}" fill="#E6EAED" />
    <rect x="0" y="${panelY - 3}" width="${width}" height="6" fill="currentColor" />
    <circle cx="${cx}" cy="${panelY}" r="${iconR}" fill="currentColor" pointer-events="all" />
    ${presentationIcon(cx, panelY)}
    ${accentDots ? dots.join('\n') : ''}
    ${copy}
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
  if (lines.length >= 3) return lines.slice(0, 7)
  return fallback
}

function layoutBulletListTwoColumn(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const g = BULLET_LIST_TWO_COLUMN_GEOM
  const scaleX = canvasW / g.viewW
  const scaleY = canvasH / g.viewH

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => matcher(String(e.slotId || '').toUpperCase()))
    const txt = el?.content?.text || el?.text || el?.content?.heading
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const heading = findText((s) => s === 'HEADING' || s === 'TITLE' || s === 'MAIN_TITLE', BULLET_LIST_TWO_COLUMN_DEFAULTS.HEADING)

  const left = []
  const right = []
  for (let i = 1; i <= 7; i += 1) {
    left.push(findText((s) => s === `LEFT_${i}` || s === `L${i}`, ''))
    right.push(findText((s) => s === `RIGHT_${i}` || s === `R${i}`, ''))
  }
  if (left.filter(Boolean).length < 3) {
    const parsed = parseList(findText((s) => s === 'LEFT_BODY' || s === 'LEFT', ''), BULLET_LIST_TWO_COLUMN_DEFAULTS.LEFT)
    parsed.forEach((line, i) => {
      if (!left[i]) left[i] = line
    })
  }
  if (right.filter(Boolean).length < 3) {
    const parsed = parseList(findText((s) => s === 'RIGHT_BODY' || s === 'RIGHT', ''), BULLET_LIST_TWO_COLUMN_DEFAULTS.RIGHT)
    parsed.forEach((line, i) => {
      if (!right[i]) right[i] = line
    })
  }
  for (let i = 0; i < 7; i += 1) {
    if (!left[i]) left[i] = BULLET_LIST_TWO_COLUMN_DEFAULTS.LEFT[i]
    if (!right[i]) right[i] = BULLET_LIST_TWO_COLUMN_DEFAULTS.RIGHT[i]
  }

  const prevChrome = elements.find((e) => String(e.slotId || '').toUpperCase() === 'CHROME')
  const accent = resolveStoredColor(prevChrome, palette?.primary || BULLET_LIST_TWO_COLUMN_ACCENT)

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
        align: 'left',
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
    id: 'blt_bg',
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
    id: 'blt_heading',
    slotId: 'HEADING',
    role: 'caption',
    text: heading,
    x: g.headingX * scaleX,
    y: g.headingY * scaleY,
    width: g.headingW * scaleX,
    height: g.headingH * scaleY,
    fontSize: 26,
    fontWeight: 500,
    color: '#1F2937',
  })

  const chromeY = g.panelY - g.iconR
  const chromeH = g.panelH + g.iconR
  pushGraphic({
    id: prevChrome?.id || 'blt_chrome',
    slotId: 'CHROME',
    layer: 2,
    x: g.panelX * scaleX,
    y: chromeY * scaleY,
    width: g.panelW * scaleX,
    height: chromeH * scaleY,
    fill: accent,
    svg: buildTwoColumnPanelSvg({
      width: g.panelW,
      height: chromeH,
      iconR: g.iconR,
      panelH: g.panelH,
    }),
  })

  for (let i = 0; i < 7; i += 1) {
    const y = (g.panelY + g.listStartY + i * g.rowGap - 6) * scaleY
    const h = 28 * scaleY
    pushText({
      id: `blt_left_${i + 1}`,
      slotId: `LEFT_${i + 1}`,
      text: left[i],
      x: (g.panelX + g.leftX + 16) * scaleX,
      y,
      width: 340 * scaleX,
      height: h,
      fontSize: 15,
      color: '#1F2937',
    })
    pushText({
      id: `blt_right_${i + 1}`,
      slotId: `RIGHT_${i + 1}`,
      text: right[i],
      x: (g.panelX + g.rightX + 16) * scaleX,
      y,
      width: 340 * scaleX,
      height: h,
      fontSize: 15,
      color: '#1F2937',
    })
  }

  if (Array.isArray(docOrElements)) return outElements
  return { ...docOrElements, elements: outElements }
}

function bulletListTwoColumnPreviewSvg() {
  const g = BULLET_LIST_TWO_COLUMN_GEOM
  const chromeY = g.panelY - g.iconR
  const chromeH = g.panelH + g.iconR
  const inner = buildTwoColumnPanelSvg({
    width: g.panelW,
    height: chromeH,
    iconR: g.iconR,
    panelH: g.panelH,
    includeCopy: true,
    left: BULLET_LIST_TWO_COLUMN_DEFAULTS.LEFT,
    right: BULLET_LIST_TWO_COLUMN_DEFAULTS.RIGHT,
  }).replace(/^<svg[^>]*>/, '').replace(/<\/svg>$/, '')

  const headingLines = wrapLines(BULLET_LIST_TWO_COLUMN_DEFAULTS.HEADING, 42, 2)

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    <rect width="100%" height="100%" fill="#FFFFFF" />
    ${headingLines
      .map(
        (line, i) =>
          `<text x="${g.headingX}" y="${g.headingY + 28 + i * 28}" fill="#1F2937" font-size="26" font-weight="500" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`
      )
      .join('\n')}
    <g transform="translate(${g.panelX}, ${chromeY})" color="${BULLET_LIST_TWO_COLUMN_ACCENT}">${inner}</g>
  </svg>`
}

module.exports = {
  BULLET_LIST_TWO_COLUMN_GEOM,
  BULLET_LIST_TWO_COLUMN_ACCENT,
  BULLET_LIST_TWO_COLUMN_DEFAULTS,
  isBulletListTwoColumnLayout,
  buildTwoColumnPanelSvg,
  layoutBulletListTwoColumn,
  bulletListTwoColumnPreviewSvg,
};
