/**
 * Bullet List Numbered Layout Engine (Frontend)
 * Layout IDs:
 *  - bullet_list_numbered_v1
 *  - bullet_list_numbered
 *
 * Five outlined hexagons (3 top / 2 bottom honeycomb) with large
 * stroke numerals, caption, and short body copy.
 */

const BULLET_LIST_NUMBERED_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 22,
  headingH: 36,
  R: 122,
  col: 228,
  row: 188,
  topCy: 176,
  botCy: 364,
}

const BULLET_LIST_NUMBERED_ITEMS = [
  { color: '#FF7A3C' },
  { color: '#22C5E0' },
  { color: '#F04444' },
  { color: '#6B5CE7' },
  { color: '#E85AAA' },
]

const BULLET_LIST_NUMBERED_DEFAULTS = {
  HEADING: 'Five Numbers List',
  TITLE: 'Caption',
  ITEM: 'This slide is an editable slide with all your needs.',
}

function isBulletListNumberedLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return (
    id === 'bullet_list_numbered_v1' ||
    id === 'bullet_list_numbered'
  )
}

function hexWidth(R) {
  return Math.sqrt(3) * R
}

function hexagonCenters() {
  const { col, topCy, botCy } = BULLET_LIST_NUMBERED_GEOM
  const cx = 500
  return [
    { cx: cx - col, cy: topCy, n: 1 },
    { cx, cy: topCy, n: 2 },
    { cx: cx + col, cy: topCy, n: 3 },
    { cx: cx - col / 2, cy: botCy, n: 4 },
    { cx: cx + col / 2, cy: botCy, n: 5 },
  ]
}

function hexagonPath(cx, cy, r) {
  const pts = []
  for (let i = 0; i < 6; i += 1) {
    const a = ((-90 + i * 60) * Math.PI) / 180
    pts.push(`${(cx + r * Math.cos(a)).toFixed(1)},${(cy + r * Math.sin(a)).toFixed(1)}`)
  }
  return `M ${pts.join(' L ')} Z`
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

function buildNumberedHexSvg({ width, height, cx, cy, r, number }) {
  const path = hexagonPath(cx, cy, r)
  const numX = cx - r * 0.62
  const numY = cy + r * 0.42
  const numSize = Math.round(r * 0.78)

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%" overflow="visible">
    <path d="${path}" fill="currentColor" fill-opacity="0.04" stroke="currentColor" stroke-width="4.5" stroke-linejoin="round" stroke-linecap="round" pointer-events="all" />
    <text x="${numX}" y="${numY}" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linejoin="round" font-size="${numSize}" font-weight="700" font-family="Inter, Arial, sans-serif" pointer-events="none">${number}</text>
  </svg>`
}

function stripListPrefix(text) {
  return String(text || '')
    .replace(/^\s*(?:[•●▪–—-]|\d+[.)]|0\d)\s+/u, '')
    .trim()
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill
  if (fill && typeof fill === 'object' && fill.color) return fill.color
  const stroke = el?.content?.stroke
  if (typeof stroke === 'string' && stroke) return stroke
  return fallback
}

function layoutBulletListNumbered(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const geom = BULLET_LIST_NUMBERED_GEOM
  const scaleX = canvasW / geom.viewW
  const scaleY = canvasH / geom.viewH
  const R = geom.R
  const hexW = hexWidth(R)

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => {
      const sid = String(e.slotId || '').toUpperCase()
      const role = String(e.role || '').toUpperCase()
      return matcher(sid, role)
    })
    const txt = el?.content?.text || el?.text || el?.content?.heading || el?.content?.title
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const heading = findText(
    (s) => s === 'HEADING' || s === 'TITLE' || s === 'MAIN_TITLE',
    BULLET_LIST_NUMBERED_DEFAULTS.HEADING
  )

  const titles = [1, 2, 3, 4, 5].map((n) =>
    findText((s) => s === `TITLE_${n}` || s === `HEADING_${n}` || s === `CAPTION_${n}`, '') ||
    BULLET_LIST_NUMBERED_DEFAULTS.TITLE
  )
  const bodies = [1, 2, 3, 4, 5].map((n) => {
    const raw = findText((s) => s === `ITEM_${n}` || s === `BODY_${n}` || s === `POINT_${n}`, '')
    return raw ? stripListPrefix(raw) : BULLET_LIST_NUMBERED_DEFAULTS.ITEM
  })

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
        preserveAspectRatio: 'xMidYMid meet',
        colorMode: config.colorMode || 'fixed',
        fill: config.fill,
        stroke: config.stroke || config.fill,
      },
    })
  }

  pushGraphic({
    id: 'bln_bg',
    slotId: 'SLIDE_BG',
    layer: 0,
    x: 0,
    y: 0,
    width: canvasW,
    height: canvasH,
    svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${canvasW} ${canvasH}"><rect width="100%" height="100%" fill="#FFFFFF" /></svg>`,
  })

  pushText({
    id: 'bln_heading',
    slotId: 'HEADING',
    role: 'caption',
    text: heading,
    x: 80 * scaleX,
    y: geom.headingY * scaleY,
    width: 840 * scaleX,
    height: geom.headingH * scaleY,
    fontSize: 26,
    fontWeight: 700,
    color: '#1F2937',
    align: 'center',
    maxLines: 1,
  })

  hexagonCenters().forEach((hex, i) => {
    const theme = BULLET_LIST_NUMBERED_ITEMS[i]
    const pad = 28
    const boxX = hex.cx - hexW / 2 - pad
    const boxY = hex.cy - R
    const boxW = hexW + pad + 8
    const boxH = R * 2
    const localCx = pad + hexW / 2
    const localCy = R

    const prevHex = elements.find((e) => String(e.slotId || '').toUpperCase() === `HEX_${i + 1}`)
    const hexColor = resolveStoredColor(prevHex, theme.color)

    pushGraphic({
      id: prevHex?.id || `bln_hex_${i + 1}`,
      slotId: `HEX_${i + 1}`,
      layer: 2,
      x: boxX * scaleX,
      y: boxY * scaleY,
      width: boxW * scaleX,
      height: boxH * scaleY,
      colorMode: 'recolorable',
      fill: hexColor,
      stroke: hexColor,
      svg: buildNumberedHexSvg({
        width: boxW,
        height: boxH,
        cx: localCx,
        cy: localCy,
        r: R,
        number: String(i + 1),
      }),
    })

    pushText({
      id: `bln_title_${i + 1}`,
      slotId: `TITLE_${i + 1}`,
      role: 'body',
      text: titles[i],
      x: (hex.cx - R * 0.08) * scaleX,
      y: (hex.cy - R * 0.28) * scaleY,
      width: (R * 1.05) * scaleX,
      height: 22 * scaleY,
      fontSize: 14,
      fontWeight: 800,
      color: '#111827',
      maxLines: 1,
    })

    pushText({
      id: `bln_item_${i + 1}`,
      slotId: `ITEM_${i + 1}`,
      role: 'body',
      text: bodies[i],
      x: (hex.cx - R * 0.08) * scaleX,
      y: (hex.cy - R * 0.04) * scaleY,
      width: (R * 1.05) * scaleX,
      height: (R * 0.62) * scaleY,
      fontSize: 12,
      fontWeight: 400,
      color: '#4B5563',
      lineHeight: 1.3,
      maxLines: 3,
    })
  })

  if (Array.isArray(docOrElements)) {
    return outElements
  }
  return { ...docOrElements, elements: outElements }
}

function bulletListNumberedPreviewSvg() {
  const geom = BULLET_LIST_NUMBERED_GEOM
  const R = geom.R
  const hexes = hexagonCenters()
    .map((hex, i) => {
      const color = BULLET_LIST_NUMBERED_ITEMS[i].color
      const path = hexagonPath(hex.cx, hex.cy, R)
      const numX = hex.cx - R * 0.62
      const numY = hex.cy + R * 0.42
      const title = BULLET_LIST_NUMBERED_DEFAULTS.TITLE
      const bodyLines = wrapLines(BULLET_LIST_NUMBERED_DEFAULTS.ITEM, 22, 3)
      const textX = hex.cx - R * 0.08
      return `
        <path d="${path}" fill="none" stroke="${color}" stroke-width="4.5" stroke-linejoin="round" stroke-linecap="round" />
        <text x="${numX}" y="${numY}" fill="none" stroke="${color}" stroke-width="3.2" stroke-linejoin="round" font-size="${Math.round(R * 0.78)}" font-weight="700" font-family="Inter, Arial, sans-serif">${i + 1}</text>
        <text x="${textX}" y="${hex.cy - R * 0.12}" fill="#111827" font-size="14" font-weight="800" font-family="Inter, Arial, sans-serif">${escapeXml(title)}</text>
        ${bodyLines
          .map(
            (line, li) =>
              `<text x="${textX}" y="${hex.cy + 10 + li * 15}" fill="#4B5563" font-size="12" font-weight="400" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`
          )
          .join('\n')}
      `
    })
    .join('\n')

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${geom.viewW} ${geom.viewH}" width="100%" height="100%">
    <rect width="100%" height="100%" fill="#FFFFFF" />
    <text x="500" y="46" text-anchor="middle" fill="#1F2937" font-size="26" font-weight="700" font-family="Georgia, 'Times New Roman', serif">${BULLET_LIST_NUMBERED_DEFAULTS.HEADING}</text>
    ${hexes}
  </svg>`
}

module.exports = {
  BULLET_LIST_NUMBERED_GEOM,
  BULLET_LIST_NUMBERED_ITEMS,
  BULLET_LIST_NUMBERED_DEFAULTS,
  isBulletListNumberedLayout,
  buildNumberedHexSvg,
  layoutBulletListNumbered,
  bulletListNumberedPreviewSvg,
};
