/**
 * Section Divider Split Diagonal
 * Layout IDs: section_divider_split_diagonal_v1, section_divider_split_diagonal
 *
 * Two-tone chapter opener: dark diagonal panel (number + title)
 * and a cream reading panel (label + body). Recolorable CHROME.
 */

const SECTION_DIVIDER_SPLIT_DIAGONAL_GEOM = {
  viewW: 1000,
  viewH: 560,
  numberX: 48,
  numberY: 70,
  numberW: 400,
  numberH: 160,
  eyebrowX: 56,
  eyebrowY: 248,
  eyebrowW: 380,
  eyebrowH: 22,
  headingX: 56,
  headingY: 278,
  headingW: 390,
  headingH: 120,
  labelX: 660,
  labelY: 188,
  labelW: 280,
  labelH: 22,
  bodyX: 660,
  bodyY: 228,
  bodyW: 280,
  bodyH: 180,
}

const SECTION_DIVIDER_SPLIT_DIAGONAL_ACCENT = '#148A80'

const SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS = {
  SECTION_NUMBER: '02',
  EYEBROW: 'SECTION',
  HEADING: 'Next chapter',
  LABEL: 'IN THIS SECTION',
  BODY: 'What we cover next: the shift, the stakes, and the decisions this chapter is here to unlock.',
}

function isSectionDividerSplitDiagonalLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return id === 'section_divider_split_diagonal_v1' || id === 'section_divider_split_diagonal'
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

function buildSplitDiagonalChromeSvg() {
  const width = 1000
  const height = 560
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect width="${width}" height="${height}" fill="#F6F4F0" pointer-events="all" />
    <path d="M 0 0 H 490 L 620 560 H 0 Z" fill="currentColor" pointer-events="all" />
    <path d="M 490 0 L 506 0 L 636 560 L 620 560 Z" fill="#F6F4F0" />
    <path d="M 498 0 L 504 0 L 634 560 L 628 560 Z" fill="currentColor" fill-opacity="0.35" />
    <circle cx="562" cy="280" r="11" fill="#F6F4F0" />
    <circle cx="562" cy="280" r="6" fill="currentColor" />
    <rect x="660" y="214" width="36" height="3" rx="1.5" fill="currentColor" />
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

function layoutSectionDividerSplitDiagonal(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const g = SECTION_DIVIDER_SPLIT_DIAGONAL_GEOM
  const scaleX = canvasW / g.viewW
  const scaleY = canvasH / g.viewH

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => matcher(String(e.slotId || '').toUpperCase()))
    const txt = el?.content?.text || el?.text || el?.content?.heading
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const number = findText((s) => s === 'SECTION_NUMBER' || s === 'NUMBER', SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.SECTION_NUMBER)
  const eyebrow = String(
    findText((s) => s === 'EYEBROW' || s === 'BADGE', SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.EYEBROW) ||
      SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.EYEBROW
  ).toUpperCase()
  const heading = findText((s) => s === 'HEADING' || s === 'TITLE', SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.HEADING)
  const label = String(
    findText((s) => s === 'LABEL', SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.LABEL) ||
      SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.LABEL
  ).toUpperCase()
  const body = findText((s) => s === 'BODY' || s === 'SUBTITLE', SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.BODY)

  const prevChrome = elements.find((e) => String(e.slotId || '').toUpperCase() === 'CHROME')
  const accent = resolveStoredColor(prevChrome, palette?.primary || SECTION_DIVIDER_SPLIT_DIAGONAL_ACCENT)

  const outElements = []
  const pushText = (config) => {
    const placement = {
      x: Math.round(config.x),
      y: Math.round(config.y),
      width: Math.max(1, Math.round(config.width)),
      height: Math.max(1, Math.round(config.height)),
      rotation: 0,
      opacity: config.opacity == null ? 1 : config.opacity,
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
        fontWeight: config.fontWeight || 500,
        fontFamily: config.fontFamily,
        color: config.color,
        align: config.align || 'left',
        lineHeight: config.lineHeight || 1.2,
        letterSpacing: config.letterSpacing || 'normal',
        clipToSlot: true,
        maxLines: config.maxLines || 3,
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
      layer: config.layer || 1,
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
    id: prevChrome?.id || 'sdsd_chrome',
    slotId: 'CHROME',
    layer: 1,
    x: 0,
    y: 0,
    width: canvasW,
    height: canvasH,
    fill: accent,
    svg: buildSplitDiagonalChromeSvg(),
  })

  pushText({
    id: 'sdsd_number',
    slotId: 'SECTION_NUMBER',
    role: 'stat',
    text: number,
    x: g.numberX * scaleX,
    y: g.numberY * scaleY,
    width: g.numberW * scaleX,
    height: g.numberH * scaleY,
    fontSize: 120,
    fontWeight: 800,
    fontFamily: "Georgia, 'Times New Roman', serif",
    color: 'rgba(255,255,255,0.18)',
    lineHeight: 0.9,
    maxLines: 1,
    layer: 8,
    opacity: 1,
  })

  pushText({
    id: 'sdsd_eyebrow',
    slotId: 'EYEBROW',
    role: 'caption',
    text: eyebrow,
    x: g.eyebrowX * scaleX,
    y: g.eyebrowY * scaleY,
    width: g.eyebrowW * scaleX,
    height: g.eyebrowH * scaleY,
    fontSize: 12,
    fontWeight: 600,
    fontFamily: 'Inter, system-ui, sans-serif',
    color: 'rgba(255,255,255,0.72)',
    letterSpacing: '0.2em',
    maxLines: 1,
  })

  pushText({
    id: 'sdsd_heading',
    slotId: 'HEADING',
    role: 'heading',
    text: heading,
    x: g.headingX * scaleX,
    y: g.headingY * scaleY,
    width: g.headingW * scaleX,
    height: g.headingH * scaleY,
    fontSize: 36,
    fontWeight: 700,
    fontFamily: "Georgia, 'Times New Roman', serif",
    color: '#FFFFFF',
    lineHeight: 1.12,
    maxLines: 2,
  })

  pushText({
    id: 'sdsd_label',
    slotId: 'LABEL',
    role: 'caption',
    text: label,
    x: g.labelX * scaleX,
    y: g.labelY * scaleY,
    width: g.labelW * scaleX,
    height: g.labelH * scaleY,
    fontSize: 12,
    fontWeight: 600,
    fontFamily: 'Inter, system-ui, sans-serif',
    color: accent,
    letterSpacing: '0.18em',
    maxLines: 1,
  })

  pushText({
    id: 'sdsd_body',
    slotId: 'BODY',
    role: 'body',
    text: body,
    x: g.bodyX * scaleX,
    y: g.bodyY * scaleY,
    width: g.bodyW * scaleX,
    height: g.bodyH * scaleY,
    fontSize: 16,
    fontWeight: 400,
    fontFamily: 'Inter, system-ui, sans-serif',
    color: '#4B5563',
    lineHeight: 1.45,
    maxLines: 5,
  })

  if (Array.isArray(docOrElements)) return outElements
  return { ...docOrElements, elements: outElements }
}

function sectionDividerSplitDiagonalPreviewSvg() {
  const g = SECTION_DIVIDER_SPLIT_DIAGONAL_GEOM
  const headingLines = wrapLines(SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.HEADING, 16, 2)
  const bodyLines = wrapLines(SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.BODY, 28, 4)
  const chrome = buildSplitDiagonalChromeSvg()
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>$/, '')

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    <g color="${SECTION_DIVIDER_SPLIT_DIAGONAL_ACCENT}">${chrome}</g>
    <text x="${g.numberX}" y="${g.numberY + 130}" fill="#FFFFFF" fill-opacity="0.18" font-size="120" font-weight="800" font-family="Georgia, 'Times New Roman', serif">${escapeXml(SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.SECTION_NUMBER)}</text>
    <text x="${g.eyebrowX}" y="${g.eyebrowY + 16}" fill="#FFFFFF" fill-opacity="0.72" font-size="12" font-weight="600" font-family="Inter, Arial, sans-serif" letter-spacing="0.2em">${SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.EYEBROW}</text>
    ${headingLines
      .map(
        (line, i) =>
          `<text x="${g.headingX}" y="${g.headingY + 38 + i * 42}" fill="#FFFFFF" font-size="36" font-weight="700" font-family="Georgia, 'Times New Roman', serif">${escapeXml(line)}</text>`
      )
      .join('\n')}
    <text x="${g.labelX}" y="${g.labelY + 16}" fill="${SECTION_DIVIDER_SPLIT_DIAGONAL_ACCENT}" font-size="12" font-weight="600" font-family="Inter, Arial, sans-serif" letter-spacing="0.18em">${SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS.LABEL}</text>
    ${bodyLines
      .map(
        (line, i) =>
          `<text x="${g.bodyX}" y="${g.bodyY + 22 + i * 24}" fill="#4B5563" font-size="15" font-weight="400" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`
      )
      .join('\n')}
  </svg>`
}

module.exports = {
  SECTION_DIVIDER_SPLIT_DIAGONAL_GEOM,
  SECTION_DIVIDER_SPLIT_DIAGONAL_ACCENT,
  SECTION_DIVIDER_SPLIT_DIAGONAL_DEFAULTS,
  isSectionDividerSplitDiagonalLayout,
  buildSplitDiagonalChromeSvg,
  layoutSectionDividerSplitDiagonal,
  sectionDividerSplitDiagonalPreviewSvg,
};
