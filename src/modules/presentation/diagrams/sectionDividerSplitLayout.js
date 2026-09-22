/**
 * Section Divider Split
 * Layout IDs: section_divider_split_v1, section_divider_split
 *
 * Quiet vertical chapter break: heading stays left, body stays right.
 * Recolorable CHROME (tint panel + center rule).
 */

const SECTION_DIVIDER_SPLIT_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 56,
  headingY: 188,
  headingW: 400,
  headingH: 168,
  bodyX: 556,
  bodyY: 200,
  bodyW: 388,
  bodyH: 168,
}

const SECTION_DIVIDER_SPLIT_ACCENT = '#148A80'

const SECTION_DIVIDER_SPLIT_DEFAULTS = {
  HEADING: 'Next section',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

function isSectionDividerSplitLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return id === 'section_divider_split_v1' || id === 'section_divider_split'
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

function buildSplitChromeSvg() {
  const width = 1000
  const height = 560
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect width="${width}" height="${height}" fill="#FBFBFA" pointer-events="all" />
    <rect x="0" y="0" width="500" height="${height}" fill="currentColor" fill-opacity="0.08" pointer-events="all" />
    <rect x="0" y="0" width="8" height="${height}" fill="currentColor" />
    <rect x="499" y="88" width="3" height="384" rx="1.5" fill="currentColor" />
    <circle cx="500.5" cy="280" r="11" fill="#FBFBFA" />
    <circle cx="500.5" cy="280" r="5.5" fill="currentColor" />
    <rect x="56" y="372" width="48" height="3" rx="1.5" fill="currentColor" />
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

function layoutSectionDividerSplit(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const g = SECTION_DIVIDER_SPLIT_GEOM
  const scaleX = canvasW / g.viewW
  const scaleY = canvasH / g.viewH

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => matcher(String(e.slotId || '').toUpperCase()))
    const txt = el?.content?.text || el?.text || el?.content?.heading
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const heading = findText((s) => s === 'HEADING' || s === 'TITLE', SECTION_DIVIDER_SPLIT_DEFAULTS.HEADING)
  const body = findText((s) => s === 'BODY' || s === 'SUBTITLE', SECTION_DIVIDER_SPLIT_DEFAULTS.BODY)

  const prevChrome = elements.find((e) => String(e.slotId || '').toUpperCase() === 'CHROME')
  const accent = resolveStoredColor(prevChrome, palette?.primary || SECTION_DIVIDER_SPLIT_ACCENT)

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
        fontFamily: config.fontFamily,
        color: config.color,
        align: 'left',
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
      layer: 1,
      placement,
      rect: { ...placement },
      content: {
        svg: config.svg,
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: config.fill,
        stroke: config.stroke || config.fill,
      },
    })
  }

  pushGraphic({
    id: prevChrome?.id || 'sds_chrome',
    slotId: 'CHROME',
    x: 0,
    y: 0,
    width: canvasW,
    height: canvasH,
    fill: accent,
    svg: buildSplitChromeSvg(),
  })

  pushText({
    id: 'sds_heading',
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
    color: '#111827',
    lineHeight: 1.15,
    maxLines: 3,
  })

  pushText({
    id: 'sds_body',
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

function sectionDividerSplitPreviewSvg() {
  const g = SECTION_DIVIDER_SPLIT_GEOM
  const headingLines = wrapLines(SECTION_DIVIDER_SPLIT_DEFAULTS.HEADING, 16, 3)
  const bodyLines = wrapLines(SECTION_DIVIDER_SPLIT_DEFAULTS.BODY, 32, 4)
  const chrome = buildSplitChromeSvg()
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>$/, '')

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    <g color="${SECTION_DIVIDER_SPLIT_ACCENT}">${chrome}</g>
    ${headingLines
      .map(
        (line, i) =>
          `<text x="${g.headingX}" y="${g.headingY + 40 + i * 42}" fill="#111827" font-size="36" font-weight="700" font-family="Georgia, 'Times New Roman', serif">${escapeXml(line)}</text>`
      )
      .join('\n')}
    ${bodyLines
      .map(
        (line, i) =>
          `<text x="${g.bodyX}" y="${g.bodyY + 22 + i * 24}" fill="#4B5563" font-size="15" font-weight="400" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`
      )
      .join('\n')}
  </svg>`
}

module.exports = {
  SECTION_DIVIDER_SPLIT_GEOM,
  SECTION_DIVIDER_SPLIT_ACCENT,
  SECTION_DIVIDER_SPLIT_DEFAULTS,
  isSectionDividerSplitLayout,
  buildSplitChromeSvg,
  layoutSectionDividerSplit,
  sectionDividerSplitPreviewSvg,
};
