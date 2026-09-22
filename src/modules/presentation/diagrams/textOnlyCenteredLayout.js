/**
 * Text Only Centered Layout Engine
 * Layout IDs: text_only_centered_v1, text_only_centered
 *
 * Editorial statement slide: generous whitespace, centered type,
 * a short accent rule, and a faint quote ornament.
 */

const TEXT_ONLY_CENTERED_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 120,
  headingY: 168,
  headingW: 760,
  headingH: 120,
  bodyX: 180,
  bodyY: 328,
  bodyW: 640,
  bodyH: 90,
  badgeY: 118,
  ruleY: 304,
  ruleW: 56,
}

const TEXT_ONLY_CENTERED_ACCENT = '#148A80'

const TEXT_ONLY_CENTERED_DEFAULTS = {
  BADGE: 'A NOTE',
  HEADING: 'A clear idea, well said.',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

function isTextOnlyCenteredLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase()
  return id === 'text_only_centered_v1' || id === 'text_only_centered'
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

function buildCenteredOrnamentSvg() {
  const width = 1000
  const height = 560
  const cx = width / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect width="${width}" height="${height}" fill="#FBFBFA" pointer-events="all" />
    <text x="${cx}" y="132" text-anchor="middle" fill="currentColor" fill-opacity="0.10" font-size="160" font-weight="700" font-family="Georgia, 'Times New Roman', serif">“</text>
    <circle cx="${cx - 14}" cy="96" r="3.2" fill="currentColor" />
    <circle cx="${cx}" cy="96" r="3.2" fill="currentColor" />
    <circle cx="${cx + 14}" cy="96" r="3.2" fill="currentColor" />
    <rect x="${cx - 28}" y="304" width="56" height="3" rx="1.5" fill="currentColor" />
    <path d="M 36 36 H 86 M 36 36 V 86" fill="none" stroke="currentColor" stroke-opacity="0.28" stroke-width="1.6" stroke-linecap="round" />
    <path d="M ${width - 36} 36 H ${width - 86} M ${width - 36} 36 V 86" fill="none" stroke="currentColor" stroke-opacity="0.28" stroke-width="1.6" stroke-linecap="round" />
    <path d="M 36 ${height - 36} H 86 M 36 ${height - 36} V ${height - 86}" fill="none" stroke="currentColor" stroke-opacity="0.28" stroke-width="1.6" stroke-linecap="round" />
    <path d="M ${width - 36} ${height - 36} H ${width - 86} M ${width - 36} ${height - 36} V ${height - 86}" fill="none" stroke="currentColor" stroke-opacity="0.28" stroke-width="1.6" stroke-linecap="round" />
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

function layoutTextOnlyCentered(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1000
  const canvasH = canvas.height || docOrElements?.canvas?.height || 560
  const g = TEXT_ONLY_CENTERED_GEOM
  const scaleX = canvasW / g.viewW
  const scaleY = canvasH / g.viewH

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => matcher(String(e.slotId || '').toUpperCase()))
    const txt = el?.content?.text || el?.text || el?.content?.heading
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback
  }

  const badge = String(
    findText((s) => s === 'BADGE' || s === 'EYEBROW', TEXT_ONLY_CENTERED_DEFAULTS.BADGE) || TEXT_ONLY_CENTERED_DEFAULTS.BADGE
  ).toUpperCase()
  const heading = findText((s) => s === 'HEADING' || s === 'TITLE' || s === 'MAIN_TITLE', TEXT_ONLY_CENTERED_DEFAULTS.HEADING)
  const body = findText((s) => s === 'BODY' || s === 'SUBTITLE', TEXT_ONLY_CENTERED_DEFAULTS.BODY)

  const prevChrome = elements.find((e) => String(e.slotId || '').toUpperCase() === 'CHROME')
  const accent = resolveStoredColor(prevChrome, palette?.primary || TEXT_ONLY_CENTERED_ACCENT)

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
        align: 'center',
        lineHeight: config.lineHeight || 1.2,
        letterSpacing: config.letterSpacing || 'normal',
        fontFamily: config.fontFamily,
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
    id: prevChrome?.id || 'toc_chrome',
    slotId: 'CHROME',
    layer: 1,
    x: 0,
    y: 0,
    width: canvasW,
    height: canvasH,
    fill: accent,
    svg: buildCenteredOrnamentSvg(),
  })

  pushText({
    id: 'toc_badge',
    slotId: 'BADGE',
    role: 'caption',
    text: badge,
    fontFamily: 'Inter, system-ui, sans-serif',
    x: 300 * scaleX,
    y: g.badgeY * scaleY,
    width: 400 * scaleX,
    height: 22 * scaleY,
    fontSize: 12,
    fontWeight: 600,
    color: accent,
    letterSpacing: '0.18em',
    maxLines: 1,
  })

  pushText({
    id: 'toc_heading',
    slotId: 'HEADING',
    role: 'heading',
    text: heading,
    fontFamily: "Georgia, 'Times New Roman', serif",
    x: g.headingX * scaleX,
    y: g.headingY * scaleY,
    width: g.headingW * scaleX,
    height: g.headingH * scaleY,
    fontSize: 40,
    fontWeight: 700,
    color: '#111827',
    lineHeight: 1.15,
    maxLines: 2,
  })

  pushText({
    id: 'toc_body',
    slotId: 'BODY',
    role: 'body',
    text: body,
    fontFamily: 'Inter, system-ui, sans-serif',
    x: g.bodyX * scaleX,
    y: g.bodyY * scaleY,
    width: g.bodyW * scaleX,
    height: g.bodyH * scaleY,
    fontSize: 16,
    fontWeight: 400,
    color: '#4B5563',
    lineHeight: 1.45,
    maxLines: 4,
  })

  if (Array.isArray(docOrElements)) return outElements
  return { ...docOrElements, elements: outElements }
}

function textOnlyCenteredPreviewSvg() {
  const g = TEXT_ONLY_CENTERED_GEOM
  const headingLines = wrapLines(TEXT_ONLY_CENTERED_DEFAULTS.HEADING, 22, 2)
  const bodyLines = wrapLines(TEXT_ONLY_CENTERED_DEFAULTS.BODY, 52, 3)
  const ornament = buildCenteredOrnamentSvg()
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>$/, '')

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%">
    <g color="${TEXT_ONLY_CENTERED_ACCENT}">${ornament}</g>
    <text x="500" y="${g.badgeY + 16}" text-anchor="middle" fill="${TEXT_ONLY_CENTERED_ACCENT}" font-size="12" font-weight="600" font-family="Inter, Arial, sans-serif" letter-spacing="0.18em">${TEXT_ONLY_CENTERED_DEFAULTS.BADGE}</text>
    ${headingLines
      .map(
        (line, i) =>
          `<text x="500" y="${g.headingY + 44 + i * 46}" text-anchor="middle" fill="#111827" font-size="40" font-weight="700" font-family="Georgia, 'Times New Roman', serif">${escapeXml(line)}</text>`
      )
      .join('\n')}
    ${bodyLines
      .map(
        (line, i) =>
          `<text x="500" y="${g.bodyY + 22 + i * 22}" text-anchor="middle" fill="#4B5563" font-size="15" font-weight="400" font-family="Inter, Arial, sans-serif">${escapeXml(line)}</text>`
      )
      .join('\n')}
  </svg>`
}

module.exports = {
  TEXT_ONLY_CENTERED_GEOM,
  TEXT_ONLY_CENTERED_ACCENT,
  TEXT_ONLY_CENTERED_DEFAULTS,
  isTextOnlyCenteredLayout,
  buildCenteredOrnamentSvg,
  layoutTextOnlyCentered,
  textOnlyCenteredPreviewSvg,
};
