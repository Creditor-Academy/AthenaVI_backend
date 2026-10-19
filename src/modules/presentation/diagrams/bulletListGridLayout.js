/**
 * Bullet List Grid
 * Layout ID: bullet_list_grid_v1
 *
 * Four full-height staggered columns with large index marks.
 * Distinct from Bullet List Cards (equal card row).
 */

function isBulletListGridLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  return id === 'bullet_list_grid_v1' || id === 'bullet_list_grid'
}

const BULLET_LIST_GRID_DEFAULTS = {
  HEADING: 'Key points',
  CARD_1_TITLE: 'Point one',
  CARD_2_TITLE: 'Point two',
  CARD_3_TITLE: 'Point three',
  CARD_4_TITLE: 'Point four',
  BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headX: 80,
  headY: 28,
  headW: 1760,
  headH: 72,
  colW: 480,
  colXs: [0, 480, 960, 1440],
  padX: 48,
  titleW: 384,
  titleH: 96,
  bodyH: 280,
}

function colTitleY(i) {
  return i % 2 === 0 ? 560 : 300
}

function colNumY(i) {
  return i % 2 === 0 ? 430 : 232
}

function buildBulletListGridChromeSvg() {
  const fills = GEOM.colXs.map((x, i) => {
    const opacity = i % 2 === 0 ? 0.08 : 0.03
    return `<rect x="${x}" y="0" width="${GEOM.colW}" height="1080" fill="currentColor" opacity="${opacity}" />`
  }).join('')
  const nums = GEOM.colXs.map((x, i) =>
    `<text x="${x + 40}" y="${colNumY(i)}" fill="currentColor" fill-opacity="0.22" font-size="110" font-weight="800" font-family="system-ui, sans-serif">${String(i + 1).padStart(2, '0')}</text>`
  ).join('')
  const rules = [480, 960, 1440].map((x) =>
    `<rect x="${x}" y="110" width="2" height="930" fill="currentColor" opacity="0.12" />`
  ).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <rect width="1920" height="1080" fill="#FFFFFF" />
    ${fills}
    <rect x="0" y="0" width="1920" height="110" fill="#FFFFFF" />
    <rect x="0" y="108" width="1920" height="2" fill="currentColor" opacity="0.12" />
    ${rules}
    ${nums}
  </svg>`
}

function findEl(elements, ids) {
  const set = new Set(ids)
  return (elements || []).find((e) => set.has(String(e.slotId || '').toUpperCase()))
}

function textOf(el, fallback) {
  const txt = el?.content?.text || el?.text
  if (txt && String(txt).trim()) return String(txt).trim()
  return fallback
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill
  if (fill && typeof fill === 'object' && fill.color) return fill.color
  return fallback
}

function textEl({ slotId, prev, x, y, w, h, text, fontSize, fontWeight, color, lineHeight, maxLines, sx, sy, scale, role, align }) {
  return {
    id: prev?.id || `slot-${slotId}`,
    slotId,
    type: 'text',
    role,
    layer: 10,
    placement: {
      x: Math.round(x * sx),
      y: Math.round(y * sy),
      width: Math.round(w * sx),
      height: Math.round(h * sy),
      rotation: 0,
      opacity: 1,
    },
    content: {
      text,
      fontSize: Math.round(fontSize * scale),
      fontWeight,
      color,
      align,
      verticalAlign: 'top',
      lineHeight,
      clipToSlot: true,
      maxLines,
    },
  }
}

function paletteColors(palette) {
  const pal = palette?.primary ? palette : (palette?.palette || palette || {})
  return {
    accent: pal.primary || pal.accent || '#6366F1',
    textColor: pal.text || '#0F172A',
    mutedColor: pal.muted || pal.textMuted || '#64748B',
  }
}

function buildElements({ canvasW, canvasH, heading, titles, bodies, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  const out = [
    {
      id: prev.IMAGE_CARD_BG?.id || prev.CARD_1_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildBulletListGridChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    textEl({
      slotId: 'HEADING',
      prev: prev.HEADING,
      x: GEOM.headX,
      y: GEOM.headY,
      w: GEOM.headW,
      h: GEOM.headH,
      text: heading,
      fontSize: 28,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 1,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'left',
    }),
  ]
  GEOM.colXs.forEach((colX, i) => {
    const n = i + 1
    const tx = colX + GEOM.padX
    const titleY = colTitleY(i)
    out.push(textEl({
      slotId: `CARD_${n}_TITLE`,
      prev: prev[`CARD_${n}_TITLE`],
      x: tx,
      y: titleY,
      w: GEOM.titleW,
      h: GEOM.titleH,
      text: titles[i],
      fontSize: 22,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.2,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'left',
    }))
    out.push(textEl({
      slotId: `CARD_${n}_BODY`,
      prev: prev[`CARD_${n}_BODY`],
      x: tx,
      y: titleY + GEOM.titleH + 8,
      w: GEOM.titleW,
      h: GEOM.bodyH,
      text: bodies[i],
      fontSize: 15,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.45,
      maxLines: 6,
      sx,
      sy,
      scale,
      role: 'body',
      align: 'left',
    }))
  })
  return out
}

function layoutBulletListGrid(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'HEADLINE', 'TITLE'])
  const chromeEl = findEl(elements, ['IMAGE_CARD_BG', 'CARD_1_BG'])
  const titles = [1, 2, 3, 4].map((n) => textOf(findEl(elements, [`CARD_${n}_TITLE`]), BULLET_LIST_GRID_DEFAULTS[`CARD_${n}_TITLE`]))
  const bodies = [1, 2, 3, 4].map((n) => textOf(findEl(elements, [`CARD_${n}_BODY`]), BULLET_LIST_GRID_DEFAULTS.BODY))
  const prev = { IMAGE_CARD_BG: chromeEl, CARD_1_BG: chromeEl, HEADING: headingEl }
  ;[1, 2, 3, 4].forEach((n) => {
    prev[`CARD_${n}_TITLE`] = findEl(elements, [`CARD_${n}_TITLE`])
    prev[`CARD_${n}_BODY`] = findEl(elements, [`CARD_${n}_BODY`])
  })
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, BULLET_LIST_GRID_DEFAULTS.HEADING),
    titles,
    bodies,
    accent: resolveStoredColor(chromeEl, accent),
    textColor,
    mutedColor,
    prev,
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildBulletListGridCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || BULLET_LIST_GRID_DEFAULTS.HEADING).trim(),
    titles: [1, 2, 3, 4].map((n) => String(bySlot[`CARD_${n}_TITLE`] || content[`card${n}Title`] || BULLET_LIST_GRID_DEFAULTS[`CARD_${n}_TITLE`]).trim()),
    bodies: [1, 2, 3, 4].map((n) => String(bySlot[`CARD_${n}_BODY`] || content[`card${n}Body`] || BULLET_LIST_GRID_DEFAULTS.BODY).trim()),
    accent,
    textColor,
    mutedColor,
  })
}

function bulletListGridPreviewSvg() {
  const chrome = buildBulletListGridChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  const titles = ['Point one', 'Point two', 'Point three', 'Point four']
  const nodes = GEOM.colXs.map((x, i) => {
    const y = colTitleY(i) + 36
    return `<text x="${x + 48}" y="${y}" fill="#0F172A" font-size="26" font-weight="800" font-family="system-ui, sans-serif">${titles[i]}</text>
      <text x="${x + 48}" y="${y + 48}" fill="#64748B" font-size="16" font-family="system-ui, sans-serif">A short, scannable point.</text>`
  }).join('')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    ${chrome}
    <text x="80" y="78" fill="#0F172A" font-size="32" font-weight="800" font-family="system-ui, sans-serif">Key points</text>
    ${nodes}
  </svg>`
}

module.exports = {
  isBulletListGridLayout,
  layoutBulletListGrid,
  buildBulletListGridCanvasElements,
  buildBulletListGridChromeSvg,
  BULLET_LIST_GRID_DEFAULTS,
};
