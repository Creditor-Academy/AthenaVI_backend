/**
 * Comparison Side By Side Centerline
 * Layout ID: comparison_side_by_side_centerline_v1
 *
 * Split reading columns with a vertical accent rule.
 * Distinct from Side By Side (VS cards) and Side By Side Cards (fill vs outline).
 */

function isComparisonSideBySideCenterlineLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  return id === 'comparison_side_by_side_centerline_v1' || id === 'comparison_side_by_side_centerline'
}

const COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS = {
  HEADING: 'Compare options',
  LEFT_TITLE: 'Option A',
  RIGHT_TITLE: 'Option B',
  LEFT_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  RIGHT_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headX: 160,
  headY: 56,
  headW: 1600,
  headH: 110,
  ruleX: 958,
  ruleY: 200,
  ruleW: 4,
  ruleH: 780,
  leftTitleX: 80,
  rightTitleX: 1040,
  titleY: 210,
  titleW: 800,
  titleH: 100,
  leftBodyX: 110,
  rightBodyX: 1070,
  bodyY: 330,
  bodyW: 740,
  bodyH: 640,
}

function buildComparisonSideBySideCenterlineChromeSvg() {
  const { ruleX, ruleY, ruleW, ruleH } = GEOM
  const cx = 960
  const cy = ruleY + ruleH / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <rect width="1920" height="1080" fill="#FFFFFF" />
    <rect width="960" height="1080" fill="currentColor" opacity="0.05" />
    <circle cx="120" cy="140" r="140" fill="currentColor" opacity="0.05" />
    <circle cx="1800" cy="980" r="160" fill="currentColor" opacity="0.04" />
    <rect x="${ruleX}" y="${ruleY}" width="${ruleW}" height="${ruleH}" rx="2" fill="currentColor" />
    <circle cx="${cx}" cy="${cy}" r="28" fill="#FFFFFF" />
    <circle cx="${cx}" cy="${cy}" r="28" fill="none" stroke="currentColor" stroke-width="3" />
    <circle cx="${cx}" cy="${cy}" r="8" fill="currentColor" />
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

function buildElements({ canvasW, canvasH, heading, leftTitle, rightTitle, leftBody, rightBody, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW
  const sy = canvasH / GEOM.viewH
  const scale = Math.min(sx, sy)
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildComparisonSideBySideCenterlineChromeSvg(),
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
      fontSize: 34,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'center',
    }),
    textEl({
      slotId: 'LEFT_TITLE',
      prev: prev.LEFT_TITLE,
      x: GEOM.leftTitleX,
      y: GEOM.titleY,
      w: GEOM.titleW,
      h: GEOM.titleH,
      text: leftTitle,
      fontSize: 26,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'center',
    }),
    textEl({
      slotId: 'LEFT_BODY',
      prev: prev.LEFT_BODY,
      x: GEOM.leftBodyX,
      y: GEOM.bodyY,
      w: GEOM.bodyW,
      h: GEOM.bodyH,
      text: leftBody,
      fontSize: 16,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.5,
      maxLines: 10,
      sx,
      sy,
      scale,
      role: 'body',
      align: 'center',
    }),
    textEl({
      slotId: 'RIGHT_TITLE',
      prev: prev.RIGHT_TITLE,
      x: GEOM.rightTitleX,
      y: GEOM.titleY,
      w: GEOM.titleW,
      h: GEOM.titleH,
      text: rightTitle,
      fontSize: 26,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'center',
    }),
    textEl({
      slotId: 'RIGHT_BODY',
      prev: prev.RIGHT_BODY,
      x: GEOM.rightBodyX,
      y: GEOM.bodyY,
      w: GEOM.bodyW,
      h: GEOM.bodyH,
      text: rightBody,
      fontSize: 16,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.5,
      maxLines: 10,
      sx,
      sy,
      scale,
      role: 'body',
      align: 'center',
    }),
  ]
}

function layoutComparisonSideBySideCenterline(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'HEADLINE', 'TITLE'])
  const chromeEl = findEl(elements, ['IMAGE_CARD_BG', 'BAND'])
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.HEADING),
    leftTitle: textOf(findEl(elements, ['LEFT_TITLE']), COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.LEFT_TITLE),
    rightTitle: textOf(findEl(elements, ['RIGHT_TITLE']), COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.RIGHT_TITLE),
    leftBody: textOf(findEl(elements, ['LEFT_BODY']), COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.LEFT_BODY),
    rightBody: textOf(findEl(elements, ['RIGHT_BODY']), COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.RIGHT_BODY),
    accent: resolveStoredColor(chromeEl, accent),
    textColor,
    mutedColor,
    prev: {
      IMAGE_CARD_BG: chromeEl,
      HEADING: headingEl,
      LEFT_TITLE: findEl(elements, ['LEFT_TITLE']),
      RIGHT_TITLE: findEl(elements, ['RIGHT_TITLE']),
      LEFT_BODY: findEl(elements, ['LEFT_BODY']),
      RIGHT_BODY: findEl(elements, ['RIGHT_BODY']),
    },
  })
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

function buildComparisonSideBySideCenterlineCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.HEADING).trim(),
    leftTitle: String(bySlot.LEFT_TITLE || content.leftTitle || COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.LEFT_TITLE).trim(),
    rightTitle: String(bySlot.RIGHT_TITLE || content.rightTitle || COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.RIGHT_TITLE).trim(),
    leftBody: String(bySlot.LEFT_BODY || content.leftBody || COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.LEFT_BODY).trim(),
    rightBody: String(bySlot.RIGHT_BODY || content.rightBody || COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS.RIGHT_BODY).trim(),
    accent,
    textColor,
    mutedColor,
  })
}

function comparisonSideBySideCenterlinePreviewSvg() {
  const chrome = buildComparisonSideBySideCenterlineChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    ${chrome}
    <text x="960" y="122" text-anchor="middle" fill="#0F172A" font-size="42" font-weight="800" font-family="system-ui, sans-serif">Compare options</text>
    <text x="480" y="270" text-anchor="middle" fill="#0F172A" font-size="32" font-weight="800" font-family="system-ui, sans-serif">Option A</text>
    <text x="480" y="380" text-anchor="middle" fill="#64748B" font-size="20" font-family="system-ui, sans-serif">Clear strengths on this side of the line.</text>
    <text x="1440" y="270" text-anchor="middle" fill="#0F172A" font-size="32" font-weight="800" font-family="system-ui, sans-serif">Option B</text>
    <text x="1440" y="380" text-anchor="middle" fill="#64748B" font-size="20" font-family="system-ui, sans-serif">The matching case, equally easy to scan.</text>
  </svg>`
}

module.exports = {
  isComparisonSideBySideCenterlineLayout,
  layoutComparisonSideBySideCenterline,
  buildComparisonSideBySideCenterlineCanvasElements,
  buildComparisonSideBySideCenterlineChromeSvg,
  COMPARISON_SIDE_BY_SIDE_CENTERLINE_DEFAULTS,
};
