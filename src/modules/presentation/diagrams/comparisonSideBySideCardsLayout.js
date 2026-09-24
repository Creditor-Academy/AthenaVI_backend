/**
 * Comparison Side By Side Cards
 * Layout ID: comparison_side_by_side_cards_v1
 *
 * Filled accent card vs outlined card. Distinct from Side By Side (VS pair)
 * and Centerline (old split).
 */

function isComparisonSideBySideCardsLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  return id === 'comparison_side_by_side_cards_v1' || id === 'comparison_side_by_side_cards'
}

const COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS = {
  HEADING: 'Compare options',
  LEFT_TITLE: 'Option A',
  RIGHT_TITLE: 'Option B',
  LEFT_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  RIGHT_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
}

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  headX: 120,
  headY: 52,
  headW: 1680,
  headH: 100,
  leftX: 90,
  rightX: 1010,
  cardY: 180,
  cardW: 820,
  cardH: 810,
  railW: 12,
  titlePadX: 56,
  titleY: 280,
  titleH: 100,
  bodyY: 400,
  bodyH: 540,
}

function buildComparisonSideBySideCardsChromeSvg() {
  const { leftX, rightX, cardY, cardW, cardH, railW } = GEOM
  const rx = 32
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <rect width="1920" height="1080" fill="#F8FAFC" />
    <circle cx="1680" cy="80" r="200" fill="currentColor" opacity="0.07" />
    <circle cx="140" cy="1000" r="160" fill="currentColor" opacity="0.05" />
    <rect x="${leftX + 14}" y="${cardY + 18}" width="${cardW}" height="${cardH}" rx="${rx}" fill="currentColor" opacity="0.16" />
    <rect x="${leftX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${rx}" fill="currentColor" />
    <circle cx="${leftX + 72}" cy="${cardY + 64}" r="28" fill="#FFFFFF" opacity="0.18" />
    <text x="${leftX + 72}" y="${cardY + 72}" text-anchor="middle" fill="#FFFFFF" font-size="18" font-weight="800" font-family="system-ui, sans-serif">01</text>
    <rect x="${rightX + 14}" y="${cardY + 18}" width="${cardW}" height="${cardH}" rx="${rx}" fill="currentColor" opacity="0.08" />
    <rect x="${rightX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${rx}" fill="#FFFFFF" />
    <rect x="${rightX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${rx}" fill="none" stroke="currentColor" stroke-width="2" opacity="0.18" />
    <rect x="${rightX}" y="${cardY + rx}" width="${railW}" height="${cardH - rx * 2}" fill="currentColor" />
    <rect x="${rightX}" y="${cardY}" width="${rx + 4}" height="${rx}" fill="currentColor" />
    <rect x="${rightX}" y="${cardY + cardH - rx}" width="${rx + 4}" height="${rx}" fill="currentColor" />
    <circle cx="${rightX + 72}" cy="${cardY + 64}" r="28" fill="currentColor" opacity="0.12" />
    <text x="${rightX + 72}" y="${cardY + 72}" text-anchor="middle" fill="currentColor" font-size="18" font-weight="800" font-family="system-ui, sans-serif">02</text>
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
  const titleW = GEOM.cardW - GEOM.titlePadX * 2
  const leftTextX = GEOM.leftX + GEOM.titlePadX
  const rightTextX = GEOM.rightX + GEOM.titlePadX
  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildComparisonSideBySideCardsChromeSvg(),
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
      fontSize: 32,
      fontWeight: 800,
      color: textColor,
      lineHeight: 1.15,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'left',
    }),
    textEl({
      slotId: 'LEFT_TITLE',
      prev: prev.LEFT_TITLE,
      x: leftTextX,
      y: GEOM.titleY,
      w: titleW,
      h: GEOM.titleH,
      text: leftTitle,
      fontSize: 26,
      fontWeight: 800,
      color: '#FFFFFF',
      lineHeight: 1.15,
      maxLines: 2,
      sx,
      sy,
      scale,
      role: 'heading',
      align: 'left',
    }),
    textEl({
      slotId: 'LEFT_BODY',
      prev: prev.LEFT_BODY,
      x: leftTextX,
      y: GEOM.bodyY,
      w: titleW,
      h: GEOM.bodyH,
      text: leftBody,
      fontSize: 16,
      fontWeight: 400,
      color: 'rgba(255,255,255,0.86)',
      lineHeight: 1.5,
      maxLines: 9,
      sx,
      sy,
      scale,
      role: 'body',
      align: 'left',
    }),
    textEl({
      slotId: 'RIGHT_TITLE',
      prev: prev.RIGHT_TITLE,
      x: rightTextX,
      y: GEOM.titleY,
      w: titleW,
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
      align: 'left',
    }),
    textEl({
      slotId: 'RIGHT_BODY',
      prev: prev.RIGHT_BODY,
      x: rightTextX,
      y: GEOM.bodyY,
      w: titleW,
      h: GEOM.bodyH,
      text: rightBody,
      fontSize: 16,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.5,
      maxLines: 9,
      sx,
      sy,
      scale,
      role: 'body',
      align: 'left',
    }),
  ]
}

function layoutComparisonSideBySideCards(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'HEADLINE', 'TITLE'])
  const chromeEl = findEl(elements, ['IMAGE_CARD_BG', 'BAND'])
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.HEADING),
    leftTitle: textOf(findEl(elements, ['LEFT_TITLE']), COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.LEFT_TITLE),
    rightTitle: textOf(findEl(elements, ['RIGHT_TITLE']), COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.RIGHT_TITLE),
    leftBody: textOf(findEl(elements, ['LEFT_BODY']), COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.LEFT_BODY),
    rightBody: textOf(findEl(elements, ['RIGHT_BODY']), COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.RIGHT_BODY),
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

function buildComparisonSideBySideCardsCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.HEADING).trim(),
    leftTitle: String(bySlot.LEFT_TITLE || content.leftTitle || COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.LEFT_TITLE).trim(),
    rightTitle: String(bySlot.RIGHT_TITLE || content.rightTitle || COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.RIGHT_TITLE).trim(),
    leftBody: String(bySlot.LEFT_BODY || content.leftBody || COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.LEFT_BODY).trim(),
    rightBody: String(bySlot.RIGHT_BODY || content.rightBody || COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS.RIGHT_BODY).trim(),
    accent,
    textColor,
    mutedColor,
  })
}

function comparisonSideBySideCardsPreviewSvg() {
  const chrome = buildComparisonSideBySideCardsChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    ${chrome}
    <text x="120" y="118" fill="#0F172A" font-size="40" font-weight="800" font-family="system-ui, sans-serif">Compare options</text>
    <text x="146" y="340" fill="#FFFFFF" font-size="32" font-weight="800" font-family="system-ui, sans-serif">Option A</text>
    <text x="146" y="440" fill="#FFFFFF" fill-opacity="0.86" font-size="20" font-family="system-ui, sans-serif">The featured path — strengths and fit at a glance.</text>
    <text x="1066" y="340" fill="#0F172A" font-size="32" font-weight="800" font-family="system-ui, sans-serif">Option B</text>
    <text x="1066" y="440" fill="#64748B" font-size="20" font-family="system-ui, sans-serif">The alternative, with matching depth on a quiet card.</text>
  </svg>`
}

module.exports = {
  isComparisonSideBySideCardsLayout,
  layoutComparisonSideBySideCards,
  buildComparisonSideBySideCardsCanvasElements,
  buildComparisonSideBySideCardsChromeSvg,
  COMPARISON_SIDE_BY_SIDE_CARDS_DEFAULTS,
};
