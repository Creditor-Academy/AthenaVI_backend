/**
 * Comparison Side By Side
 * Layout ID: comparison_side_by_side_v1
 *
 * Two equal option cards under a heading, with a VS mark in the gap.
 * Twin `_centerline` has its own engine. `_cards` has its own engine.
 */

function isComparisonSideBySideLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  if (id.includes('_cards') || id.includes('_centerline')) return false
  return id === 'comparison_side_by_side_v1' || id === 'comparison_side_by_side'
}

function isComparisonSideBySideTwinLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase()
  return id === 'comparison_side_by_side_centerline_v1' || id === 'comparison_side_by_side_centerline'
}

const COMPARISON_SIDE_BY_SIDE_DEFAULTS = {
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
  headY: 64,
  headW: 1680,
  headH: 110,
  leftX: 100,
  rightX: 1020,
  cardY: 200,
  cardW: 800,
  cardH: 780,
  barH: 10,
  titlePadX: 48,
  titleY: 248,
  titleH: 100,
  bodyY: 368,
  bodyH: 560,
}

function buildComparisonSideBySideChromeSvg() {
  const { leftX, rightX, cardY, cardW, cardH, barH } = GEOM
  const rx = 28
  const vsCx = 960
  const vsCy = cardY + cardH / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <rect width="1920" height="1080" fill="#FFFFFF" />
    <rect width="1920" height="1080" fill="currentColor" opacity="0.04" />
    <circle cx="1760" cy="80" r="180" fill="currentColor" opacity="0.06" />
    <circle cx="120" cy="1000" r="140" fill="currentColor" opacity="0.05" />
    <rect x="${leftX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${rx}" fill="#FFFFFF" />
    <rect x="${leftX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${rx}" fill="none" stroke="currentColor" stroke-width="2" opacity="0.14" />
    <path d="M ${leftX} ${cardY + barH} L ${leftX + cardW} ${cardY + barH} L ${leftX + cardW} ${cardY + rx} Q ${leftX + cardW} ${cardY} ${leftX + cardW - rx} ${cardY} L ${leftX + rx} ${cardY} Q ${leftX} ${cardY} ${leftX} ${cardY + rx} Z" fill="currentColor" />
    <rect x="${rightX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${rx}" fill="#FFFFFF" />
    <rect x="${rightX}" y="${cardY}" width="${cardW}" height="${cardH}" rx="${rx}" fill="none" stroke="currentColor" stroke-width="2" opacity="0.14" />
    <path d="M ${rightX} ${cardY + barH} L ${rightX + cardW} ${cardY + barH} L ${rightX + cardW} ${cardY + rx} Q ${rightX + cardW} ${cardY} ${rightX + cardW - rx} ${cardY} L ${rightX + rx} ${cardY} Q ${rightX} ${cardY} ${rightX} ${cardY + rx} Z" fill="currentColor" />
    <circle cx="${vsCx}" cy="${vsCy}" r="46" fill="#FFFFFF" />
    <circle cx="${vsCx}" cy="${vsCy}" r="46" fill="none" stroke="currentColor" stroke-width="3" />
    <text x="${vsCx}" y="${vsCy + 8}" text-anchor="middle" fill="currentColor" font-size="22" font-weight="800" font-family="system-ui, sans-serif">VS</text>
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
      id: prev.IMAGE_CARD_BG?.id || prev.BAND?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildComparisonSideBySideChromeSvg(),
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
      x: leftTextX,
      y: GEOM.titleY,
      w: titleW,
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
      color: mutedColor,
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

function layoutComparisonSideBySide(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080
  const { accent, textColor, mutedColor } = paletteColors(palette)
  const headingEl = findEl(elements, ['HEADING', 'HEADLINE', 'TITLE'])
  const chromeEl = findEl(elements, ['IMAGE_CARD_BG', 'BAND'])
  const out = buildElements({
    canvasW,
    canvasH,
    heading: textOf(headingEl, COMPARISON_SIDE_BY_SIDE_DEFAULTS.HEADING),
    leftTitle: textOf(findEl(elements, ['LEFT_TITLE']), COMPARISON_SIDE_BY_SIDE_DEFAULTS.LEFT_TITLE),
    rightTitle: textOf(findEl(elements, ['RIGHT_TITLE']), COMPARISON_SIDE_BY_SIDE_DEFAULTS.RIGHT_TITLE),
    leftBody: textOf(findEl(elements, ['LEFT_BODY']), COMPARISON_SIDE_BY_SIDE_DEFAULTS.LEFT_BODY),
    rightBody: textOf(findEl(elements, ['RIGHT_BODY']), COMPARISON_SIDE_BY_SIDE_DEFAULTS.RIGHT_BODY),
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

function buildComparisonSideBySideCanvasElements({ schema, options = {} } = {}) {
  const canvasW = options.canvas?.width || 1920
  const canvasH = options.canvas?.height || 1080
  const content = options.content || {}
  const bySlot = options.contentBySlotId || {}
  const { accent, textColor, mutedColor } = paletteColors(options.palette || {})
  return buildElements({
    canvasW,
    canvasH,
    heading: String(bySlot.HEADING || content.heading || content.title || COMPARISON_SIDE_BY_SIDE_DEFAULTS.HEADING).trim(),
    leftTitle: String(bySlot.LEFT_TITLE || content.leftTitle || COMPARISON_SIDE_BY_SIDE_DEFAULTS.LEFT_TITLE).trim(),
    rightTitle: String(bySlot.RIGHT_TITLE || content.rightTitle || COMPARISON_SIDE_BY_SIDE_DEFAULTS.RIGHT_TITLE).trim(),
    leftBody: String(bySlot.LEFT_BODY || content.leftBody || COMPARISON_SIDE_BY_SIDE_DEFAULTS.LEFT_BODY).trim(),
    rightBody: String(bySlot.RIGHT_BODY || content.rightBody || COMPARISON_SIDE_BY_SIDE_DEFAULTS.RIGHT_BODY).trim(),
    accent,
    textColor,
    mutedColor,
  })
}

function comparisonSideBySidePreviewSvg() {
  const chrome = buildComparisonSideBySideChromeSvg()
    .replace(/currentColor/g, '#6366F1')
    .replace(/^<svg[^>]*>/, '')
    .replace(/<\/svg>\s*$/, '')
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%">
    ${chrome}
    <text x="960" y="130" text-anchor="middle" fill="#0F172A" font-size="42" font-weight="800" font-family="system-ui, sans-serif">Compare options</text>
    <text x="148" y="310" fill="#0F172A" font-size="32" font-weight="800" font-family="system-ui, sans-serif">Option A</text>
    <text x="148" y="410" fill="#64748B" font-size="20" font-family="system-ui, sans-serif">Clear strengths, trade-offs, and fit for this choice.</text>
    <text x="1068" y="310" fill="#0F172A" font-size="32" font-weight="800" font-family="system-ui, sans-serif">Option B</text>
    <text x="1068" y="410" fill="#64748B" font-size="20" font-family="system-ui, sans-serif">The alternative path with a matching depth of detail.</text>
  </svg>`
}

function renderCardSvg(w, h, color) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w + 40} ${h + 40}" width="${w + 40}" height="${h + 40}" style="overflow:visible">
    <defs>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="16" stdDeviation="24" flood-color="#000000" flood-opacity="0.05" />
      </filter>
    </defs>
    <rect x="20" y="20" width="${w}" height="${h}" rx="24" fill="${color}" filter="url(#shadow)" opacity="0.3" />
    <path d="M44,20 L${w - 4},20" stroke="${color}" stroke-width="4" stroke-linecap="round" />
  </svg>`
}

function comparisonSideBySideGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const padX = Math.round(160 * sx)
  const padY = Math.round(100 * sy)
  const headingH = Math.round(120 * sy)
  const contentStartY = padY + headingH + Math.round(60 * sy)
  const contentH = canvasH - contentStartY - padY
  const colGap = Math.round(120 * sx)
  const colW = (canvasW - padX * 2 - colGap) / 2
  const cardPadX = Math.round(60 * sx)
  const cardPadY = Math.round(60 * sy)
  const textColW = colW - cardPadX * 2
  const titleH = Math.round(80 * sy)
  const bodyH = contentH - cardPadY * 2 - titleH - Math.round(20 * sy)
  return {
    canvasW,
    canvasH,
    headingBox: { x: padX, y: padY, width: canvasW - padX * 2, height: headingH },
    leftCard: { x: padX, y: contentStartY, width: colW, height: contentH },
    rightCard: { x: padX + colW + colGap, y: contentStartY, width: colW, height: contentH },
    leftTitle: { x: padX + cardPadX, y: contentStartY + cardPadY, width: textColW, height: titleH },
    leftBody: { x: padX + cardPadX, y: contentStartY + cardPadY + titleH + Math.round(20 * sy), width: textColW, height: bodyH },
    rightTitle: { x: padX + colW + colGap + cardPadX, y: contentStartY + cardPadY, width: textColW, height: titleH },
    rightBody: { x: padX + colW + colGap + cardPadX, y: contentStartY + cardPadY + titleH + Math.round(20 * sy), width: textColW, height: bodyH },
    centerline: {
      x: canvasW / 2,
      y: contentStartY + Math.round(40 * sy),
      width: 2,
      height: contentH - Math.round(80 * sy),
    },
  }
}

const TWIN_COLORS = {
  left: '#3b82f6',
  right: '#a855f7',
}

function layoutComparisonSideBySideTwin(docOrElements, schema, themeTokens, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements
  if (!Array.isArray(elements)) return docOrElements
  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  const isCards = /_cards/i.test(layoutId)
  const isCenterline = /_centerline/i.test(layoutId)
  const g = comparisonSideBySideGeom(canvasW, canvasH)
  const out = []
  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    if (slotId === 'HEADING') {
      out.push({ ...el, layer: 10, placement: { ...g.headingBox, rotation: 0, opacity: 1 }, content: { ...el.content, align: 'center' } })
      return
    }
    if (slotId === 'LEFT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.leftTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: isCards ? TWIN_COLORS.left : undefined, colorOverride: isCards, align: 'center' } })
      return
    }
    if (slotId === 'LEFT_BODY') {
      out.push({ ...el, layer: 10, placement: { ...g.leftBody, rotation: 0, opacity: 1 } })
      return
    }
    if (slotId === 'RIGHT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.rightTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: isCards ? TWIN_COLORS.right : undefined, colorOverride: isCards, align: 'center' } })
      return
    }
    if (slotId === 'RIGHT_BODY') {
      out.push({ ...el, layer: 10, placement: { ...g.rightBody, rotation: 0, opacity: 1 } })
      return
    }
    if (el.role === 'decoration' && String(el.id).startsWith('shp-')) return
    out.push(el)
  })
  if (isCards) {
    out.unshift({
      id: 'shp-left-card',
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...g.leftCard, x: g.leftCard.x - 20, y: g.leftCard.y - 20, width: g.leftCard.width + 40, height: g.leftCard.height + 40, rotation: 0, opacity: 1 },
      content: { svg: renderCardSvg(g.leftCard.width, g.leftCard.height, TWIN_COLORS.left), colorMode: 'preserve' },
    })
    out.unshift({
      id: 'shp-right-card',
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...g.rightCard, x: g.rightCard.x - 20, y: g.rightCard.y - 20, width: g.rightCard.width + 40, height: g.rightCard.height + 40, rotation: 0, opacity: 1 },
      content: { svg: renderCardSvg(g.rightCard.width, g.rightCard.height, TWIN_COLORS.right), colorMode: 'preserve' },
    })
  }
  if (isCenterline) {
    out.unshift({
      id: 'shp-centerline',
      type: 'shape',
      layer: 2,
      role: 'decoration',
      placement: { ...g.centerline, rotation: 0, opacity: 0.2 },
      content: { shape: 'rectangle', fill: '#6b7280' },
    })
  }
  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

module.exports = {
  isComparisonSideBySideLayout,
  isComparisonSideBySideTwinLayout,
  layoutComparisonSideBySide,
  layoutComparisonSideBySideTwin,
  buildComparisonSideBySideCanvasElements,
  buildComparisonSideBySideChromeSvg,
  comparisonSideBySideGeom,
  COMPARISON_SIDE_BY_SIDE_DEFAULTS,
};
