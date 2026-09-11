function isTextTwoColumnCardsLayout(layoutId) {
  return /text_two_column_cards/i.test(layoutId)
}

function renderColumnCardSvg(w, h, color) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w + 40} ${h + 40}" width="${w + 40}" height="${h + 40}" style="overflow:visible">
    <defs>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="16" stdDeviation="24" flood-color="#000000" flood-opacity="0.05" />
      </filter>
    </defs>
    <rect x="20" y="20" width="${w}" height="${h}" rx="24" fill="${color}" filter="url(#shadow)" opacity="0.3" />
    <!-- A small decorative top-border line inside the card -->
    <path d="M44,20 L${w-4},20" stroke="${color}" stroke-width="4" stroke-linecap="round" />
  </svg>`
}

function textTwoColumnCardsGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  const padX = Math.round(160 * sx)
  const padY = Math.round(100 * sy)
  const headingH = Math.round(120 * sy)
  
  const contentStartY = padY + headingH + Math.round(40 * sy)
  const contentH = canvasH - contentStartY - padY
  
  const colGap = Math.round(80 * sx)
  const colW = (canvasW - padX * 2 - colGap) / 2
  
  // Create padding inside the cards
  const cardPadX = Math.round(60 * sx)
  const cardPadY = Math.round(60 * sy)
  
  const textColW = colW - cardPadX * 2
  const titleH = Math.round(80 * sy)
  const bodyH = contentH - cardPadY * 2 - titleH - Math.round(20 * sy)
  
  const geom = {
    canvasW,
    canvasH,
    headingBox: { x: padX, y: padY, width: canvasW - padX * 2, height: headingH },
    
    leftCard: { x: padX, y: contentStartY, width: colW, height: contentH },
    rightCard: { x: padX + colW + colGap, y: contentStartY, width: colW, height: contentH },
    
    leftTitle: { x: padX + cardPadX, y: contentStartY + cardPadY, width: textColW, height: titleH },
    leftBody: { x: padX + cardPadX, y: contentStartY + cardPadY + titleH + Math.round(20 * sy), width: textColW, height: bodyH },
    
    rightTitle: { x: padX + colW + colGap + cardPadX, y: contentStartY + cardPadY, width: textColW, height: titleH },
    rightBody: { x: padX + colW + colGap + cardPadX, y: contentStartY + cardPadY + titleH + Math.round(20 * sy), width: textColW, height: bodyH },
  }

  return geom
}

const COLORS = {
  left: '#3b82f6', // Pastel blue base
  right: '#a855f7' // Pastel purple base
}

function layoutTextTwoColumnCards(docOrElements, schema, themeTokens, canvas = {}) {
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  const mode = schema?.mode || ''
  
  if (!isTextTwoColumnCardsLayout(mode) && !isTextTwoColumnCardsLayout(layoutId)) return docOrElements;
  
  const g = textTwoColumnCardsGeom(canvasW, canvasH)
  
  let out = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'HEADING') {
      out.push({ ...el, layer: 10, placement: { ...g.headingBox, rotation: 0, opacity: 1 }, content: { ...el.content, align: 'center' } })
      return
    }

    if (slotId === 'LEFT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.leftTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: COLORS.left, colorOverride: true, align: 'center' } })
      return
    }
    
    if (slotId === 'LEFT_BODY') {
      out.push({ ...el, layer: 10, placement: { ...g.leftBody, rotation: 0, opacity: 1 } })
      return
    }
    
    if (slotId === 'RIGHT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.rightTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: COLORS.right, colorOverride: true, align: 'center' } })
      return
    }
    
    if (slotId === 'RIGHT_BODY') {
      out.push({ ...el, layer: 10, placement: { ...g.rightBody, rotation: 0, opacity: 1 } })
      return
    }

    if (el.role === 'decoration' && String(el.id).startsWith('shp-')) {
      return;
    }

    out.push(el)
  })

  // Add Cards Background
  out.unshift({
    id: 'shp-left-card',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.leftCard, x: g.leftCard.x - 20, y: g.leftCard.y - 20, width: g.leftCard.width + 40, height: g.leftCard.height + 40, rotation: 0, opacity: 1 },
    content: { svg: renderColumnCardSvg(g.leftCard.width, g.leftCard.height, COLORS.left), colorMode: 'preserve' }
  })
  
  out.unshift({
    id: 'shp-right-card',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.rightCard, x: g.rightCard.x - 20, y: g.rightCard.y - 20, width: g.rightCard.width + 40, height: g.rightCard.height + 40, rotation: 0, opacity: 1 },
    content: { svg: renderColumnCardSvg(g.rightCard.width, g.rightCard.height, COLORS.right), colorMode: 'preserve' }
  })

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isTextTwoColumnCardsLayout,
  textTwoColumnCardsGeom,
  layoutTextTwoColumnCards
}
