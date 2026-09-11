/** Custom shapes for bullet_list_cards_v1 and bullet_list_grid_v1 layouts */

function isBulletListCardsLayout(layoutId) {
  return /bullet_list_(cards|grid)/i.test(String(layoutId || ''))
}

function bulletListCardsGeom(canvasW = 1920, canvasH = 1080, isGrid = false) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  if (isGrid) {
    const colW = canvasW / 4
    const cards = [0, 1, 2, 3].map((i) => {
      const cx = i * colW
      const isDown = i % 2 === 0
      const contentStartY = isDown ? canvasH / 2 + Math.round(50 * sy) : Math.round(150 * sy)
      
      const titleY = contentStartY + Math.round(200 * sy)
      const bodyY = titleY + Math.round(120 * sy)
      
      return {
        bg: { x: cx, y: 0, width: colW, height: canvasH },
        title: { x: cx + Math.round(60 * sx), y: titleY, width: colW - Math.round(120 * sx), height: Math.round(100 * sy) },
        body: { x: cx + Math.round(60 * sx), y: bodyY, width: colW - Math.round(120 * sx), height: Math.round(300 * sy) }
      }
    })
    return {
      canvasW,
      canvasH,
      headingBox: { x: -1000, y: -1000, width: 10, height: 10 }, // Hide heading for grid
      cards
    }
  }

  // Cards Variant
  const padX = Math.round(100 * sx)
  const padY = Math.round(100 * sy)
  const headingH = Math.round(120 * sy)
  const gapY = Math.round(80 * sy)
  
  const contentW = canvasW - padX * 2
  const cardGap = Math.round(40 * sx)
  const cardW = Math.round((contentW - cardGap * 3) / 4)
  
  const contentStartY = padY + headingH + gapY
  const cardH = canvasH - contentStartY - padY - Math.round(50 * sy)

  const headingBox = {
    x: padX,
    y: padY,
    width: contentW,
    height: headingH,
  }

  const cards = [0, 1, 2, 3].map((i) => {
    const cx = padX + i * (cardW + cardGap)
    return {
      bg: { x: cx, y: contentStartY, width: cardW, height: cardH },
      title: { x: cx + Math.round(40 * sx), y: contentStartY + Math.round(180 * sy), width: cardW - Math.round(80 * sx), height: Math.round(80 * sy) },
      body: { x: cx + Math.round(40 * sx), y: contentStartY + Math.round(260 * sy), width: cardW - Math.round(80 * sx), height: cardH - Math.round(320 * sy) }
    }
  })

  return {
    canvasW,
    canvasH,
    headingBox,
    cards
  }
}

function renderCardSvg(w, h, idx) {
  const r = 24
  const CARD_COLORS = ['#bae6fd', '#bbf7d0', '#e9d5ff', '#fbcfe8']
  const bg = CARD_COLORS[idx] || CARD_COLORS[0]
  const numColor = '#1f2937'
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-20 -20 ${w + 40} ${h + 80}" width="${w + 40}" height="${h + 80}" style="overflow:visible">
    <defs>
      <filter id="shadow-${idx}" x="-10%" y="-10%" width="130%" height="130%">
        <feDropShadow dx="0" dy="16" stdDeviation="24" flood-color="#000000" flood-opacity="0.1"/>
      </filter>
    </defs>
    <!-- Background colored panel slightly offset to right and top -->
    <rect x="16" y="-12" width="${w}" height="${h}" rx="${r}" fill="${bg}" />
    <!-- Main white card -->
    <rect x="0" y="0" width="${w}" height="${h}" rx="${r}" fill="#ffffff" filter="url(#shadow-${idx})" />
    
    <!-- Decorative Icon (Circle + Line) -->
    <g transform="translate(${w/2}, 60)" stroke="${bg}" stroke-width="3" fill="none">
      <circle cx="0" cy="0" r="24" stroke-opacity="0.2" fill="${bg}" fill-opacity="0.05" />
      <path d="M -10 -10 L 10 10 M -10 10 L 10 -10" stroke-linecap="round" />
    </g>

    <!-- Number Circle at bottom center -->
    <circle cx="${w/2}" cy="${h}" r="32" fill="${bg}" />
    <text x="${w/2}" y="${h + 10}" text-anchor="middle" font-size="28" font-weight="800" fill="${numColor}" font-family="system-ui, sans-serif">0${idx + 1}</text>
  </svg>`
}

function renderGridSvg(w, h, idx) {
  const GRID_COLORS = ['#e0f2fe', '#dcfce7', '#f3e8ff', '#fce7f3']
  const bg = GRID_COLORS[idx] || GRID_COLORS[0]
  const isDown = idx % 2 === 0
  
  // contentStartY is matching the layout logic
  const contentStartY = isDown ? h / 2 + 50 : 150
  
  // Arrow points to the next column's content
  const nextIsDown = (idx + 1) % 2 === 0
  const arrowY = nextIsDown ? h / 2 + 100 : 200
  
  // Arrow on right edge (except last col)
  const arrow = idx < 3 ? `<path d="M ${w} ${arrowY - 24} L ${w + 24} ${arrowY} L ${w} ${arrowY + 24} Z" fill="${bg}" />` : ''
  
  const textY = contentStartY + 140
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w + 24} ${h}" width="${w + 24}" height="${h}" style="overflow:visible">
    <rect x="0" y="0" width="${w}" height="${h}" fill="${bg}" />
    ${arrow}
    <text x="60" y="${textY}" font-size="160" font-weight="300" fill="rgba(31,41,55,0.4)" font-family="system-ui, sans-serif">${idx + 1}</text>
  </svg>`
}

function layoutBulletListCards(docOrElements, schema, themeTokens, canvas = {}) {
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  const isGrid = /grid/i.test(layoutId)
  
  const g = bulletListCardsGeom(canvasW, canvasH, isGrid)
  
  let out = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'HEADING') {
      out.push({
        ...el,
        layer: 10,
        placement: { ...g.headingBox, rotation: 0, opacity: 1 },
      })
      return
    }

    const cardMatch = slotId.match(/^CARD_(\d+)_(BG|TITLE|BODY)$/)
    if (cardMatch) {
      const idx = parseInt(cardMatch[1], 10) - 1
      const type = cardMatch[2]
      const cardGeom = g.cards[idx]
      
      if (!cardGeom) return

      if (type === 'BG') {
        out.push({
          ...el,
          type: 'graphic',
          layer: 2,
          placement: { ...cardGeom.bg, rotation: 0, opacity: 1 },
          content: {
            svg: isGrid ? renderGridSvg(cardGeom.bg.width, cardGeom.bg.height, idx) : renderCardSvg(cardGeom.bg.width, cardGeom.bg.height, idx),
            colorMode: 'preserve'
          }
        })
      } else if (type === 'TITLE' || type === 'BODY') {
        const isDarkBg = false // We use light neutral colors for all columns
        const textColor = '#1f2937'
        
        let newEl = {
          ...el,
          layer: 10,
          placement: { ...cardGeom[type.toLowerCase()], rotation: 0, opacity: 1 },
        }
        
        if (newEl.type === 'shape' || newEl.type === 'text') {
          newEl.content = {
            ...newEl.content,
            color: textColor,
            colorOverride: true
          }
          if (type === 'TITLE' && !isGrid) {
            newEl.content.align = 'center'
          }
          if (type === 'BODY' && !isGrid) {
            newEl.content.align = 'center'
          }
        }
        
        out.push(newEl)
      }
      return
    }

    out.push(el)
  })

  // Ensure backgrounds exist even if the template dropped them
  ;[0, 1, 2, 3].forEach(idx => {
    const slotId = `CARD_${idx + 1}_BG`
    if (!out.some(el => String(el.slotId || '').toUpperCase() === slotId)) {
      const cardGeom = g.cards[idx]
      out.unshift({
        id: `shp-card-bg-${idx}`,
        type: 'graphic',
        layer: 1,
        role: 'decoration',
        slotId,
        placement: { ...cardGeom.bg, rotation: 0, opacity: 1 },
        content: {
          svg: isGrid ? renderGridSvg(cardGeom.bg.width, cardGeom.bg.height, idx) : renderCardSvg(cardGeom.bg.width, cardGeom.bg.height, idx),
          colorMode: 'preserve'
        }
      })
    }
  })

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isBulletListCardsLayout,
  layoutBulletListCards,
  bulletListCardsGeom,
};
