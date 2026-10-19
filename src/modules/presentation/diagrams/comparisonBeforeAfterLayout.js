function isComparisonBeforeAfterLayout(layoutId) {
  return /comparison_before_after/i.test(layoutId)
}

function renderMetricBlockSvg(w, h, color) {
  const r = 8
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w + 40} ${h + 40}" width="${w + 40}" height="${h + 40}" style="overflow:visible">
    <defs>
      <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="16" stdDeviation="24" flood-color="#000000" flood-opacity="0.1" />
      </filter>
    </defs>
    <!-- Left half slightly darker, right half normal -->
    <rect x="20" y="20" width="${w/2}" height="${h}" fill="${color}" filter="url(#shadow)" opacity="0.9" />
    <rect x="${w/2 + 20}" y="20" width="${w/2}" height="${h}" fill="${color}" filter="url(#shadow)" />
  </svg>`
}

function comparisonBeforeAfterGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  const padX = Math.round(160 * sx)
  const padY = Math.round(80 * sy)
  const headingH = Math.round(120 * sy)
  
  const contentStartY = padY + headingH + Math.round(40 * sy)
  const contentH = canvasH - contentStartY - padY
  
  const metricW = Math.round(400 * sx)
  const metricX = (canvasW - metricW) / 2
  const textColW = metricX - padX - Math.round(60 * sx)
  
  const leftX = padX
  const rightX = metricX + metricW + Math.round(60 * sx)
  
  const headerH = Math.round(80 * sy)
  
  const geom = {
    canvasW,
    canvasH,
    headingBox: { x: padX, y: padY, width: canvasW - padX * 2, height: headingH },
    leftTitle: { x: leftX, y: contentStartY, width: textColW, height: headerH },
    rightTitle: { x: rightX, y: contentStartY, width: textColW, height: headerH },
    rows: []
  }
  
  const rowH = Math.round(160 * sy)
  const rowGap = (contentH - headerH - (rowH * 3)) / 2
  
  let currentY = contentStartY + headerH + Math.round(20 * sy) // A little gap below headers
  
  for (let i = 0; i < 3; i++) {
    geom.rows.push({
      leftTitle: { x: leftX, y: currentY, width: textColW, height: Math.round(50 * sy) },
      leftBody: { x: leftX, y: currentY + Math.round(50 * sy), width: textColW, height: Math.round(100 * sy) },
      rightTitle: { x: rightX, y: currentY, width: textColW, height: Math.round(50 * sy) },
      rightBody: { x: rightX, y: currentY + Math.round(50 * sy), width: textColW, height: Math.round(100 * sy) },
      metric: { x: metricX, y: currentY + Math.round(10 * sy), width: metricW, height: rowH - Math.round(20 * sy) }
    })
    currentY += rowH + rowGap
  }

  return geom
}

const COLORS = ['#7dd3fc', '#86efac', '#a78bfa'] // Pastel blue, green, purple

function layoutComparisonBeforeAfter(docOrElements, schema, themeTokens, canvas = {}) {
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  
  if (!isComparisonBeforeAfterLayout(layoutId)) return docOrElements;
  
  const g = comparisonBeforeAfterGeom(canvasW, canvasH)
  
  let out = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'HEADING') {
      out.push({ ...el, layer: 10, placement: { ...g.headingBox, rotation: 0, opacity: 1 } })
      return
    }

    if (slotId === 'LEFT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.leftTitle, rotation: 0, opacity: 1 }, content: { ...el.content, align: 'center', verticalAlign: 'middle' } })
      return
    }
    if (slotId === 'RIGHT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.rightTitle, rotation: 0, opacity: 1 }, content: { ...el.content, align: 'center', verticalAlign: 'middle' } })
      return
    }

    const rowMatch = slotId.match(/^ROW_(\d+)_(LEFT_TITLE|LEFT_BODY|RIGHT_TITLE|RIGHT_BODY|METRIC)$/)
    if (rowMatch) {
      const rIdx = parseInt(rowMatch[1], 10) - 1
      const slotType = rowMatch[2]
      
      const rowGeom = g.rows[rIdx]
      if (!rowGeom) return
      
      let geomKey = ''
      if (slotType === 'LEFT_TITLE') geomKey = 'leftTitle'
      if (slotType === 'LEFT_BODY') geomKey = 'leftBody'
      if (slotType === 'RIGHT_TITLE') geomKey = 'rightTitle'
      if (slotType === 'RIGHT_BODY') geomKey = 'rightBody'
      if (slotType === 'METRIC') geomKey = 'metric'
      
      let newEl = {
        ...el,
        layer: 10,
        placement: { ...rowGeom[geomKey], rotation: 0, opacity: 1 },
      }
      
      if (newEl.type === 'shape' || newEl.type === 'text') {
        const align = slotType.startsWith('LEFT') ? 'right' : slotType.startsWith('RIGHT') ? 'left' : 'center'
        newEl.content = {
          ...newEl.content,
          align: align
        }
        
        // Metric text needs to be white to contrast the colored background block
        if (slotType === 'METRIC') {
          newEl.content.color = '#ffffff'
          newEl.content.colorOverride = true
          newEl.content.verticalAlign = 'middle'
        }
      }
      
      out.push(newEl)
      return
    }

    // Don't push old decorative shapes if we're going to regenerate them
    if (el.role === 'decoration' && String(el.id).startsWith('shp-')) {
      return;
    }

    out.push(el)
  })

  // Add Metric Background Blocks
  g.rows.forEach((r, i) => {
    out.unshift({
      id: `shp-metric-bg-${i}`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...r.metric, rotation: 0, opacity: 1 },
      content: { svg: renderMetricBlockSvg(r.metric.width, r.metric.height, COLORS[i % COLORS.length]), colorMode: 'preserve' }
    })
  })

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isComparisonBeforeAfterLayout,
  comparisonBeforeAfterGeom,
  layoutComparisonBeforeAfter
}
