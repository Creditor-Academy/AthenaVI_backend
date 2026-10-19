function isTitleFullbleedLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'title_fullbleed_v1' || id === 'title_fullbleed'
}

function buildTitleFullbleedScrimSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <radialGradient id="tfbVignette" cx="50%" cy="48%" r="72%">
        <stop offset="0%" stop-color="#020617" stop-opacity="0.18" />
        <stop offset="55%" stop-color="#020617" stop-opacity="0.34" />
        <stop offset="100%" stop-color="#020617" stop-opacity="0.62" />
      </radialGradient>
    </defs>
    <rect width="1920" height="1080" fill="url(#tfbVignette)" />
    <rect x="908" y="612" width="104" height="3" rx="1.5" fill="#FFFFFF" fill-opacity="0.92" />
  </svg>`
}

function layoutTitleFullbleed(docOrElements, schema, themeTokens, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || [])
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1920
  const canvasH = canvas.height || docOrElements?.canvas?.height || 1080
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  const scale = Math.min(sx, sy)

  const findText = (matcher, fallback = '') => {
    const el = elements.find((e) => matcher(String(e.slotId || '').toUpperCase()))
    const txt = el?.content?.text || el?.text
    return txt && String(txt).trim() ? String(txt).trim() : fallback
  }
  const imageEl = elements.find(
    (e) => String(e.slotId || '').toUpperCase() === 'BACKGROUND_IMAGE' || e.type === 'image'
  )
  const imageUrl = imageEl?.content?.url || imageEl?.content?.src || null
  const titleText = findText((s) => s === 'MAIN_TITLE' || s === 'HEADING' || s === 'TITLE', 'Presentation title')
  const subtitleText = findText((s) => s === 'SUBTITLE' || s === 'SUBHEADING', 'Tagline or company name')
  const isMultiLine = titleText.split(/\r?\n/).filter(Boolean).length > 1 || titleText.length > 22
  const titleY = isMultiLine ? Math.round(400 * sy) : Math.round(448 * sy)
  const titleH = isMultiLine ? Math.round(170 * sy) : Math.round(96 * sy)
  const subtitleY = isMultiLine ? Math.round(640 * sy) : Math.round(628 * sy)

  const out = [
    {
      id: 'slot-BACKGROUND_IMAGE',
      slotId: 'BACKGROUND_IMAGE',
      type: 'image',
      role: 'background',
      layer: 0,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        ...(imageUrl ? { url: imageUrl, src: imageUrl } : {}),
        fit: 'cover',
        alt: '',
      },
    },
    {
      id: 'slot-OVERLAY_SCRIM',
      slotId: 'OVERLAY_SCRIM',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildTitleFullbleedScrimSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'preserve',
      },
    },
    {
      id: 'slot-MAIN_TITLE',
      slotId: 'MAIN_TITLE',
      type: 'text',
      role: 'heading',
      layer: 10,
      placement: {
        x: Math.round(180 * sx),
        y: titleY,
        width: Math.round(1560 * sx),
        height: titleH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: titleText,
        fontSize: Math.round(64 * scale),
        fontWeight: 800,
        color: '#FFFFFF',
        align: 'center',
        verticalAlign: 'flex-start',
        lineHeight: 1.12,
        wrap: 'pre-wrap',
        clipToSlot: true,
        maxLines: 2,
      },
    },
    {
      id: 'slot-SUBTITLE',
      slotId: 'SUBTITLE',
      type: 'text',
      role: 'subheading',
      layer: 10,
      placement: {
        x: Math.round(280 * sx),
        y: subtitleY,
        width: Math.round(1360 * sx),
        height: Math.round(80 * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: subtitleText,
        fontSize: Math.round(24 * scale),
        fontWeight: 400,
        color: '#F1F5F9',
        align: 'center',
        verticalAlign: 'flex-start',
        lineHeight: 1.4,
        wrap: 'pre-wrap',
        clipToSlot: true,
        maxLines: 2,
      },
    },
  ]

  if (Array.isArray(docOrElements)) return out
  return { ...docOrElements, elements: out }
}

module.exports = {
  isTitleFullbleedLayout,
  buildTitleFullbleedScrimSvg,
  layoutTitleFullbleed,
}
