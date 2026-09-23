function isTitleFullbleedOverlayLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase()
  return id === 'title_fullbleed_overlay_v1' || id === 'title_fullbleed_overlay'
}

function buildTitleFullbleedOverlaySvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <linearGradient id="tfoScrim" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#020617" stop-opacity="0" />
        <stop offset="42%" stop-color="#020617" stop-opacity="0.08" />
        <stop offset="72%" stop-color="#020617" stop-opacity="0.55" />
        <stop offset="100%" stop-color="#020617" stop-opacity="0.86" />
      </linearGradient>
    </defs>
    <rect width="1920" height="1080" fill="url(#tfoScrim)" />
    <rect x="120" y="688" width="56" height="4" rx="2" fill="#FFFFFF" fill-opacity="0.92" />
  </svg>`
}

function layoutTitleFullbleedOverlay(docOrElements, schema, themeTokens, canvas = {}) {
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
  const findImage = () => {
    const el = elements.find((e) => String(e.slotId || '').toUpperCase() === 'BACKGROUND_IMAGE' || e.type === 'image')
    return el?.content?.url || el?.content?.src || null
  }

  const titleText = findText((s) => s === 'MAIN_TITLE' || s === 'HEADING' || s === 'TITLE', 'Title Fullbleed Overlay')
  const subtitleText = findText((s) => s === 'SUBTITLE' || s === 'SUBHEADING', 'Tagline or company name')
  const imageUrl = findImage()
  const isMultiLine = titleText.split(/\r?\n/).filter(Boolean).length > 1 || titleText.length > 28
  const titleY = isMultiLine ? Math.round(680 * sy) : Math.round(720 * sy)
  const titleH = isMultiLine ? Math.round(150 * sy) : Math.round(90 * sy)
  const subtitleY = isMultiLine ? Math.round(860 * sy) : Math.round(840 * sy)

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
      id: 'slot-OVERLAY_CARD',
      slotId: 'OVERLAY_CARD',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildTitleFullbleedOverlaySvg(),
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
        x: Math.round(120 * sx),
        y: titleY,
        width: Math.round(1480 * sx),
        height: titleH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: titleText,
        fontSize: Math.round(56 * scale),
        fontWeight: 800,
        color: '#FFFFFF',
        align: 'left',
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
        x: Math.round(120 * sx),
        y: subtitleY,
        width: Math.round(1280 * sx),
        height: Math.round(80 * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: subtitleText,
        fontSize: Math.round(24 * scale),
        fontWeight: 400,
        color: '#E2E8F0',
        align: 'left',
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
  isTitleFullbleedOverlayLayout,
  buildTitleFullbleedOverlaySvg,
  layoutTitleFullbleedOverlay,
}
