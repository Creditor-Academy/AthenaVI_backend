/**
 * Agenda split panel — grayscale photo left, convex blue ribbon, 4 TOC rows.
 * Geometry matches the conference-room PPT (not the landscape S-curve).
 */

const AGENDA_SPLIT_PANEL_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingX: 400,
  headingY: 14,
  headingW: 560,
  headingH: 40,
  n: 4,
  ribbonW: 50,
}

const SPLIT_PANEL_ACCENT = '#2E89E6'

const CURVE = {
  p0: { x: 198, y: -8 },
  p1: { x: 372, y: 148 },
  p2: { x: 352, y: 388 },
  p3: { x: 132, y: 572 },
}

const NODE_T = [0.20, 0.42, 0.64, 0.84]
const NODE_R = 36

function cubic(p0, p1, p2, p3, t) {
  const u = 1 - t
  return {
    x: u * u * u * p0.x + 3 * u * u * t * p1.x + 3 * u * t * t * p2.x + t * t * t * p3.x,
    y: u * u * u * p0.y + 3 * u * u * t * p1.y + 3 * u * t * t * p2.y + t * t * t * p3.y,
  }
}

function curvePoint(t) {
  return cubic(CURVE.p0, CURVE.p1, CURVE.p2, CURVE.p3, t)
}

function nodeCenters() {
  return NODE_T.map((t) => curvePoint(t))
}

function curveD() {
  const { p0, p1, p2, p3 } = CURVE
  return `M ${p0.x} ${p0.y} C ${p1.x} ${p1.y} ${p2.x} ${p2.y} ${p3.x} ${p3.y}`
}

function sampleClipPercents() {
  const imgW = 360
  const imgH = 560
  const half = AGENDA_SPLIT_PANEL_GEOM.ribbonW * 0.42
  const pts = []
  for (let i = 0; i <= 16; i += 1) {
    const p = curvePoint(i / 16)
    const x = Math.max(8, Math.min(imgW, p.x - half))
    pts.push(`${((x / imgW) * 100).toFixed(1)}% ${((p.y / imgH) * 100).toFixed(1)}%`)
  }
  return `polygon(0% 0%, ${pts.join(', ')}, 0% 100%)`
}

const SPLIT_PANEL_IMAGE_CLIP = sampleClipPercents()

function agendaSplitPanelGraphicFrame(canvasW, canvasH) {
  return {
    graphicX: 0,
    graphicY: 0,
    graphicW: canvasW,
    graphicH: canvasH,
    headingY: Math.round(canvasH * 0.02),
    headingH: Math.round(canvasH * 0.07),
  }
}

function imageBox() {
  return { x: 0, y: 0, w: 360, h: 560 }
}

function agendaSplitPanelImageClip() {
  return SPLIT_PANEL_IMAGE_CLIP
}

function ribbonMarkup() {
  const d = curveD()
  const sw = AGENDA_SPLIT_PANEL_GEOM.ribbonW
  const nodes = nodeCenters().map((p, i) => {
    const n = String(i + 1).padStart(2, '0')
    return `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${NODE_R}" fill="#ffffff"/>
      <circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${NODE_R}" fill="none" stroke="currentColor" stroke-width="2.4"/>
      <text x="${p.x.toFixed(1)}" y="${(p.y + 7.5).toFixed(1)}" text-anchor="middle" fill="currentColor" stroke="none" font-size="17" font-weight="800" font-family="Arial,Helvetica,sans-serif">${n}</text>`
  }).join('')
  return `<path d="${d}" fill="none" stroke="#163A6B" stroke-width="${sw + 10}" stroke-linecap="round" opacity="0.28" transform="translate(7,6)"/>
    <path d="${d}" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round"/>
    ${nodes}`
}

function chromeExtras(includePhoto) {
  const clipPts = []
  const half = AGENDA_SPLIT_PANEL_GEOM.ribbonW * 0.42
  for (let i = 0; i <= 16; i += 1) {
    const p = curvePoint(i / 16)
    clipPts.push(`${(p.x - half).toFixed(1)},${p.y.toFixed(1)}`)
  }
  const photo = includePhoto
    ? `<defs><clipPath id="spPhoto"><polygon points="0,0 ${clipPts.join(' ')} 0,560"/></clipPath></defs>
      <g clip-path="url(#spPhoto)">
        <rect x="0" y="0" width="360" height="560" fill="#6b7280"/>
        <rect x="12" y="70" width="220" height="18" fill="#9ca3af" opacity="0.55"/>
        <rect x="28" y="160" width="190" height="12" fill="#d1d5db" opacity="0.4"/>
        <rect x="16" y="220" width="220" height="210" fill="#4b5563" opacity="0.55"/>
        <rect x="48" y="250" width="36" height="150" fill="#374151"/>
        <rect x="100" y="250" width="36" height="150" fill="#374151"/>
        <rect x="152" y="250" width="36" height="150" fill="#374151"/>
      </g>`
    : ''
  const dotsX = [692, 714, 736, 758]
  const dotsC = ['#93C5FD', '#2E89E6', '#F59E0B', '#9CA3AF']
  const dots = dotsX.map((x, i) => `<circle cx="${x}" cy="60" r="5" fill="${dotsC[i]}"/>`).join('')
  const footer = `<rect x="718" y="534" width="96" height="5" rx="1.5" fill="currentColor"/>
    <rect x="818" y="534" width="52" height="5" rx="1.5" fill="#F59E0B"/>
    <rect x="874" y="534" width="42" height="5" rx="1.5" fill="#9CA3AF"/>`
  const border = `<rect x="3" y="3" width="994" height="554" rx="10" fill="none" stroke="currentColor" stroke-width="2.2" opacity="0.55"/>`
  return `${photo}${border}${dots}${footer}`
}

function splitPanelInlineSvg(includePhoto) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 560" width="100%" height="100%" preserveAspectRatio="none">${chromeExtras(includePhoto)}${ribbonMarkup()}</svg>`
}

function agendaSplitPanelChromeSpecs() {
  return [{
    slotId: 'AGENDA_SP_CHROME',
    kind: 'graphic',
    x: 0,
    y: 0,
    w: 1000,
    h: 560,
    color: SPLIT_PANEL_ACCENT,
    layer: 6,
  }]
}

function agendaSplitPanelOverlayPlacements(gx, gy, gw, gh) {
  const g = AGENDA_SPLIT_PANEL_GEOM
  const sx = gw / g.viewW
  const sy = gh / g.viewH
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(24, Math.round(w * sx)),
    height: Math.max(16, Math.round(h * sy)),
  })
  const img = imageBox()
  const items = nodeCenters().map((p) => box(p.x + NODE_R + 18, p.y - 26, 430, 24))
  const itemBodies = nodeCenters().map((p) => box(p.x + NODE_R + 18, p.y + 2, 430, 40))
  return {
    heading: box(g.headingX, g.headingY, g.headingW, g.headingH),
    items,
    itemBodies,
    hero: box(img.x, img.y, img.w, img.h),
    columns: [],
  }
}

function specToSplitPanelContent(spec) {
  return { svg: splitPanelInlineSvg(false), colorMode: 'recolorable', fill: spec?.color || SPLIT_PANEL_ACCENT }
}

function agendaSplitPanelPreviewSvg() {
  return splitPanelInlineSvg(true).replace(
    '<svg ',
    `<svg style="color:${SPLIT_PANEL_ACCENT}" `
  )
}

function isAgendaSplitPanelLayout(layoutId, family, variant) {
  if (variant === 'split_panel') return true
  return /agenda_split_panel_v1$/i.test(String(layoutId || ''))
}

function isAgendaSplitPanelTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase()
  return sid === 'HEADING' || sid === 'HERO_IMAGE' || /^ITEM_\d+$/.test(sid) || /^ITEM_\d+_BODY$/.test(sid)
}

module.exports = {
  AGENDA_SPLIT_PANEL_GEOM,
  SPLIT_PANEL_ACCENT,
  SPLIT_PANEL_IMAGE_CLIP,
  agendaSplitPanelGraphicFrame,
  agendaSplitPanelImageClip,
  agendaSplitPanelChromeSpecs,
  agendaSplitPanelOverlayPlacements,
  specToSplitPanelContent,
  agendaSplitPanelPreviewSvg,
  isAgendaSplitPanelLayout,
  isAgendaSplitPanelTextSlot,
}
