const SWOT_N = 4;
const SWOT_LETTERS = ['S', 'W', 'O', 'T'];
const SWOT_COLORS = ['#7d9b6a', '#3d5a80', '#3aa8a4', '#d4785a'];
const SWOT_LABELS = ['STRENGTHS', 'WEAKNESSES', 'OPPORTUNITIES', 'THREATS'];

const SWOT_GEOM = {
  viewW: 980,
  viewH: 920,
  hubX: 268,
  hubY: 460,
  hubR: 148,
  angles: [-48, -16, 16, 48],
  inner: 92,
  outer: 395,
  petalR: 54,
};

function deg(a) {
  return (a * Math.PI) / 180;
}

function swotPetalGeom(i) {
  const { hubX, hubY, inner, outer, petalR, angles } = SWOT_GEOM;
  const a = deg(angles[i]);
  const cos = Math.cos(a);
  const sin = Math.sin(a);
  const ax = hubX + cos * inner;
  const ay = hubY + sin * inner;
  const bx = hubX + cos * outer;
  const by = hubY + sin * outer;
  const lx = hubX + cos * ((inner + outer) * 0.42);
  const ly = hubY + sin * ((inner + outer) * 0.42);
  return { i, ax, ay, bx, by, lx, ly, r: petalR, cos, sin };
}

function capsulePath(ax, ay, bx, by, r) {
  const dx = bx - ax;
  const dy = by - ay;
  const len = Math.hypot(dx, dy) || 1;
  const px = (-dy / len) * r;
  const py = (dx / len) * r;
  const a1x = ax + px;
  const a1y = ay + py;
  const a2x = ax - px;
  const a2y = ay - py;
  const b1x = bx + px;
  const b1y = by + py;
  const b2x = bx - px;
  const b2y = by - py;
  const rf = r.toFixed(1);
  return `M ${a1x.toFixed(1)} ${a1y.toFixed(1)} L ${b1x.toFixed(1)} ${b1y.toFixed(1)} A ${rf} ${rf} 0 0 1 ${b2x.toFixed(1)} ${b2y.toFixed(1)} L ${a2x.toFixed(1)} ${a2y.toFixed(1)} A ${rf} ${rf} 0 0 1 ${a1x.toFixed(1)} ${a1y.toFixed(1)} Z`;
}

function swotPetalViewBox(i) {
  const g = swotPetalGeom(i);
  const pad = g.r + 8;
  const minX = Math.min(g.ax, g.bx) - pad;
  const minY = Math.min(g.ay, g.by) - pad;
  const maxX = Math.max(g.ax, g.bx) + pad;
  const maxY = Math.max(g.ay, g.by) + pad;
  return { x: minX, y: minY, w: maxX - minX, h: maxY - minY };
}

function swotPetalPlacement(gx, gy, gw, gh, i) {
  const sx = gw / SWOT_GEOM.viewW;
  const sy = gh / SWOT_GEOM.viewH;
  const v = swotPetalViewBox(i);
  return {
    x: Math.round(gx + v.x * sx),
    y: Math.round(gy + v.y * sy),
    width: Math.round(v.w * sx),
    height: Math.round(v.h * sy),
  };
}

function swotPetalInlineSvg(i) {
  const g = swotPetalGeom(i);
  const v = swotPetalViewBox(i);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${v.x} ${v.y} ${v.w} ${v.h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><path d="${capsulePath(g.ax, g.ay, g.bx, g.by, g.r)}" fill="currentColor"/><text x="${g.lx.toFixed(1)}" y="${g.ly.toFixed(1)}" text-anchor="middle" dominant-baseline="central" fill="#ffffff" font-size="48" font-weight="800" font-family="system-ui,sans-serif">${SWOT_LETTERS[i]}</text></svg>`;
}

function iconEagle() {
  return `<path d="M40 22c8 6 14 8 22 8-6 4-10 12-10 20-8-6-16-8-24-6 4-8 6-16 12-22z" fill="none" stroke="#fff" stroke-width="2.4" stroke-linejoin="round"/><path d="M28 48c6 8 18 8 24 0" fill="none" stroke="#fff" stroke-width="2.2"/>`;
}
function iconWeb() {
  return `<polygon points="40,18 58,30 52,52 28,52 22,30" fill="none" stroke="#fff" stroke-width="2.4"/><path d="M40 18 L40 52 M22 30 L58 30 M28 52 L40 18 L52 52" fill="none" stroke="#fff" stroke-width="1.6"/>`;
}
function iconDoor() {
  return `<rect x="28" y="20" width="24" height="40" rx="2" fill="none" stroke="#fff" stroke-width="2.4"/><path d="M28 24 Q40 14 52 24" fill="none" stroke="#fff" stroke-width="2.4"/><circle cx="46" cy="42" r="1.8" fill="#fff"/>`;
}
function iconThreat() {
  return `<path d="M24 50c8-18 12-28 16-32 4 4 8 14 16 32" fill="none" stroke="#fff" stroke-width="2.4" stroke-linejoin="round"/><circle cx="40" cy="28" r="3" fill="#fff"/><path d="M40 50 L40 56 M34 54 L46 54" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/>`;
}

const ICONS = [iconEagle, iconWeb, iconDoor, iconThreat];

function swotIconInlineSvg(i) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80" width="100%" height="100%"><rect x="4" y="4" width="72" height="72" rx="16" fill="currentColor"/>${ICONS[i]()}</svg>`;
}

function swotDashInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 12" width="100%" height="100%" preserveAspectRatio="none"><line x1="2" y1="6" x2="198" y2="6" stroke="#cbd5e1" stroke-width="2.5" stroke-dasharray="7 7" stroke-linecap="round"/></svg>`;
}

function swotGraphicBox(canvasW, canvasH) {
  const headingY = 32;
  const headingH = 80;
  const graphicY = headingY + headingH + 8;
  const graphicH = canvasH - graphicY - 36;
  const graphicX = 32;
  const graphicW = Math.round(Math.min(1000, canvasW * 0.5));
  const legendX = graphicX + graphicW + 8;
  const legendW = Math.max(360, canvasW - legendX - 56);
  return { headingY, headingH, graphicX, graphicY, graphicW, graphicH, legendX, legendW, canvasW };
}

function swotOverlayPlacements(frame) {
  const { graphicX, graphicY, graphicW, graphicH, legendX, legendW } = frame;
  const { viewW, viewH, hubX, hubY, hubR } = SWOT_GEOM;
  const sx = graphicW / viewW;
  const sy = graphicH / viewH;
  const icon = 96;
  const hubSize = Math.round(hubR * 2 * Math.min(sx, sy));
  const hub = {
    x: Math.round(graphicX + hubX * sx - hubSize / 2),
    y: Math.round(graphicY + hubY * sy - hubSize / 2),
    width: hubSize,
    height: hubSize,
  };
  const rows = [0, 1, 2, 3].map((i) => {
    const g = swotPetalGeom(i);
    const letter = {
      x: Math.round(graphicX + (g.lx - 28) * sx),
      y: Math.round(graphicY + (g.ly - 28) * sy),
      width: Math.round(56 * sx),
      height: Math.round(56 * sy),
    };
    const cy = graphicY + g.by * sy;
    const iconBox = {
      x: Math.round(legendX),
      y: Math.round(cy - icon / 2),
      width: icon,
      height: icon,
    };
    const dash = {
      x: Math.round(graphicX + g.bx * sx + 8),
      y: Math.round(cy - 8),
      width: Math.max(24, iconBox.x - Math.round(graphicX + g.bx * sx) - 16),
      height: 16,
    };
    const textX = iconBox.x + icon + 20;
    const textW = Math.max(200, legendW - icon - 20);
    return {
      letter,
      icon: iconBox,
      dash,
      title: { x: textX, y: Math.round(cy - 40), width: textW, height: 36 },
      body: { x: textX, y: Math.round(cy + 2), width: textW, height: 56 },
    };
  });
  return {
    hub,
    hubTitle: {
      x: hub.x + 12,
      y: hub.y + Math.round(hub.height * 0.22),
      width: hub.width - 24,
      height: Math.round(hub.height * 0.38),
    },
    hubSub: {
      x: hub.x + 18,
      y: hub.y + Math.round(hub.height * 0.58),
      width: hub.width - 36,
      height: Math.round(hub.height * 0.22),
    },
    rows,
  };
}

function swotModeFromSchema(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  if (variant === 'grid' || (id.includes('swot') && id.includes('grid'))) return 'grid';
  if (variant === 'cards' || (id.includes('swot') && id.includes('cards'))) return 'cards';
  return 'classic';
}

function swotQuadFrame(canvasW, canvasH, mode = 'grid') {
  const headingY = 56;
  const headingH = 88;
  const insetX = 64;
  const gap = mode === 'cards' ? 36 : 18;
  const top = headingY + headingH + 28;
  const gridH = canvasH - top - 48;
  const gridW = canvasW - insetX * 2;
  const cellW = (gridW - gap) / 2;
  const cellH = (gridH - gap) / 2;
  const cells = [0, 1, 2, 3].map((i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    return {
      x: Math.round(insetX + col * (cellW + gap)),
      y: Math.round(top + row * (cellH + gap)),
      width: Math.round(cellW),
      height: Math.round(cellH),
    };
  });
  return { headingY, headingH, cells, insetX, canvasW };
}

module.exports = {
  SWOT_N,
  SWOT_LETTERS,
  SWOT_COLORS,
  SWOT_LABELS,
  SWOT_GEOM,
  swotPetalGeom,
  swotPetalPlacement,
  swotPetalInlineSvg,
  swotIconInlineSvg,
  swotDashInlineSvg,
  swotGraphicBox,
  swotOverlayPlacements,
  swotModeFromSchema,
  swotQuadFrame,
};
