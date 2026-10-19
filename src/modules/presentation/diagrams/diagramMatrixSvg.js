const MATRIX_QUAD_COLORS = ['#5B8FC4', '#5B8FC4', '#4A7EB0', '#4A7EB0'];
const MATRIX_ARROW_COLOR = '#6B9FD4';

const MATRIX_GEOM = {
  viewW: 1400,
  viewH: 980,
  arrowW: 72,
  arrowGap: 32,
  gutter: 18,
  radius: 36,
  hubR: 124,
  head: 36,
};

function matrixGridRect() {
  const { viewW, viewH, arrowW, arrowGap } = MATRIX_GEOM;
  const gridX = arrowW + arrowGap;
  const gridY = 8;
  const gridW = viewW - gridX - 8;
  const gridH = viewH - gridY - arrowW - arrowGap;
  return { gridX, gridY, gridW, gridH };
}

function matrixCellRect(index) {
  const { gutter } = MATRIX_GEOM;
  const { gridX, gridY, gridW, gridH } = matrixGridRect();
  const col = index % 2;
  const row = Math.floor(index / 2);
  const cellW = (gridW - gutter) / 2;
  const cellH = (gridH - gutter) / 2;
  return {
    x: gridX + col * (cellW + gutter),
    y: gridY + row * (cellH + gutter),
    w: cellW,
    h: cellH,
  };
}

function matrixOverlayPlacements(gx, gy, gw, gh) {
  const sx = gw / MATRIX_GEOM.viewW;
  const sy = gh / MATRIX_GEOM.viewH;
  const { arrowW, hubR } = MATRIX_GEOM;
  const { gridX, gridY, gridW, gridH } = matrixGridRect();
  const cells = [0, 1, 2, 3].map((i) => {
    const c = matrixCellRect(i);
    const padX = Math.round(c.w * 0.1 * sx);
    const titleH = Math.max(36, Math.round(c.h * 0.16 * sy));
    const titleY = gy + (c.y + c.h * 0.34) * sy;
    return {
      title: {
        x: Math.round(gx + c.x * sx + padX),
        y: Math.round(titleY),
        width: Math.round(c.w * sx - padX * 2),
        height: titleH,
      },
      body: {
        x: Math.round(gx + c.x * sx + padX),
        y: Math.round(titleY + titleH + 4),
        width: Math.round(c.w * sx - padX * 2),
        height: Math.max(40, Math.round(c.h * 0.28 * sy)),
      },
    };
  });
  const cx = gx + (gridX + gridW / 2) * sx;
  const cy = gy + (gridY + gridH / 2) * sy;
  const hubD = hubR * 2 * Math.min(sx, sy);
  return {
    cells,
    center: {
      x: Math.round(cx - hubD * 0.42),
      y: Math.round(cy - hubD * 0.32),
      width: Math.round(hubD * 0.84),
      height: Math.round(hubD * 0.64),
    },
    hub: {
      x: Math.round(cx - hubD / 2),
      y: Math.round(cy - hubD / 2),
      width: Math.round(hubD),
      height: Math.round(hubD),
    },
    yLabel: {
      x: Math.round(gx + (arrowW / 2) * sx - (gridH * 0.28) * sy),
      y: Math.round(gy + (gridY + gridH / 2) * sy - (arrowW * 0.38) * sy),
      width: Math.round(gridH * 0.56 * sy),
      height: Math.round(arrowW * 0.76 * sy),
      rotation: -90,
    },
    xLabel: {
      x: Math.round(gx + (gridX + gridW * 0.12) * sx),
      y: Math.round(gy + (gridY + gridH + MATRIX_GEOM.arrowGap + 8) * sy),
      width: Math.round(gridW * 0.76 * sx),
      height: Math.round(arrowW * sy * 0.75),
    },
  };
}

function verticalArrowPath(x, y, w, h, head) {
  const mid = x + w / 2;
  const shaft = y + head;
  return [
    `M ${mid} ${y}`,
    `L ${x + w} ${shaft}`,
    `L ${x + w * 0.72} ${shaft}`,
    `L ${x + w * 0.72} ${y + h}`,
    `L ${x + w * 0.28} ${y + h}`,
    `L ${x + w * 0.28} ${shaft}`,
    `L ${x} ${shaft}`,
    'Z',
  ].join(' ');
}

function horizontalArrowPath(x, y, w, h, head) {
  const shaft = x + w - head;
  return [
    `M ${x} ${y + h * 0.28}`,
    `L ${shaft} ${y + h * 0.28}`,
    `L ${shaft} ${y}`,
    `L ${x + w} ${y + h / 2}`,
    `L ${shaft} ${y + h}`,
    `L ${shaft} ${y + h * 0.72}`,
    `L ${x} ${y + h * 0.72}`,
    'Z',
  ].join(' ');
}

function matrixQuadPlacement(gx, gy, gw, gh, index) {
  const sx = gw / MATRIX_GEOM.viewW;
  const sy = gh / MATRIX_GEOM.viewH;
  const c = matrixCellRect(index);
  return {
    x: Math.round(gx + c.x * sx),
    y: Math.round(gy + c.y * sy),
    width: Math.round(c.w * sx),
    height: Math.round(c.h * sy),
    borderRadius: Math.round(MATRIX_GEOM.radius * Math.min(sx, sy)),
  };
}

function matrixArrowPlacement(gx, gy, gw, gh, axis) {
  const sx = gw / MATRIX_GEOM.viewW;
  const sy = gh / MATRIX_GEOM.viewH;
  const { arrowW, arrowGap, head } = MATRIX_GEOM;
  const { gridX, gridY, gridW, gridH } = matrixGridRect();
  if (axis === 'y') {
    return {
      x: Math.round(gx),
      y: Math.round(gy + gridY * sy),
      width: Math.round(arrowW * sx),
      height: Math.round(gridH * sy),
    };
  }
  return {
    x: Math.round(gx + gridX * sx),
    y: Math.round(gy + (gridY + gridH + arrowGap) * sy),
    width: Math.round(gridW * sx),
    height: Math.round(arrowW * sy),
  };
}

function matrixArrowInlineSvg(axis) {
  const { arrowW, head } = MATRIX_GEOM;
  const { gridW, gridH } = matrixGridRect();
  if (axis === 'y') {
    const d = verticalArrowPath(0, 0, arrowW, gridH, head);
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${arrowW} ${gridH}" width="100%" height="100%" preserveAspectRatio="none"><path d="${d}" fill="currentColor"/></svg>`;
  }
  const d = horizontalArrowPath(0, 0, gridW, arrowW, head);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${gridW} ${arrowW}" width="100%" height="100%" preserveAspectRatio="none"><path d="${d}" fill="currentColor"/></svg>`;
}

function buildMatrixDiagramSvg(colors = MATRIX_QUAD_COLORS) {
  const { viewW, viewH, arrowW, arrowGap, radius, hubR, head } = MATRIX_GEOM;
  const { gridX, gridY, gridW, gridH } = matrixGridRect();
  const parts = [];
  parts.push(
    `<path d="${verticalArrowPath(0, gridY, arrowW, gridH, head)}" fill="${MATRIX_ARROW_COLOR}"/>`
  );
  parts.push(
    `<path d="${horizontalArrowPath(gridX, gridY + gridH + arrowGap, gridW, arrowW, head)}" fill="${MATRIX_ARROW_COLOR}"/>`
  );
  for (let i = 0; i < 4; i += 1) {
    const c = matrixCellRect(i);
    parts.push(
      `<rect x="${c.x.toFixed(1)}" y="${c.y.toFixed(1)}" width="${c.w.toFixed(1)}" height="${c.h.toFixed(1)}" rx="${radius}" fill="${colors[i]}"/>`
    );
  }
  const cx = gridX + gridW / 2;
  const cy = gridY + gridH / 2;
  parts.push(
    `<ellipse cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" rx="${hubR}" ry="${hubR}" fill="#ffffff" stroke="#E5E7EB" stroke-width="3"/>`
  );
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}">${parts.join('')}</svg>`;
}

function matrixDiagramInlineSvg(colors = MATRIX_QUAD_COLORS) {
  return buildMatrixDiagramSvg(colors).replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs;
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"';
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"';
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"';
    return `<svg${next}>`;
  });
}

const MATRIX_GRID_COLORS = ['#1e3a5f', '#2563eb', '#0f766e', '#475569'];
const MATRIX_Q_TINTS = ['#E8EEF7', '#FFF1E6', '#E7F6F2', '#F1F5F9'];
const MATRIX_Q_TITLE = ['#1e3a5f', '#c2410c', '#0f766e', '#334155'];
const MATRIX_Q_AXIS = '#1e293b';

function matrixGridPreviewSvg() {
  const colors = MATRIX_GRID_COLORS;
  const g = 18;
  const x = 20;
  const y = 20;
  const w = 1360;
  const h = 940;
  const cw = (w - g) / 2;
  const ch = (h - g) / 2;
  const cells = [0, 1, 2, 3].map((i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    return `<rect x="${x + col * (cw + g)}" y="${y + row * (ch + g)}" width="${cw}" height="${ch}" rx="28" fill="${colors[i]}"/>`;
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 980" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${cells.join('')}</svg>`;
}

function matrixQuadrantCrossInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000" width="100%" height="100%" preserveAspectRatio="none">
<line x1="500" y1="48" x2="500" y2="952" stroke="currentColor" stroke-width="7" stroke-linecap="round" pointer-events="none"/>
<line x1="48" y1="500" x2="952" y2="500" stroke="currentColor" stroke-width="7" stroke-linecap="round" pointer-events="none"/>
<polygon points="500,18 526,56 474,56" fill="currentColor" pointer-events="none"/>
<polygon points="982,500 944,526 944,474" fill="currentColor" pointer-events="none"/>
</svg>`;
}

function matrixQuadrantPreviewSvg() {
  const tints = MATRIX_Q_TINTS;
  const x = 80;
  const y = 40;
  const w = 1240;
  const h = 860;
  const cw = w / 2;
  const ch = h / 2;
  const cells = [0, 1, 2, 3].map((i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    return `<rect x="${x + col * cw}" y="${y + row * ch}" width="${cw}" height="${ch}" fill="${tints[i]}"/>`;
  });
  const cx = x + w / 2;
  const cy = y + h / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1400 980" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${cells.join('')}
<line x1="${cx}" y1="${y + 16}" x2="${cx}" y2="${y + h - 16}" stroke="${MATRIX_Q_AXIS}" stroke-width="8" stroke-linecap="round"/>
<line x1="${x + 16}" y1="${cy}" x2="${x + w - 16}" y2="${cy}" stroke="${MATRIX_Q_AXIS}" stroke-width="8" stroke-linecap="round"/>
<polygon points="${cx},${y} ${cx + 18},${y + 32} ${cx - 18},${y + 32}" fill="${MATRIX_Q_AXIS}"/>
<polygon points="${x + w},${cy} ${x + w - 32},${cy + 18} ${x + w - 32},${cy - 18}" fill="${MATRIX_Q_AXIS}"/>
</svg>`;
}

module.exports = {
  MATRIX_GEOM,
  MATRIX_QUAD_COLORS,
  MATRIX_ARROW_COLOR,
  MATRIX_GRID_COLORS,
  MATRIX_Q_TINTS,
  MATRIX_Q_TITLE,
  MATRIX_Q_AXIS,
  matrixOverlayPlacements,
  matrixDiagramInlineSvg,
  matrixQuadPlacement,
  matrixArrowPlacement,
  matrixArrowInlineSvg,
  matrixGridPreviewSvg,
  matrixQuadrantCrossInlineSvg,
  matrixQuadrantPreviewSvg,
};
