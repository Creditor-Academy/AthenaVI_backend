function polar(cx, cy, r, a) {
  return [cx + r * Math.cos(a), cy + r * Math.sin(a)];
}

function annularArrowPath(cx, cy, rIn, rOut, a0, a1, head) {
  const aJoin = a1 - head;
  const rMid = (rIn + rOut) / 2;
  const [ox0, oy0] = polar(cx, cy, rOut, a0);
  const [ox1, oy1] = polar(cx, cy, rOut, aJoin);
  const [ix1, iy1] = polar(cx, cy, rIn, aJoin);
  const [ix0, iy0] = polar(cx, cy, rIn, a0);
  const [tx, ty] = polar(cx, cy, rMid, a1);
  return `M ${ox0.toFixed(1)} ${oy0.toFixed(1)} A ${rOut} ${rOut} 0 0 1 ${ox1.toFixed(1)} ${oy1.toFixed(1)} L ${tx.toFixed(1)} ${ty.toFixed(1)} L ${ix1.toFixed(1)} ${iy1.toFixed(1)} A ${rIn} ${rIn} 0 0 0 ${ix0.toFixed(1)} ${iy0.toFixed(1)} Z`;
}

const CYCLE_SEGMENT_COLORS = ['#3B82F6', '#22C55E', '#14B8A6', '#6366F1'];

const CYCLE_GEOM = {
  view: 1000,
  rOut: 390,
  rIn: 228,
  hubR: 196,
  gap: 0.1,
  head: 0.32,
};

function cycleSegmentMidAngle(index) {
  const i = Number(index) || 0;
  const a0 = -Math.PI / 2 + i * (Math.PI / 2) + CYCLE_GEOM.gap;
  const a1 = -Math.PI / 2 + (i + 1) * (Math.PI / 2) - CYCLE_GEOM.gap / 3;
  return (a0 + a1 - CYCLE_GEOM.head) / 2;
}

function cycleOverlayPlacements(cycleX, cycleY, cycleSize) {
  const scale = cycleSize / CYCLE_GEOM.view;
  const cx = cycleX + cycleSize / 2;
  const cy = cycleY + cycleSize / 2;
  const rText = (CYCLE_GEOM.rIn * 0.38 + CYCLE_GEOM.rOut * 0.62) * scale;
  const num = Math.max(64, Math.round(96 * scale));
  const numbers = [0, 1, 2, 3].map((i) => {
    const a = cycleSegmentMidAngle(i);
    return {
      x: Math.round(cx + rText * Math.cos(a) - num / 2),
      y: Math.round(cy + rText * Math.sin(a) - num / 2),
      width: num,
      height: num,
    };
  });
  const hubW = Math.round(CYCLE_GEOM.hubR * 2 * scale * 0.9);
  const hubH = Math.max(52, Math.round(64 * scale * 1.15));
  return {
    numbers,
    center: {
      x: Math.round(cx - hubW / 2),
      y: Math.round(cy - hubH / 2),
      width: hubW,
      height: hubH,
    },
    hub: {
      x: Math.round(cx - CYCLE_GEOM.hubR * scale),
      y: Math.round(cy - CYCLE_GEOM.hubR * scale),
      width: Math.round(CYCLE_GEOM.hubR * 2 * scale),
      height: Math.round(CYCLE_GEOM.hubR * 2 * scale),
    },
  };
}

function cycleSegmentPath(index) {
  const i = Number(index) || 0;
  const { rOut, rIn, gap, head } = CYCLE_GEOM;
  const a0 = -Math.PI / 2 + i * (Math.PI / 2) + gap;
  const a1 = -Math.PI / 2 + (i + 1) * (Math.PI / 2) - gap / 3;
  return annularArrowPath(500, 500, rIn, rOut, a0, a1, head);
}

const CYCLE_SEG_VIEWS = [
  { x: 430, y: 0, w: 570, h: 570 },
  { x: 430, y: 430, w: 570, h: 570 },
  { x: 0, y: 430, w: 570, h: 570 },
  { x: 0, y: 0, w: 570, h: 570 },
];

function cycleSegmentPlacement(cycleX, cycleY, cycleSize, index) {
  const v = CYCLE_SEG_VIEWS[Number(index) || 0];
  const s = cycleSize / CYCLE_GEOM.view;
  return {
    x: Math.round(cycleX + v.x * s),
    y: Math.round(cycleY + v.y * s),
    width: Math.round(v.w * s),
    height: Math.round(v.h * s),
  };
}

function cycleSegmentInlineSvg(index) {
  const i = Number(index) || 0;
  const v = CYCLE_SEG_VIEWS[i];
  const d = cycleSegmentPath(i);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${v.x} ${v.y} ${v.w} ${v.h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><path d="${d}" fill="currentColor"/></svg>`;
}

function buildCycleDiagramSvg(colors = CYCLE_SEGMENT_COLORS, { labels = true } = {}) {
  const cx = 500;
  const cy = 500;
  const { rOut, rIn, hubR, gap, head } = CYCLE_GEOM;
  const parts = [];
  for (let i = 0; i < 4; i += 1) {
    const a0 = -Math.PI / 2 + i * (Math.PI / 2) + gap;
    const a1 = -Math.PI / 2 + (i + 1) * (Math.PI / 2) - gap / 3;
    parts.push(
      `<path d="${annularArrowPath(cx, cy, rIn, rOut, a0, a1, head)}" fill="${colors[i % colors.length]}" />`
    );
    if (labels) {
      const mid = (a0 + a1 - head) / 2;
      const [nx, ny] = polar(cx, cy, (rIn + rOut) / 2, mid);
      parts.push(
        `<text x="${nx.toFixed(1)}" y="${ny.toFixed(1)}" text-anchor="middle" dominant-baseline="middle" fill="#ffffff" font-size="78" font-weight="800" font-family="system-ui,sans-serif">${i + 1}</text>`
      );
    }
  }
  parts.push(`<circle cx="${cx}" cy="${cy}" r="${hubR}" fill="#ffffff" />`);
  if (labels) {
    parts.push(
      `<text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="middle" fill="#1f2937" font-size="34" font-weight="800" font-family="system-ui,sans-serif" letter-spacing="2">CYCLE</text>`
    );
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000">${parts.join('')}</svg>`;
}

function cycleDiagramDataUri(colors) {
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(buildCycleDiagramSvg(colors))}`;
}

function cycleDiagramInlineSvg(colors, options = { labels: false }) {
  return buildCycleDiagramSvg(colors, options).replace(
    /<svg\b([^>]*)>/i,
    (match, attrs) => {
      let next = attrs;
      if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"';
      if (!/\bheight\s*=/i.test(next)) next += ' height="100%"';
      if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"';
      return `<svg${next}>`;
    }
  );
}

module.exports = {
  CYCLE_SEGMENT_COLORS,
  CYCLE_GEOM,
  cycleOverlayPlacements,
  buildCycleDiagramSvg,
  cycleDiagramDataUri,
  cycleDiagramInlineSvg,
  cycleSegmentInlineSvg,
  cycleSegmentPlacement,
};
