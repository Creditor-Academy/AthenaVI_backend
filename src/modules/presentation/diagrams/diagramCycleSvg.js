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

const CYCLE_RING_N = 5;
const CYCLE_RING_COLORS = ['#38BDF8', '#FB923C', '#C026D3', '#A3E635', '#0F766E'];
const CYCLE_RING_GEOM = {
  view: 1000,
  cx: 500,
  cy: 500,
  rOut: 372,
  rIn: 222,
  hubR: 198,
  gap: 0.048,
  tip: 0.22,
};

function cycleRingMidAngle(index) {
  return -Math.PI / 2 + (Number(index) || 0) * ((Math.PI * 2) / CYCLE_RING_N);
}

function cycleRingSegPath(index) {
  const sweep = (Math.PI * 2) / CYCLE_RING_N;
  const { cx, cy, rOut, rIn, gap, tip } = CYCLE_RING_GEOM;
  const rMid = (rOut + rIn) / 2;
  const t0 = cycleRingMidAngle(index) - sweep / 2 + gap / 2;
  const t1 = t0 + sweep - gap;
  const [ox0, oy0] = polar(cx, cy, rOut, t0);
  const [ox1, oy1] = polar(cx, cy, rOut, t1);
  const [tx, ty] = polar(cx, cy, rMid, t1 + tip);
  const [ix1, iy1] = polar(cx, cy, rIn, t1);
  const [ix0, iy0] = polar(cx, cy, rIn, t0);
  const [nx, ny] = polar(cx, cy, rMid, t0 + tip);
  return `M ${ox0.toFixed(1)} ${oy0.toFixed(1)} A ${rOut} ${rOut} 0 0 1 ${ox1.toFixed(1)} ${oy1.toFixed(1)} L ${tx.toFixed(1)} ${ty.toFixed(1)} L ${ix1.toFixed(1)} ${iy1.toFixed(1)} A ${rIn} ${rIn} 0 0 0 ${ix0.toFixed(1)} ${iy0.toFixed(1)} L ${nx.toFixed(1)} ${ny.toFixed(1)} Z`;
}

function cycleRingSegView(index) {
  const sweep = (Math.PI * 2) / CYCLE_RING_N;
  const { cx, cy, rOut, rIn, gap, tip } = CYCLE_RING_GEOM;
  const rMid = (rOut + rIn) / 2;
  const t0 = cycleRingMidAngle(index) - sweep / 2 + gap / 2;
  const t1 = t0 + sweep - gap;
  const pts = [];
  const steps = 16;
  for (let s = 0; s <= steps; s += 1) {
    const t = t0 + ((t1 - t0) * s) / steps;
    pts.push(polar(cx, cy, rOut, t));
    pts.push(polar(cx, cy, rIn, t));
  }
  pts.push(polar(cx, cy, rMid, t1 + tip));
  pts.push(polar(cx, cy, rMid, t0 + tip));
  const pad = 14;
  const xs = pts.map((p) => p[0]);
  const ys = pts.map((p) => p[1]);
  const minX = Math.min(...xs) - pad;
  const minY = Math.min(...ys) - pad;
  return {
    x: minX,
    y: minY,
    w: Math.max(...xs) - minX + pad,
    h: Math.max(...ys) - minY + pad,
  };
}

function cycleRingSegPlacement(cycleX, cycleY, cycleSize, index) {
  const v = cycleRingSegView(index);
  const s = cycleSize / CYCLE_RING_GEOM.view;
  return {
    x: Math.round(cycleX + v.x * s),
    y: Math.round(cycleY + v.y * s),
    width: Math.round(v.w * s),
    height: Math.round(v.h * s),
    rotation: 0,
    opacity: 1,
  };
}

function cycleRingSegSvg(index) {
  const v = cycleRingSegView(index);
  const d = cycleRingSegPath(index);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${v.x.toFixed(1)} ${v.y.toFixed(1)} ${v.w.toFixed(1)} ${v.h.toFixed(1)}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" pointer-events="none"><path d="${d}" fill="currentColor" pointer-events="visiblePainted"/></svg>`;
}

function cycleRingDiamondSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="100%" height="100%" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"><path d="M32 8L56 32 32 56 8 32Z"/></svg>`;
}

function cycleRingCalloutSvg(localPts, localBar, w, h) {
  const p0 = localPts[0] || { x: 12, y: h - 12 };
  const line = (localPts || [])
    .map((p, i) => `${i ? 'L' : 'M'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`)
    .join(' ');
  const bar = localBar
    ? `<path d="M ${localBar.x1.toFixed(1)} ${localBar.y1.toFixed(1)} L ${localBar.x2.toFixed(1)} ${localBar.y2.toFixed(1)}" fill="none" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>`
    : '';
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${Math.max(1, w)} ${Math.max(1, h)}" width="100%" height="100%" preserveAspectRatio="xMinYMin meet" fill="none"><path d="${line}" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>${bar}<circle cx="${p0.x.toFixed(1)}" cy="${p0.y.toFixed(1)}" r="7" fill="#ffffff" stroke="currentColor" stroke-width="3.5"/></svg>`;
}

function cycleRingCallouts(cx, cy, rOut) {
  const n = CYCLE_RING_N;
  const stem = Math.max(118, Math.round(rOut * 0.64));
  const barW = 300;
  const textH = 48;
  const textW = 220;
  const arm = Math.max(260, Math.round(rOut * 1.35));
  const out = [];
  for (let i = 0; i < n; i += 1) {
    const a = cycleRingMidAngle(i);
    const ax = cx + rOut * Math.cos(a);
    const ay = cy + rOut * Math.sin(a);
    const ox = Math.cos(a);
    const oy = Math.sin(a);
    const extra = i === 3 ? 48 : i === 4 ? 28 : 0;
    const useStem = stem + extra;
    const useArm = arm + (i === 3 ? 36 : 0);
    const mx = ax + ox * useStem;
    const my = ay + oy * useStem;
    let pts;
    let bar = null;
    let text;
    if (i === 0) {
      pts = [
        { x: ax, y: ay },
        { x: ax, y: ay - useStem },
      ];
      bar = { x1: ax - barW / 2, y1: ay - useStem, x2: ax + barW / 2, y2: ay - useStem };
      text = {
        x: Math.round(ax - textW / 2),
        y: Math.round(ay - useStem - textH - 6),
        width: textW,
        height: textH,
        align: 'center',
      };
    } else if (ox >= 0) {
      const hx = mx + useArm;
      pts = [
        { x: ax, y: ay },
        { x: mx, y: my },
        { x: hx, y: my },
      ];
      text = {
        x: Math.round(mx + 8),
        y: Math.round(my - textH - 4),
        width: textW,
        height: textH,
        align: 'left',
      };
    } else {
      const hx = mx - useArm;
      pts = [
        { x: ax, y: ay },
        { x: mx, y: my },
        { x: hx, y: my },
      ];
      text = {
        x: Math.round(hx),
        y: Math.round(my - textH - 4),
        width: textW,
        height: textH,
        align: 'left',
      };
    }
    const extras = bar ? [{ x: bar.x1, y: bar.y1 }, { x: bar.x2, y: bar.y2 }] : [];
    const all = [...pts, ...extras];
    const pad = 18;
    const minX = Math.min(...all.map((p) => p.x));
    const minY = Math.min(...all.map((p) => p.y));
    const maxX = Math.max(...all.map((p) => p.x));
    const maxY = Math.max(...all.map((p) => p.y));
    const box = {
      x: Math.round(minX - pad),
      y: Math.round(minY - pad),
      width: Math.round(maxX - minX + pad * 2),
      height: Math.round(maxY - minY + pad * 2),
      rotation: 0,
      opacity: 1,
    };
    out.push({
      box,
      text,
      localPts: pts.map((p) => ({ x: p.x - box.x, y: p.y - box.y })),
      localBar: bar
        ? { x1: bar.x1 - box.x, y1: bar.y1 - box.y, x2: bar.x2 - box.x, y2: bar.y2 - box.y }
        : null,
    });
  }
  return out;
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

const CYCLE_NODE_GRAY = '#D1D5DB';
const CYCLE_NODE_ACCENTS = ['#3B82F6', '#8A9A4A', '#E67E22', '#4B5563', '#E4B84A'];
const CYCLE_HBAR_COLORS = CYCLE_NODE_ACCENTS;

function cycleNodePalette(index = 0) {
  const i = ((Number(index) % 5) + 5) % 5;
  const accent = CYCLE_NODE_ACCENTS[i];
  const gray = CYCLE_NODE_GRAY;
  if (i % 2 === 0) return { top: accent, bot: gray, accent };
  return { top: gray, bot: accent, accent };
}

function cycleHalfRingArrowPath(side) {
  const cx = 120;
  const cy = 120;
  const rOut = 94;
  const rIn = 66;
  const rMid = (rOut + rIn) / 2;
  const head = 0.2;
  const tipLen = rOut - rIn;
  const a0 = side === 'top' ? Math.PI : 0;
  const a1 = side === 'top' ? Math.PI * 2 : Math.PI;
  const aJ = a1 - head;
  const [ox0, oy0] = polar(cx, cy, rOut, a0);
  const [ox1, oy1] = polar(cx, cy, rOut, aJ);
  const [ix1, iy1] = polar(cx, cy, rIn, aJ);
  const [ix0, iy0] = polar(cx, cy, rIn, a0);
  const [mx, my] = polar(cx, cy, rMid, a1);
  const tx = mx - tipLen * Math.sin(a1);
  const ty = my + tipLen * Math.cos(a1);
  return `M ${ox0.toFixed(1)} ${oy0.toFixed(1)} A ${rOut} ${rOut} 0 0 1 ${ox1.toFixed(1)} ${oy1.toFixed(1)} L ${tx.toFixed(1)} ${ty.toFixed(1)} L ${ix1.toFixed(1)} ${iy1.toFixed(1)} A ${rIn} ${rIn} 0 0 0 ${ix0.toFixed(1)} ${iy0.toFixed(1)} Z`;
}

function cycleNodeTopArcSvg() {
  const d = cycleHalfRingArrowPath('top');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 240" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><path d="${d}" fill="currentColor"/></svg>`;
}

function cycleNodeBotArcSvg() {
  const d = cycleHalfRingArrowPath('bot');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 240" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><path d="${d}" fill="currentColor"/></svg>`;
}

function nodeIconWrap(inner) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="100%" height="100%" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
}

function cycleNodeIconSvg(index = 0) {
  const i = ((Number(index) % 5) + 5) % 5;
  if (i === 0) {
    return nodeIconWrap(`<rect x="16" y="22" width="32" height="24" rx="2"/><path d="M16 30h32M28 22v-6h8v6"/>`);
  }
  if (i === 1) {
    return nodeIconWrap(`<rect x="18" y="16" width="24" height="30" rx="2"/><rect x="22" y="20" width="24" height="30" rx="2"/>`);
  }
  if (i === 2) {
    return nodeIconWrap(`<path d="M12 48V28l20-12 20 12v20H12z"/><path d="M28 48V36h8v12"/>`);
  }
  if (i === 3) {
    return nodeIconWrap(`<circle cx="32" cy="32" r="14"/><path d="M32 18v4M32 42v4M18 32h4M42 32h4M22 22l3 3M39 39l3 3M22 42l3-3M39 25l3-3"/>`);
  }
  return nodeIconWrap(`<rect x="18" y="24" width="28" height="22" rx="2"/><path d="M24 24V20h16v4"/>`);
}

function cycleLoopInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none" fill="none"><path d="M1748 760 C1888 700 1860 36 1260 36" stroke="currentColor" stroke-width="22" stroke-linecap="round"/><path fill="currentColor" d="M1304 14 L1204 36 L1304 58 Z"/><path d="M70 820 L148 820" stroke="currentColor" stroke-width="14" stroke-linecap="round"/><path fill="currentColor" d="M148 806 L186 820 L148 834 Z"/></svg>`;
}

function cycleBarInlineSvg(kind = 'mid') {
  if (kind === 'first') {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 160" width="100%" height="100%" preserveAspectRatio="none"><path fill="currentColor" d="M24 0h176v160H24C10.7 160 0 149.3 0 136V24C0 10.7 10.7 0 24 0z"/></svg>`;
  }
  if (kind === 'last') {
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 160" width="100%" height="100%" preserveAspectRatio="none"><path fill="currentColor" d="M0 0h168L240 80 168 160H0z"/></svg>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 160" width="100%" height="100%" preserveAspectRatio="none"><rect width="200" height="160" fill="currentColor"/></svg>`;
}

function cycleDropInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 48" width="100%" height="100%" preserveAspectRatio="none"><path fill="currentColor" d="M12 0h8v36c0 8-4 12-8 12s-8-4-8-12V0z"/></svg>`;
}

function cycleChevronInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 32" width="100%" height="100%" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M8 4l12 12L8 28"/></svg>`;
}

function hbarIconWrap(inner) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="100%" height="100%" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
}

function cycleHbarIconSvg(index = 0) {
  const i = ((Number(index) % 5) + 5) % 5;
  if (i === 0) {
    return hbarIconWrap(
      `<circle cx="22" cy="22" r="8"/><circle cx="42" cy="22" r="8"/><circle cx="32" cy="26" r="8"/><path d="M10 50c2-10 10-16 22-16s20 6 22 16"/>`
    );
  }
  if (i === 1) {
    return hbarIconWrap(
      `<path d="M18 36c4 8 10 12 14 12s10-4 14-12"/><path d="M22 30c0-6 4-10 10-10s10 4 10 10"/><path d="M18 36c-4 0-8-4-8-9 0-4 3-7 7-7 2 0 4 1 5 3"/><path d="M46 36c4 0 8-4 8-9 0-4-3-7-7-7-2 0-4 1-5 3"/>`
    );
  }
  if (i === 2) {
    return hbarIconWrap(
      `<path d="M12 48V28l10 8 10-16 10 12 10-20v36H12z"/><path d="M12 48h40"/><path d="M44 18l6-8 4 4"/>`
    );
  }
  if (i === 3) {
    return hbarIconWrap(
      `<rect x="14" y="16" width="16" height="20" rx="2"/><rect x="34" y="22" width="16" height="20" rx="2"/><rect x="24" y="30" width="16" height="20" rx="2"/>`
    );
  }
  return hbarIconWrap(
    `<rect x="16" y="14" width="32" height="38" rx="3"/><path d="M24 28l6 6 12-14"/>`
  );
}

module.exports = {
  CYCLE_SEGMENT_COLORS,
  CYCLE_HBAR_COLORS,
  CYCLE_GEOM,
  cycleOverlayPlacements,
  buildCycleDiagramSvg,
  cycleDiagramDataUri,
  cycleDiagramInlineSvg,
  cycleSegmentInlineSvg,
  cycleSegmentPlacement,
  cycleLoopInlineSvg,
  cycleBarInlineSvg,
  cycleDropInlineSvg,
  cycleChevronInlineSvg,
  cycleHbarIconSvg,
  cycleNodePalette,
  cycleNodeTopArcSvg,
  cycleNodeBotArcSvg,
  cycleNodeIconSvg,
  CYCLE_RING_N,
  CYCLE_RING_COLORS,
  CYCLE_RING_GEOM,
  cycleRingSegSvg,
  cycleRingSegPlacement,
  cycleRingDiamondSvg,
  cycleRingCalloutSvg,
  cycleRingCallouts,
};
