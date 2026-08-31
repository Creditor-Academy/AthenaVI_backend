const VENN_N = 3;
const VENN_COLORS = ['#4a6fa5', '#e08a2a', '#2a9d8f'];

function mixHex(hex, toward = '#ffffff', t = 0.4) {
  const parse = (h) => {
    const s = String(h || '').replace('#', '');
    if (s.length !== 6) return null;
    return [parseInt(s.slice(0, 2), 16), parseInt(s.slice(2, 4), 16), parseInt(s.slice(4, 6), 16)];
  };
  const a = parse(hex);
  const b = parse(toward);
  if (!a || !b) return hex;
  const m = (i) => Math.round(a[i] + (b[i] - a[i]) * t);
  return `#${[m(0), m(1), m(2)].map((n) => n.toString(16).padStart(2, '0')).join('')}`;
}

function vennRingColor(base, ring) {
  if (ring === 'outer') return mixHex(base, '#ffffff', 0.62);
  if (ring === 'mid') return mixHex(base, '#ffffff', 0.28);
  return mixHex(base, '#000000', 0.18);
}

function iconCode() {
  return `<path d="M30 28 L18 40 L30 52" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M50 28 L62 40 L50 52" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M44 24 L36 56" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round"/>`;
}
function iconBulb() {
  return `<path d="M40 22c-8 0-14 6.2-14 14 0 5.2 2.8 9.6 7 12v6h14v-6c4.2-2.4 7-6.8 7-12 0-7.8-6-14-14-14z" fill="none" stroke="#fff" stroke-width="2.8"/><path d="M34 56h12M36 61h8" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/>`;
}
function iconMind() {
  return `<circle cx="40" cy="34" r="12" fill="none" stroke="#fff" stroke-width="2.8"/><path d="M24 58c4-10 12-14 16-14s12 4 16 14" fill="none" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/>`;
}

const ICONS = [iconCode, iconBulb, iconMind];

function vennCoreInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80" width="100%" height="100%"><circle cx="40" cy="40" r="36" fill="currentColor"/></svg>`;
}

function vennIconInlineSvg(i) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80" width="100%" height="100%">${ICONS[i]()}</svg>`;
}

function vennFrame(canvasW, canvasH) {
  const headingY = 48;
  const headingH = 68;
  const outer = Math.round(Math.min(230, canvasW * 0.12));
  const mid = Math.round(outer * 0.66);
  const core = Math.round(outer * 0.36);
  const gap = Math.round(outer * 1.32);
  const titleH = 64;
  const insetX = 48;
  const colPad = 20;
  const colW = Math.round((canvasW - insetX * 2) / 3) - colPad * 2;
  const clusterH = outer * 2 + 20 + titleH + 200;
  const avail = canvasH - headingY - headingH - 40;
  const topPad = Math.max(16, Math.round((avail - clusterH) / 2));
  const cy = headingY + headingH + topPad + outer;
  const startX = Math.round(canvasW / 2 - gap);
  const titleY = cy + outer + 20;
  const bodyY = titleY + titleH + 6;
  const bodyH = Math.max(180, canvasH - bodyY - 36);
  return {
    headingY,
    headingH,
    outer,
    mid,
    core,
    gap,
    cy,
    startX,
    colW,
    colPad,
    insetX,
    titleY,
    titleH,
    bodyY,
    bodyH,
    canvasW,
    canvasH,
  };
}

function vennSetGeom(i, frame) {
  const { outer, mid, core, gap, cy, startX, colW, colPad, insetX, titleY, titleH, bodyY, bodyH } = frame;
  const cx = startX + i * gap;
  const colSlot = Math.round((frame.canvasW - insetX * 2) / 3);
  const textX = insetX + i * colSlot + colPad;
  const box = (r) => ({
    x: Math.round(cx - r),
    y: Math.round(cy - r),
    width: r * 2,
    height: r * 2,
  });
  return {
    cx,
    outer: box(outer),
    mid: box(mid),
    core: box(core),
    icon: box(core),
    title: {
      x: textX,
      y: titleY,
      width: colW,
      height: titleH,
    },
    body: {
      x: textX,
      y: bodyY,
      width: colW,
      height: bodyH,
    },
  };
}

module.exports = {
  VENN_N,
  VENN_COLORS,
  vennRingColor,
  vennCoreInlineSvg,
  vennIconInlineSvg,
  vennFrame,
  vennSetGeom,
};
