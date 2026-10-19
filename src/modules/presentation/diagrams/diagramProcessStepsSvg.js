const PROCESS_STEP_COLORS = ['#2F5BD6', '#4AA3E0', '#2FCB8A', '#F0B429'];

const PROCESS_RIBBON_VB = { w: 400, h: 148 };
const PROCESS_RIBBON_LABEL = { x: 22, y: 8, w: 210, h: 116 };

function processRibbonLabelBox(x, y, w, h) {
  const vb = PROCESS_RIBBON_VB;
  const L = PROCESS_RIBBON_LABEL;
  return {
    x: Math.round(x + (L.x / vb.w) * w),
    y: Math.round(y + (L.y / vb.h) * h),
    width: Math.round((L.w / vb.w) * w),
    height: Math.round((L.h / vb.h) * h),
  };
}

function processRibbonInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 148" width="100%" height="100%" preserveAspectRatio="none"><path fill="currentColor" d="M0 0h308L400 62 308 124H0z"/><path fill="#000" opacity="0.3" d="M0 124h22L0 148z"/></svg>`;
}

function iconWrap(inner) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="100%" height="100%" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;
}

function processIconInlineSvg(index = 0) {
  const i = ((Number(index) % 4) + 4) % 4;
  if (i === 0) {
    return iconWrap(
      `<path d="M18 36c4 8 10 12 14 12s10-4 14-12"/><path d="M22 30c0-6 4-10 10-10s10 4 10 10"/><path d="M18 36c-4 0-8-4-8-9 0-4 3-7 7-7 2 0 4 1 5 3"/><path d="M46 36c4 0 8-4 8-9 0-4-3-7-7-7-2 0-4 1-5 3"/>`
    );
  }
  if (i === 1) {
    return iconWrap(
      `<circle cx="24" cy="28" r="10"/><circle cx="40" cy="38" r="10"/><path d="M24 18v4M24 34v4M14 28h4M30 28h4M40 28v4M40 48v4M30 38h4M46 38h4"/>`
    );
  }
  if (i === 2) {
    return iconWrap(
      `<rect x="14" y="28" width="36" height="22" rx="3"/><path d="M22 28V22h20v6"/><path d="M32 14l8 12H24z"/><path d="M32 18v8"/>`
    );
  }
  return iconWrap(
    `<circle cx="32" cy="32" r="14"/><path d="M32 22v20M26 28h8c3 0 5 2 5 4s-2 4-5 4h-8"/><circle cx="18" cy="18" r="3"/><circle cx="46" cy="18" r="3"/><circle cx="18" cy="46" r="3"/><circle cx="46" cy="46" r="3"/><path d="M20.2 20.2 26 26M43.8 20.2 38 26M20.2 43.8 26 38M43.8 43.8 38 38"/>`
  );
}

function processFlowArrowInlineSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 24" width="100%" height="100%" preserveAspectRatio="none"><path fill="currentColor" d="M0 9h42V3l22 9-22 9v-6H0z"/></svg>`;
}

module.exports = {
  PROCESS_STEP_COLORS,
  processRibbonInlineSvg,
  processRibbonLabelBox,
  processIconInlineSvg,
  processFlowArrowInlineSvg,
};
