function mixHex(hex, toward = '#ffffff', t = 0.25) {
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

const FUNNEL_STAGE_COLORS = ['#1e3a5f', '#2563eb', '#ea580c', '#64748b'];
const FUNNEL_TITLE_COLORS = ['#1e3a5f', '#1d4ed8', '#c2410c', '#334155'];

const FUNNEL_GEOM = {
  viewW: 820,
  viewH: 980,
  cx: 310,
  y0: 36,
  gap: 16,
  bandH: 220,
  widths: [600, 468, 344, 216, 72],
  tabW: 168,
  tabGap: 16,
  ry: 32,
};

function funnelStageGeom(i) {
  const { cx, y0, gap, bandH, widths, tabW, tabGap, ry } = FUNNEL_GEOM;
  const y = y0 + i * (bandH + gap);
  const wTop = widths[i];
  const wBot = widths[i + 1];
  const rightTop = cx + wTop / 2;
  const rightBot = cx + wBot / 2;
  return {
    i,
    y,
    wTop,
    wBot,
    bandH,
    tabW,
    tabGap,
    ry,
    cx,
    leftTop: cx - wTop / 2,
    rightTop,
    leftBot: cx - wBot / 2,
    rightBot,
    tabInTop: rightTop + tabGap,
    tabInBot: rightBot + tabGap,
    tabOutTop: rightTop + tabGap + tabW,
    tabOutBot: rightBot + tabGap + tabW,
  };
}

function funnelOverlayPlacements(gx, gy, gw, gh) {
  const sx = gw / FUNNEL_GEOM.viewW;
  const sy = gh / FUNNEL_GEOM.viewH;
  const stages = [0, 1, 2, 3].map((i) => funnelStageGeom(i));
  return {
    stages: stages.map((g) => {
      const left = Math.max(g.tabInTop, g.tabInBot);
      const right = Math.min(g.tabOutTop, g.tabOutBot);
      return {
        num: {
          x: Math.round(gx + (left + 6) * sx),
          y: Math.round(gy + (g.y + 8) * sy),
          width: Math.max(72, Math.round((right - left - 12) * sx)),
          height: Math.round((g.bandH - 16) * sy),
        },
        y: Math.round(gy + g.y * sy),
        h: Math.round(g.bandH * sy),
      };
    }),
  };
}

function funnelStageInnerMarkup(i) {
  const g = funnelStageGeom(i);
  const yb = g.y + g.bandH;
  const shadeLTop = g.cx + g.wTop * 0.18;
  const shadeLBot = g.cx + g.wBot * 0.18;
  return [
    `<path d="M ${g.leftTop.toFixed(1)} ${g.y.toFixed(1)} L ${g.leftBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightTop.toFixed(1)} ${g.y.toFixed(1)} Z" fill="currentColor"/>`,
    `<path d="M ${shadeLTop.toFixed(1)} ${g.y.toFixed(1)} L ${shadeLBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightTop.toFixed(1)} ${g.y.toFixed(1)} Z" fill="#000000" opacity="0.22"/>`,
    `<ellipse cx="${g.cx}" cy="${yb}" rx="${(g.wBot / 2).toFixed(1)}" ry="${g.ry.toFixed(1)}" fill="#000000" opacity="0.28"/>`,
    `<ellipse cx="${g.cx}" cy="${g.y}" rx="${(g.wTop / 2).toFixed(1)}" ry="${g.ry.toFixed(1)}" fill="currentColor"/>`,
    `<ellipse cx="${g.cx}" cy="${g.y}" rx="${(g.wTop / 2).toFixed(1)}" ry="${g.ry.toFixed(1)}" fill="#ffffff" opacity="0.38"/>`,
    `<path d="M ${g.tabInTop.toFixed(1)} ${(g.y + 6).toFixed(1)} L ${g.tabOutTop.toFixed(1)} ${(g.y + 6).toFixed(1)} L ${g.tabOutBot.toFixed(1)} ${(yb - 6).toFixed(1)} L ${g.tabInBot.toFixed(1)} ${(yb - 6).toFixed(1)} Z" fill="currentColor"/>`,
  ].join('');
}

function funnelStageViewBox(i) {
  const g = funnelStageGeom(i);
  const yb = g.y + g.bandH;
  const left = Math.min(g.leftTop, g.leftBot) - 10;
  const right = Math.max(g.tabOutTop, g.tabOutBot) + 10;
  const top = g.y - g.ry - 10;
  const bot = yb + g.ry + 10;
  return { x: left, y: top, w: right - left, h: bot - top };
}

function funnelStagePlacement(gx, gy, gw, gh, i) {
  const sx = gw / FUNNEL_GEOM.viewW;
  const sy = gh / FUNNEL_GEOM.viewH;
  const v = funnelStageViewBox(i);
  return {
    x: Math.round(gx + v.x * sx),
    y: Math.round(gy + v.y * sy),
    width: Math.round(v.w * sx),
    height: Math.round(v.h * sy),
  };
}

function funnelStageInlineSvg(i) {
  const v = funnelStageViewBox(i);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${v.x} ${v.y} ${v.w} ${v.h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${funnelStageInnerMarkup(i)}</svg>`;
}

function buildFunnelDiagramSvg(colors = FUNNEL_STAGE_COLORS) {
  const { viewW, viewH } = FUNNEL_GEOM;
  const parts = [];
  for (let i = 0; i < 4; i += 1) {
    const g = funnelStageGeom(i);
    const color = colors[i % colors.length];
    const lid = mixHex(color, '#ffffff', 0.42);
    const hole = mixHex(color, '#000000', 0.28);
    const shade = mixHex(color, '#000000', 0.22);
    const yb = g.y + g.bandH;
    parts.push(
      `<path d="M ${g.leftTop.toFixed(1)} ${g.y.toFixed(1)} L ${g.leftBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightTop.toFixed(1)} ${g.y.toFixed(1)} Z" fill="${color}"/>`
    );
    const shadeLTop = g.cx + g.wTop * 0.18;
    const shadeLBot = g.cx + g.wBot * 0.18;
    parts.push(
      `<path d="M ${shadeLTop.toFixed(1)} ${g.y.toFixed(1)} L ${shadeLBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightBot.toFixed(1)} ${yb.toFixed(1)} L ${g.rightTop.toFixed(1)} ${g.y.toFixed(1)} Z" fill="${shade}" opacity="0.45"/>`
    );
    parts.push(
      `<ellipse cx="${g.cx}" cy="${yb}" rx="${(g.wBot / 2).toFixed(1)}" ry="${g.ry.toFixed(1)}" fill="${hole}"/>`
    );
    parts.push(
      `<ellipse cx="${g.cx}" cy="${g.y}" rx="${(g.wTop / 2).toFixed(1)}" ry="${g.ry.toFixed(1)}" fill="${lid}"/>`
    );
    parts.push(
      `<path d="M ${g.tabInTop.toFixed(1)} ${(g.y + 6).toFixed(1)} L ${g.tabOutTop.toFixed(1)} ${(g.y + 6).toFixed(1)} L ${g.tabOutBot.toFixed(1)} ${(yb - 6).toFixed(1)} L ${g.tabInBot.toFixed(1)} ${(yb - 6).toFixed(1)} Z" fill="${color}"/>`
    );
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}">${parts.join('')}</svg>`;
}

function funnelDiagramInlineSvg(colors = FUNNEL_STAGE_COLORS) {
  return buildFunnelDiagramSvg(colors).replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs;
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"';
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"';
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMinYMid meet"';
    return `<svg${next}>`;
  });
}

const FUNNEL_H_STAGE_COLORS = FUNNEL_STAGE_COLORS;
const FUNNEL_H_TITLE_COLORS = FUNNEL_TITLE_COLORS;

const FUNNEL_H_GEOM = {
  viewW: 1680,
  viewH: 700,
  cy: 292,
  x0: Math.round((1680 - (360 * 4 + 16 * 3)) / 2),
  gap: 16,
  bandW: 360,
  heights: [560, 440, 330, 220, 96],
  tabH: 76,
  tabGap: 0,
  rx: 30,
};

function funnelHStageGeom(i) {
  const { cy, x0, gap, bandW, heights, tabH, tabGap, rx } = FUNNEL_H_GEOM;
  const x = x0 + i * (bandW + gap);
  const hL = heights[i];
  const hR = heights[i + 1];
  const botL = cy + hL / 2;
  const botR = cy + hR / 2;
  const tabInL = botL + tabGap;
  const tabInR = botR + tabGap;
  return {
    i,
    x,
    xr: x + bandW,
    bandW,
    hL,
    hR,
    cy,
    rx,
    tabH,
    tabGap,
    topL: cy - hL / 2,
    botL,
    topR: cy - hR / 2,
    botR,
    tabInL,
    tabInR,
    tabOutL: tabInL + tabH,
    tabOutR: tabInR + tabH,
  };
}

function funnelHStageInnerMarkup(i, fills = null) {
  const g = funnelHStageGeom(i);
  const body = fills?.body ?? 'currentColor';
  const shade = fills?.shade ?? '#000000';
  const hole = fills?.hole ?? '#000000';
  const lid = fills?.lid ?? 'currentColor';
  const shadeYl = g.cy + g.hL * 0.18;
  const shadeYr = g.cy + g.hR * 0.18;
  return [
    `<path d="M ${g.x.toFixed(1)} ${g.topL.toFixed(1)} L ${g.x.toFixed(1)} ${g.botL.toFixed(1)} L ${g.xr.toFixed(1)} ${g.botR.toFixed(1)} L ${g.xr.toFixed(1)} ${g.topR.toFixed(1)} Z" fill="${body}" pointer-events="visiblePainted"/>`,
    `<path d="M ${g.x.toFixed(1)} ${shadeYl.toFixed(1)} L ${g.x.toFixed(1)} ${g.botL.toFixed(1)} L ${g.xr.toFixed(1)} ${g.botR.toFixed(1)} L ${g.xr.toFixed(1)} ${shadeYr.toFixed(1)} Z" fill="${shade}" opacity="0.22" pointer-events="none"/>`,
    `<ellipse cx="${g.xr.toFixed(1)}" cy="${g.cy.toFixed(1)}" rx="${g.rx.toFixed(1)}" ry="${(g.hR / 2).toFixed(1)}" fill="${hole}" opacity="${fills ? 1 : 0.28}" pointer-events="none"/>`,
    `<ellipse cx="${g.x.toFixed(1)}" cy="${g.cy.toFixed(1)}" rx="${g.rx.toFixed(1)}" ry="${(g.hL / 2).toFixed(1)}" fill="${lid}" pointer-events="none"/>`,
    fills ? '' : `<ellipse cx="${g.x.toFixed(1)}" cy="${g.cy.toFixed(1)}" rx="${g.rx.toFixed(1)}" ry="${(g.hL / 2).toFixed(1)}" fill="#ffffff" opacity="0.38" pointer-events="none"/>`,
    `<path d="M ${(g.x + 8).toFixed(1)} ${g.tabInL.toFixed(1)} L ${(g.xr - 8).toFixed(1)} ${g.tabInR.toFixed(1)} L ${(g.xr - 8).toFixed(1)} ${g.tabOutR.toFixed(1)} L ${(g.x + 8).toFixed(1)} ${g.tabOutL.toFixed(1)} Z" fill="${body}" pointer-events="visiblePainted"/>`,
  ].join('');
}

function funnelHSegView(i) {
  const g = funnelHStageGeom(i);
  const left = g.x - g.rx - 10;
  const right = g.xr + g.rx + 10;
  const top = Math.min(g.topL, g.topR) - 10;
  const bot = Math.max(g.tabOutL, g.tabOutR) + 10;
  return { x: left, y: top, w: right - left, h: bot - top };
}

function funnelHSegInlineSvg(i) {
  const v = funnelHSegView(i);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${v.x} ${v.y} ${v.w} ${v.h}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${funnelHStageInnerMarkup(i)}</svg>`;
}

function funnelHSegPlacement(gx, gy, gw, gh, i) {
  const sx = gw / FUNNEL_H_GEOM.viewW;
  const sy = gh / FUNNEL_H_GEOM.viewH;
  const v = funnelHSegView(i);
  return {
    x: Math.round(gx + v.x * sx),
    y: Math.round(gy + v.y * sy),
    width: Math.round(v.w * sx),
    height: Math.round(v.h * sy),
  };
}

function funnelHOverlayPlacements(gx, gy, gw, gh) {
  const sx = gw / FUNNEL_H_GEOM.viewW;
  const sy = gh / FUNNEL_H_GEOM.viewH;
  return {
    stages: [0, 1, 2, 3].map((i) => {
      const g = funnelHStageGeom(i);
      return {
        num: {
          x: Math.round(gx + (g.x + 28) * sx),
          y: Math.round(gy + ((g.tabInL + g.tabInR) / 2 + 8) * sy),
          width: Math.round((g.bandW - 56) * sx),
          height: Math.round((g.tabH - 16) * sy),
        },
        x: Math.round(gx + g.x * sx),
        w: Math.round(g.bandW * sx),
      };
    }),
  };
}

function funnelHColumnPlacements(gx, gy, gw, gh) {
  return funnelHOverlayPlacements(gx, gy, gw, gh).stages.map((s) => ({ x: s.x, w: s.w }));
}

function funnelHPreviewSvg(colors = FUNNEL_STAGE_COLORS) {
  const { viewW, viewH } = FUNNEL_H_GEOM;
  const parts = [0, 1, 2, 3].map((i) => {
    const color = colors[i % colors.length];
    return funnelHStageInnerMarkup(i, {
      body: color,
      shade: mixHex(color, '#000000', 0.22),
      hole: mixHex(color, '#000000', 0.28),
      lid: mixHex(color, '#ffffff', 0.42),
    });
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet">${parts.join('')}</svg>`;
}

module.exports = {
  FUNNEL_STAGE_COLORS,
  FUNNEL_TITLE_COLORS,
  FUNNEL_GEOM,
  funnelOverlayPlacements,
  funnelDiagramInlineSvg,
  funnelStageInlineSvg,
  funnelStagePlacement,
  FUNNEL_H_STAGE_COLORS,
  FUNNEL_H_TITLE_COLORS,
  FUNNEL_H_GEOM,
  funnelHSegInlineSvg,
  funnelHSegPlacement,
  funnelHColumnPlacements,
  funnelHOverlayPlacements,
  funnelHPreviewSvg,
};
