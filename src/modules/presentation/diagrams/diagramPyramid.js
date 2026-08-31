const PYRAMID_N = 5;
const PYRAMID_COLORS = ['#3b82f6', '#0f9d8a', '#86efac', '#f4c430', '#f97316'];

const PYRAMID_GEOM = {
  viewW: 900,
  viewH: 980,
  cx: 450,
  y0: 48,
  totalH: 900,
  baseW: 820,
  tabR: 30,
};

function pyramidStageGeom(i) {
  const { cx, y0, totalH, baseW, tabR } = PYRAMID_GEOM;
  const n = PYRAMID_N;
  const bandH = totalH / n;
  const yTop = y0 + i * bandH;
  const yBot = yTop + bandH;
  const wTop = (i / n) * baseW;
  const wBot = ((i + 1) / n) * baseW;
  return {
    i,
    yTop,
    yBot,
    bandH,
    wTop,
    wBot,
    tabR,
    cx,
    leftTop: cx - wTop / 2,
    rightTop: cx + wTop / 2,
    leftBot: cx - wBot / 2,
    rightBot: cx + wBot / 2,
  };
}

function pyramidStagePath(g) {
  const { cx, tabR, yTop, yBot } = g;
  const tab = g.i > 0;
  const notch = g.i < PYRAMID_N - 1;
  const parts = [`M ${g.leftTop.toFixed(1)} ${yTop.toFixed(1)}`];
  if (tab) {
    parts.push(
      `L ${(cx - tabR).toFixed(1)} ${yTop.toFixed(1)}`,
      `Q ${cx.toFixed(1)} ${(yTop - tabR).toFixed(1)} ${(cx + tabR).toFixed(1)} ${yTop.toFixed(1)}`
    );
  }
  parts.push(`L ${g.rightTop.toFixed(1)} ${yTop.toFixed(1)}`);
  parts.push(`L ${g.rightBot.toFixed(1)} ${yBot.toFixed(1)}`);
  if (notch) {
    parts.push(
      `L ${(cx + tabR).toFixed(1)} ${yBot.toFixed(1)}`,
      `Q ${cx.toFixed(1)} ${(yBot - tabR).toFixed(1)} ${(cx - tabR).toFixed(1)} ${yBot.toFixed(1)}`
    );
  }
  parts.push(`L ${g.leftBot.toFixed(1)} ${yBot.toFixed(1)} Z`);
  return parts.join(' ');
}

function personIcon(x, y, s) {
  const h = 12 * s;
  const r = 2.4 * s;
  return [
    `<circle cx="${x.toFixed(1)}" cy="${(y - h * 0.28).toFixed(1)}" r="${r.toFixed(1)}" fill="#ffffff"/>`,
    `<path d="M ${(x - 4.2 * s).toFixed(1)} ${(y + h * 0.42).toFixed(1)} Q ${x.toFixed(1)} ${(y + h * 0.02).toFixed(1)} ${(x + 4.2 * s).toFixed(1)} ${(y + h * 0.42).toFixed(1)} Z" fill="#ffffff"/>`,
  ].join('');
}

function pyramidPeopleMarkup(g) {
  const count = 1 + g.i * 2;
  const y = g.yTop + g.bandH * 0.58;
  const maxW = Math.min(g.wTop, g.wBot) * 0.72 || g.wBot * 0.55;
  const s = Math.min(2.4, g.bandH / 38, maxW / (count * 14));
  const gap = 11 * s;
  const total = (count - 1) * gap;
  const x0 = g.cx - total / 2;
  let out = '';
  for (let p = 0; p < count; p += 1) out += personIcon(x0 + p * gap, y, s);
  return out;
}

function pyramidStageInnerMarkup(i) {
  const g = pyramidStageGeom(i);
  return `<path d="${pyramidStagePath(g)}" fill="currentColor"/>${pyramidPeopleMarkup(g)}`;
}

function pyramidStageViewBox(i) {
  const g = pyramidStageGeom(i);
  const pad = g.tabR + 8;
  const left = Math.min(g.leftTop, g.leftBot) - 8;
  const right = Math.max(g.rightTop, g.rightBot) + 8;
  const top = g.yTop - (g.i > 0 ? pad : 8);
  const bot = g.yBot + 8;
  return { x: left, y: top, w: right - left, h: bot - top };
}

function pyramidStagePlacement(gx, gy, gw, gh, i) {
  const sx = gw / PYRAMID_GEOM.viewW;
  const sy = gh / PYRAMID_GEOM.viewH;
  const v = pyramidStageViewBox(i);
  return {
    x: Math.round(gx + v.x * sx),
    y: Math.round(gy + v.y * sy),
    width: Math.round(v.w * sx),
    height: Math.round(v.h * sy),
  };
}

function pyramidStageInlineSvg(i) {
  const v = pyramidStageViewBox(i);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${v.x} ${v.y} ${v.w} ${v.h}" width="100%" height="100%" preserveAspectRatio="none">${pyramidStageInnerMarkup(i)}</svg>`;
}

function pyramidGraphicBox(canvasW, canvasH) {
  const headingY = 36;
  const headingH = 70;
  const y = headingY + headingH + 8;
  const h = canvasH - y - 40;
  const graphicW = Math.round(Math.min(920, canvasW * 0.5));
  const graphicX = 48;
  const legendX = graphicX + graphicW + 28;
  const legendW = Math.max(320, canvasW - legendX - 56);
  return { headingY, headingH, graphicX, graphicY: y, graphicW, graphicH: h, legendX, legendW, canvasW };
}

function pyramidLegendPlacements(frame) {
  const { graphicY, graphicH, legendX, legendW } = frame;
  const sy = graphicH / PYRAMID_GEOM.viewH;
  const badgeW = 128;
  const badgeH = 108;
  return [0, 1, 2, 3, 4].map((i) => {
    const g = pyramidStageGeom(i);
    const midY = graphicY + ((g.yTop + g.yBot) / 2) * sy;
    const rowH = Math.round(g.bandH * sy);
    return {
      badge: {
        x: Math.round(legendX),
        y: Math.round(midY - badgeH / 2),
        width: badgeW,
        height: badgeH,
      },
      num: {
        x: Math.round(legendX + 6),
        y: Math.round(midY - badgeH / 2 + 8),
        width: Math.round(badgeW * 0.58),
        height: badgeH - 16,
      },
      title: {
        x: Math.round(legendX + badgeW + 18),
        y: Math.round(midY - rowH * 0.28),
        width: Math.round(legendW - badgeW - 18),
        height: 36,
      },
      body: {
        x: Math.round(legendX + badgeW + 18),
        y: Math.round(midY + 10),
        width: Math.round(legendW - badgeW - 18),
        height: Math.max(40, Math.round(rowH * 0.42)),
      },
    };
  });
}

const PYRAMID_BADGE_CLIP = 'polygon(0% 6%, 92% 50%, 0% 94%)';

module.exports = {
  PYRAMID_N,
  PYRAMID_COLORS,
  PYRAMID_GEOM,
  pyramidStageGeom,
  pyramidStagePlacement,
  pyramidStageInlineSvg,
  pyramidGraphicBox,
  pyramidLegendPlacements,
  PYRAMID_BADGE_CLIP,
};
