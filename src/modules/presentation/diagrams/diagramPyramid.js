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

const LAYER_GAP = 22;
const LAYER_ISO = { dx: 42, dy: -30 };

function pyramidModeFromSchema(schema) {
  const id = String(schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.diagramVariant || '').toLowerCase();
  if (variant === 'layers' || (id.includes('pyramid') && id.includes('layers'))) return 'layers';
  if (variant === 'inverted' || (id.includes('pyramid') && id.includes('inverted'))) return 'inverted';
  return 'classic';
}

function pyramidStageGeom(i, mode = 'classic') {
  const { cx, y0, totalH, baseW, tabR } = PYRAMID_GEOM;
  const n = PYRAMID_N;
  const inverted = mode === 'inverted';
  const layers = mode === 'layers';
  const gap = layers ? LAYER_GAP : 0;
  const usable = totalH - gap * (n - 1);
  const bandH = usable / n;
  const yTop = y0 + i * (bandH + gap);
  const yBot = yTop + bandH;
  const wTop = inverted ? ((n - i) / n) * baseW : (i / n) * baseW;
  const wBot = inverted ? ((n - i - 1) / n) * baseW : ((i + 1) / n) * baseW;
  return {
    i,
    mode,
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
  const { cx, tabR, yTop, yBot, mode } = g;
  if (mode === 'layers') {
    return [
      `M ${g.leftTop.toFixed(1)} ${yTop.toFixed(1)}`,
      `L ${g.rightTop.toFixed(1)} ${yTop.toFixed(1)}`,
      `L ${g.rightBot.toFixed(1)} ${yBot.toFixed(1)}`,
      `L ${g.leftBot.toFixed(1)} ${yBot.toFixed(1)} Z`,
    ].join(' ');
  }
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

function pyramidLayerFaces(g) {
  const { dx, dy } = LAYER_ISO;
  const top = [
    `M ${g.leftTop.toFixed(1)} ${g.yTop.toFixed(1)}`,
    `L ${g.rightTop.toFixed(1)} ${g.yTop.toFixed(1)}`,
    `L ${(g.rightTop + dx).toFixed(1)} ${(g.yTop + dy).toFixed(1)}`,
    `L ${(g.leftTop + dx).toFixed(1)} ${(g.yTop + dy).toFixed(1)} Z`,
  ].join(' ');
  const right = [
    `M ${g.rightTop.toFixed(1)} ${g.yTop.toFixed(1)}`,
    `L ${(g.rightTop + dx).toFixed(1)} ${(g.yTop + dy).toFixed(1)}`,
    `L ${(g.rightBot + dx).toFixed(1)} ${(g.yBot + dy).toFixed(1)}`,
    `L ${g.rightBot.toFixed(1)} ${g.yBot.toFixed(1)} Z`,
  ].join(' ');
  return { top, right };
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
  const widthRank = g.mode === 'inverted' ? PYRAMID_N - 1 - g.i : g.i;
  const count = 1 + widthRank * 2;
  const y = g.yTop + g.bandH * 0.58;
  const maxW = Math.min(g.wTop, g.wBot) * 0.72 || Math.max(g.wTop, g.wBot) * 0.55;
  const s = Math.min(2.4, g.bandH / 38, maxW / (count * 14));
  const gap = 11 * s;
  const total = (count - 1) * gap;
  const x0 = g.cx - total / 2;
  let out = '';
  for (let p = 0; p < count; p += 1) out += personIcon(x0 + p * gap, y, s);
  return out;
}

function pyramidStageInnerMarkup(i, mode = 'classic') {
  const g = pyramidStageGeom(i, mode);
  const front = `<path d="${pyramidStagePath(g)}" fill="currentColor"/>`;
  if (mode === 'layers') {
    const faces = pyramidLayerFaces(g);
    return [
      front,
      `<path d="${faces.top}" fill="#fff" opacity="0.28"/>`,
      `<path d="${faces.right}" fill="#000" opacity="0.2"/>`,
    ].join('');
  }
  return `${front}${pyramidPeopleMarkup(g)}`;
}

function pyramidStageViewBox(i, mode = 'classic') {
  const g = pyramidStageGeom(i, mode);
  const iso = mode === 'layers' ? LAYER_ISO : { dx: 0, dy: 0 };
  const pad = mode === 'layers' ? 8 : g.tabR + 8;
  const left = Math.min(g.leftTop, g.leftBot) - 8;
  const right = Math.max(g.rightTop, g.rightBot) + iso.dx + 8;
  const top = g.yTop + iso.dy - (g.i > 0 && mode !== 'layers' ? pad : 8);
  const bot = g.yBot + 8;
  return { x: left, y: top, w: right - left, h: bot - top };
}

function pyramidStagePlacement(gx, gy, gw, gh, i, mode = 'classic') {
  const sx = gw / PYRAMID_GEOM.viewW;
  const sy = gh / PYRAMID_GEOM.viewH;
  const v = pyramidStageViewBox(i, mode);
  return {
    x: Math.round(gx + v.x * sx),
    y: Math.round(gy + v.y * sy),
    width: Math.round(v.w * sx),
    height: Math.round(v.h * sy),
  };
}

function pyramidStageInlineSvg(i, mode = 'classic') {
  const v = pyramidStageViewBox(i, mode);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${v.x} ${v.y} ${v.w} ${v.h}" width="100%" height="100%" preserveAspectRatio="none">${pyramidStageInnerMarkup(i, mode)}</svg>`;
}

function pyramidGraphicBox(canvasW, canvasH, mode = 'classic') {
  const roomy = mode === 'layers' || mode === 'inverted';
  const headingY = 64;
  const headingH = 96;
  const gap = roomy ? 28 : 16;
  const y = headingY + headingH + gap;
  const h = canvasH - y - 40;
  const graphicW = Math.round(Math.min(920, canvasW * 0.5));
  const graphicX = 48;
  const legendX = graphicX + graphicW + 28;
  const legendW = Math.max(320, canvasW - legendX - 56);
  return { headingY, headingH, graphicX, graphicY: y, graphicW, graphicH: h, legendX, legendW, canvasW };
}

function pyramidLegendPlacements(frame, mode = 'classic') {
  const { graphicX, graphicY, graphicW, graphicH, legendX, legendW } = frame;
  const sx = graphicW / PYRAMID_GEOM.viewW;
  const sy = graphicH / PYRAMID_GEOM.viewH;
  const badgeW = 128;
  const badgeH = 108;
  const layers = mode === 'layers';
  const titleH = 52;
  return [0, 1, 2, 3, 4].map((i) => {
    const g = pyramidStageGeom(i, mode);
    const midY = graphicY + ((g.yTop + g.yBot) / 2) * sy;
    const rowH = Math.round(g.bandH * sy);
    const span = (g.wTop + g.wBot) || 1;
    const fromTop = (g.bandH * (2 * g.wBot + g.wTop)) / (3 * span);
    const t = fromTop / (g.bandH || 1);
    const wAt = g.wTop + (g.wBot - g.wTop) * t;
    const numH = layers ? Math.max(40, Math.round(g.bandH * sy * 0.42)) : 40;
    const numW = layers
      ? Math.max(72, Math.round(Math.min(Math.max(wAt, 80) * sx * 0.62, 180)))
      : Math.round(badgeW * 0.4);
    const numX = layers
      ? Math.round(graphicX + g.cx * sx - numW / 2)
      : Math.round(legendX + 4);
    const numY = layers
      ? Math.round(graphicY + (g.yTop + fromTop) * sy - numH / 2)
      : Math.round(midY - numH / 2);
    const textX = layers ? legendX : legendX + badgeW + 18;
    const textW = layers ? legendW : legendW - badgeW - 18;
    return {
      badge: {
        x: Math.round(legendX),
        y: Math.round(midY - badgeH / 2),
        width: badgeW,
        height: badgeH,
      },
      num: {
        x: numX,
        y: numY,
        width: numW,
        height: numH,
      },
      title: {
        x: Math.round(textX),
        y: Math.round(midY - titleH - 4),
        width: Math.round(textW),
        height: titleH,
      },
      body: {
        x: Math.round(textX),
        y: Math.round(midY + 8),
        width: Math.round(textW),
        height: Math.max(40, Math.round(rowH * 0.38)),
      },
    };
  });
}

const PYRAMID_BADGE_CLIP = 'polygon(0% 6%, 92% 50%, 0% 94%)';

module.exports = {
  PYRAMID_N,
  PYRAMID_COLORS,
  PYRAMID_GEOM,
  pyramidModeFromSchema,
  pyramidStageGeom,
  pyramidStagePlacement,
  pyramidStageInlineSvg,
  pyramidGraphicBox,
  pyramidLegendPlacements,
  PYRAMID_BADGE_CLIP,
};
