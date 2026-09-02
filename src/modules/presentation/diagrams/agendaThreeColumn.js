/**
 * Agenda three-column coloured layout — reference-style tall columns with
 * top heading, rule line, icons overlapping column heads, white in-column text.
 */

const AGENDA_THREE_COLUMN_GEOM = {
  viewW: 1000,
  viewH: 560,
  headingY: 10,
  headingH: 40,
  lineY: 56,
  linePadX: 48,
  padX: 56,
  colTopY: 108,
  colBottomPad: 20,
  gutter: 18,
  bandH: 48,
  iconR: 52,
  radius: 2,
};

const DEFAULT_COLUMN_PALETTE = [
  { main: '#2EC4C6', band: '#62D5D7', iconKey: 'gear' },
  { main: '#1B4965', band: '#2D5F7F', iconKey: 'clock' },
  { main: '#5C7C9E', band: '#7D96B0', iconKey: 'lightbulb' },
];

function columnRects() {
  const { viewW, padX, gutter, colTopY, viewH, colBottomPad } = AGENDA_THREE_COLUMN_GEOM;
  const colW = (viewW - padX * 2 - gutter * 2) / 3;
  const colH = viewH - colTopY - colBottomPad;
  return [0, 1, 2].map((i) => {
    const x = padX + i * (colW + gutter);
    return {
      x,
      y: colTopY,
      w: colW,
      h: colH,
      cx: x + colW / 2,
    };
  });
}

/** Icon circle centered on the column top edge (half above, half on the block). */
function iconOnColumnTop(col) {
  const { iconR, colTopY } = AGENDA_THREE_COLUMN_GEOM;
  const cy = colTopY;
  return {
    cx: col.cx,
    cy,
    x: col.cx - iconR,
    y: cy - iconR,
    w: iconR * 2,
    h: iconR * 2,
  };
}

function iconPath(key, cx, cy, size) {
  const s = size * 0.34;
  const paths = {
    gear: `M ${cx} ${cy - s * 0.55} l ${s * 0.22} ${s * 0.12} l ${s * 0.12} ${-s * 0.22} l ${s * 0.35} 0 l ${s * 0.12} ${s * 0.22} l ${s * 0.22} ${-s * 0.12} l ${s * 0.22} ${s * 0.12} l ${-s * 0.12} ${s * 0.22} l 0 ${s * 0.35} l ${-s * 0.22} ${s * 0.12} l ${-s * 0.12} ${-s * 0.22} l ${-s * 0.35} 0 l ${-s * 0.12} ${s * 0.22} l ${-s * 0.22} ${-s * 0.12} l ${-s * 0.22} ${s * 0.12} l ${s * 0.12} ${s * 0.22} l 0 ${-s * 0.35} z M ${cx} ${cy} m ${-s * 0.28} 0 a ${s * 0.28} ${s * 0.28} 0 1 0 ${s * 0.56} 0 a ${s * 0.28} ${s * 0.28} 0 1 0 ${-s * 0.56} 0`,
    clock: `M ${cx} ${cy} m ${-s * 0.55} 0 a ${s * 0.55} ${s * 0.55} 0 1 0 ${s * 1.1} 0 a ${s * 0.55} ${s * 0.55} 0 1 0 ${-s * 1.1} 0 M ${cx} ${cy} V ${cy - s * 0.25} M ${cx} ${cy} L ${cx + s * 0.28} ${cy + s * 0.18}`,
    lightbulb: `M ${cx} ${cy - s * 0.72} q ${s * 0.85} ${s * 0.48} ${s * 0.85} ${s * 1.05} q 0 ${s * 0.55} ${-s * 0.45} ${s * 0.85} h ${-s * 0.8} q ${-s * 0.45} ${-s * 0.3} ${-s * 0.45} ${-s * 0.85} q 0 ${-s * 0.57} ${s * 0.85} ${-s * 1.05} M ${cx - s * 0.28} ${cy + s * 0.95} h ${s * 0.56} M ${cx - s * 0.2} ${cy + s * 1.2} h ${s * 0.4}`,
    calendar: `M ${cx - s * 0.55} ${cy - s * 0.25} h ${s * 1.1} v ${s * 0.95} h ${-s * 1.1} z M ${cx - s * 0.35} ${cy - s * 0.55} v ${s * 0.35} M ${cx + s * 0.35} ${cy - s * 0.55} v ${s * 0.35}`,
    chart: `M ${cx - s * 0.5} ${cy + s * 0.55} V ${cy - s * 0.1} M ${cx} ${cy + s * 0.55} V ${cy - s * 0.65} M ${cx + s * 0.5} ${cy + s * 0.55} V ${cy + s * 0.15}`,
    user: `M ${cx} ${cy - s * 0.42} a ${s * 0.38} ${s * 0.38} 0 1 1 0 ${s * 0.76} a ${s * 0.38} ${s * 0.38} 0 1 1 0 ${-s * 0.76} M ${cx - s * 0.62} ${cy + s * 0.82} q ${s * 0.62} ${-s * 0.42} ${s * 1.24} 0`,
  };
  return paths[key] || paths.gear;
}

function agendaThreeColumnGraphicFrame(canvasW, canvasH) {
  const headingY = Math.round(canvasH * 0.034);
  const headingH = Math.round(canvasH * 0.058);
  const graphicY = Math.round(canvasH * 0.102);
  const graphicH = canvasH - graphicY - Math.round(canvasH * 0.022);
  return {
    graphicX: 0,
    graphicY,
    graphicW: canvasW,
    graphicH,
    headingY,
    headingH,
  };
}

function agendaThreeColumnRuleInlineSvg() {
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 4" width="100%" height="100%" preserveAspectRatio="none"><rect x="0" y="1.5" width="1000" height="1.5" fill="currentColor" opacity="0.22"/></svg>';
}

function agendaThreeColumnIconInlineSvg(iconKey = 'gear') {
  const cx = 28;
  const cy = 28;
  const d = iconPath(iconKey, cx, cy, 44);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 56 56" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><circle cx="${cx}" cy="${cy}" r="26" fill="#ffffff"/><path d="${d}" fill="none" stroke="#4B5563" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

function agendaThreeColumnNumberInlineSvg(label = '01') {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 48" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><text x="40" y="36" text-anchor="middle" fill="#ffffff" font-size="28" font-weight="800" font-family="system-ui,sans-serif">${label}</text></svg>`;
}

function plainTextFromContent(content = {}) {
  if (typeof content.text === 'string') return content.text;
  if (Array.isArray(content.runs)) return content.runs.map((r) => r.text || '').join('');
  return '';
}

/** Strip theme roles/runs so canvas renders white on-column text. */
function colouredColumnTextContent(content = {}, opts = {}) {
  const {
    color = '#FFFFFF',
    fontSize = 16,
    fontWeight = 400,
    fontStyle,
    align = 'center',
    verticalAlign = 'flex-start',
  } = opts;
  return {
    text: plainTextFromContent(content),
    color,
    colorRole: null,
    fill: null,
    runs: null,
    fontSize,
    fontWeight,
    fontStyle: fontStyle || undefined,
    align,
    verticalAlign,
    letterSpacing: '0',
    padding: 0,
    paddingX: 0,
    stroke: undefined,
    strokeWidth: 0,
    listType: null,
  };
}

function resolveColumnPalette(colors = {}) {
  const accent = colors.accent || '#6366f1';
  if (colors.useThemeAccent) {
    return [
      { main: accent, band: accent, iconKey: 'gear' },
      { main: accent, band: accent, iconKey: 'clock' },
      { main: accent, band: accent, iconKey: 'lightbulb' },
    ];
  }
  return DEFAULT_COLUMN_PALETTE;
}

function agendaThreeColumnChromeSpecs(colors = {}) {
  const palette = resolveColumnPalette(colors);
  const { bandH, radius, lineY, linePadX, viewW, iconR } = AGENDA_THREE_COLUMN_GEOM;
  const specs = [];
  const cols = columnRects();

  specs.push({
    slotId: 'AGENDA_COL_RULE',
    kind: 'graphic',
    x: linePadX,
    y: lineY,
    w: viewW - linePadX * 2,
    h: 4,
    rule: true,
    layer: 4,
  });

  for (let i = 0; i < 3; i += 1) {
    const col = cols[i];
    const pal = palette[i % palette.length];
    const icon = iconOnColumnTop(col);
    const n = i + 1;

    specs.push({
      slotId: `AGENDA_COL_BLOCK_${n}`,
      kind: 'shape',
      x: col.x,
      y: col.y,
      w: col.w,
      h: col.h,
      borderRadius: radius,
      fill: pal.main,
      layer: 2,
    });
    specs.push({
      slotId: `AGENDA_COL_BAND_${n}`,
      kind: 'shape',
      x: col.x,
      y: col.y,
      w: col.w,
      h: bandH,
      borderRadius: radius,
      fill: pal.band,
      layer: 3,
    });
    specs.push({
      slotId: `AGENDA_COL_ICON_${n}`,
      kind: 'graphic',
      x: icon.x,
      y: icon.y,
      w: icon.w,
      h: icon.h,
      iconKey: pal.iconKey,
      layer: 9,
    });
    specs.push({
      slotId: `AGENDA_COL_NUM_${n}`,
      kind: 'graphic',
      x: col.cx - 44,
      y: col.y + iconR * 0.72,
      w: 88,
      h: 44,
      badge: String(n).padStart(2, '0'),
      layer: 8,
    });
  }
  return specs;
}

function agendaThreeColumnOverlayPlacements(gx, gy, gw, gh) {
  const sx = gw / AGENDA_THREE_COLUMN_GEOM.viewW;
  const sy = gh / AGENDA_THREE_COLUMN_GEOM.viewH;
  const box = (x, y, w, h) => ({
    x: Math.round(gx + x * sx),
    y: Math.round(gy + y * sy),
    width: Math.max(32, Math.round(w * sx)),
    height: Math.max(22, Math.round(h * sy)),
  });

  const overlay = { columns: [] };
  const cols = columnRects();
  const { iconR } = AGENDA_THREE_COLUMN_GEOM;

  for (let i = 0; i < 3; i += 1) {
    const col = cols[i];
    const pad = col.w * 0.05;
    const textW = col.w - pad * 2;
    const textX = col.x + pad;
    const headingY = col.y + iconR + 52;
    overlay.columns.push({
      heading: box(textX, headingY, textW, 48),
      items: [
        box(textX, headingY + 54, textW, 38),
        box(textX, headingY + 94, textW, 38),
        box(textX, headingY + 134, textW, 38),
        box(textX, headingY + 174, textW, 38),
      ],
    });
  }
  return overlay;
}

function buildAgendaThreeColumnPreviewSvg(colors = {}) {
  const specs = agendaThreeColumnChromeSpecs(colors);
  const parts = [];
  const { viewW, viewH, lineY } = AGENDA_THREE_COLUMN_GEOM;

  parts.push(`<rect x="0" y="${lineY}" width="${viewW}" height="1.5" fill="#94a3b8" opacity="0.35"/>`);

  for (const spec of specs) {
    if (spec.rule) continue;
    if (spec.kind === 'shape') {
      parts.push(`<rect x="${spec.x}" y="${spec.y}" width="${spec.w}" height="${spec.h}" rx="${spec.borderRadius || 0}" fill="${spec.fill}"/>`);
    } else if (spec.badge) {
      parts.push(`<text x="${spec.x + spec.w / 2}" y="${spec.y + spec.h * 0.78}" text-anchor="middle" fill="#fff" font-size="26" font-weight="800" font-family="system-ui,sans-serif">${spec.badge}</text>`);
    } else if (spec.iconKey) {
      const cx = spec.x + spec.w / 2;
      const cy = spec.y + spec.h / 2;
      const r = spec.w / 2;
      parts.push(`<circle cx="${cx}" cy="${cy}" r="${r}" fill="#ffffff"/>`);
      parts.push(`<path d="${iconPath(spec.iconKey, cx, cy, r * 2)}" fill="none" stroke="#4B5563" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>`);
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW} ${viewH}">${parts.join('')}</svg>`;
}

function agendaThreeColumnPreviewSvg(colors = {}) {
  return buildAgendaThreeColumnPreviewSvg(colors).replace(/<svg\b([^>]*)>/i, (match, attrs) => {
    let next = attrs;
    if (!/\bwidth\s*=/i.test(next)) next += ' width="100%"';
    if (!/\bheight\s*=/i.test(next)) next += ' height="100%"';
    if (!/\bpreserveAspectRatio\s*=/i.test(next)) next += ' preserveAspectRatio="xMidYMid meet"';
    return `<svg${next}>`;
  });
}

function specToThreeColumnContent(spec) {
  if (spec.rule) {
    return { svg: agendaThreeColumnRuleInlineSvg(), colorMode: 'recolorable', fill: '#94a3b8' };
  }
  if (spec.badge) {
    return { svg: agendaThreeColumnNumberInlineSvg(spec.badge), colorMode: 'fixed', fill: '#ffffff' };
  }
  if (spec.iconKey) {
    return { svg: agendaThreeColumnIconInlineSvg(spec.iconKey), colorMode: 'fixed', fill: '#ffffff' };
  }
  return { svg: agendaThreeColumnIconInlineSvg('gear'), colorMode: 'fixed', fill: '#ffffff' };
}

function isAgendaThreeColumnColouredLayout(layoutId, family, variant) {
  const id = String(layoutId || '').toLowerCase();
  if (id === 'agenda_three_icons_v1') return true;
  return family === 'three_col' && variant === 'coloured';
}

function isAgendaThreeColumnTextSlot(slotId) {
  const sid = String(slotId || '').toUpperCase();
  return sid === 'HEADING' || /^AGENDA_COL_\d+_(HEADING|ITEM_\d+)$/.test(sid);
}

module.exports = {
  AGENDA_THREE_COLUMN_GEOM,
  DEFAULT_COLUMN_PALETTE,
  agendaThreeColumnGraphicFrame,
  agendaThreeColumnRuleInlineSvg,
  agendaThreeColumnIconInlineSvg,
  agendaThreeColumnNumberInlineSvg,
  colouredColumnTextContent,
  agendaThreeColumnChromeSpecs,
  agendaThreeColumnOverlayPlacements,
  agendaThreeColumnPreviewSvg,
  specToThreeColumnContent,
  isAgendaThreeColumnColouredLayout,
  isAgendaThreeColumnTextSlot,
};
