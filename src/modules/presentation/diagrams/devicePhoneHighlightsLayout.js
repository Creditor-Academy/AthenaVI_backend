const HIGHLIGHT_FEATURES = [
  { key: 'L1', side: 'L', heading: 'Title 01', body: 'Description 01' },
  { key: 'L2', side: 'L', heading: 'Title 02', body: 'Description 02' },
  { key: 'L3', side: 'L', heading: 'Title 03', body: 'Description 03' },
  { key: 'R1', side: 'R', heading: 'Title 04', body: 'Description 04' },
  { key: 'R2', side: 'R', heading: 'Title 05', body: 'Description 05' },
  { key: 'R3', side: 'R', heading: 'Title 06', body: 'Description 06' },
];

const HIGHLIGHT_ICON_COLORS = ['#22c55e', '#1e3a8a', '#ef4444', '#38bdf8', '#f97316', '#64748b'];

const ICON_SVGS = [
  '<svg viewBox="0 0 24 24" fill="none"><rect x="5" y="4.5" width="14" height="4" rx="1" stroke="#fff" stroke-width="1.7"/><rect x="5" y="10" width="14" height="4" rx="1" stroke="#fff" stroke-width="1.7"/><rect x="5" y="15.5" width="14" height="4" rx="1" stroke="#fff" stroke-width="1.7"/></svg>',
  '<svg viewBox="0 0 24 24" fill="none"><ellipse cx="12" cy="7" rx="6.5" ry="2.4" stroke="#fff" stroke-width="1.7"/><path d="M5.5 7v10c0 1.3 2.9 2.4 6.5 2.4s6.5-1.1 6.5-2.4V7" stroke="#fff" stroke-width="1.7"/><path d="M5.5 12c0 1.3 2.9 2.4 6.5 2.4s6.5-1.1 6.5-2.4" stroke="#fff" stroke-width="1.7"/></svg>',
  '<svg viewBox="0 0 24 24" fill="none"><rect x="4.5" y="7" width="13" height="10" rx="1.4" stroke="#fff" stroke-width="1.7"/><path d="M7.5 7V6.2A1.7 1.7 0 0 1 9.2 4.5h8.3A1.7 1.7 0 0 1 19.2 6.2V14" stroke="#fff" stroke-width="1.7"/></svg>',
  '<svg viewBox="0 0 24 24" fill="none"><rect x="6" y="8.5" width="12" height="9" rx="1.4" stroke="#fff" stroke-width="1.7"/><path d="M8 8.5V7.2A4 4 0 0 1 12 4.5 4 4 0 0 1 16 7.2v1.3" stroke="#fff" stroke-width="1.7"/></svg>',
  '<svg viewBox="0 0 24 24" fill="none"><path d="M8 15.5 5.5 18l2.5 2.5" stroke="#fff" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.5 18H14a4.5 4.5 0 0 0 0-9H10" stroke="#fff" stroke-width="1.7" stroke-linecap="round"/><circle cx="16.5" cy="7" r="2.2" stroke="#fff" stroke-width="1.7"/></svg>',
  '<svg viewBox="0 0 24 24" fill="none"><path d="M14.5 5.5 18.5 9.5" stroke="#fff" stroke-width="1.7" stroke-linecap="round"/><path d="M7 19.5 16.8 9.7a1.4 1.4 0 0 0 0-2L14.3 5.2a1.4 1.4 0 0 0-2 0L4.5 13v6.5H11z" stroke="#fff" stroke-width="1.7" stroke-linejoin="round"/></svg>',
];

function highlightIconSvg(index) {
  return ICON_SVGS[index % ICON_SVGS.length];
}

function isDevicePhoneHighlightsLayout(layoutId) {
  return /device_phone_highlights/i.test(String(layoutId || ''));
}

const HIGHLIGHT_DECO = /^(FEATURE_[LR]\d+_ICON|HIGHLIGHT_(ICON|CONN|LINE)_|CALLOUT_)/i;

function paletteColor(palette, role, fallback) {
  if (!palette || typeof palette !== 'object') return fallback;
  return palette[role] || fallback;
}

function layoutDevicePhoneHighlightsElements(elements, palette, canvas, newElementId) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const textColor = paletteColor(palette, 'text', '#1F2937');
  const muted = paletteColor(palette, 'muted', '#6B7280');
  const id = (prefix) => (typeof newElementId === 'function' ? newElementId(prefix) : `${prefix}_${Math.random().toString(36).slice(2, 9)}`);

  const titleY = 48;
  const titleH = 96;
  const phoneH = Math.round(canvasH * 0.58);
  const phoneW = Math.round(phoneH * (9 / 19.5));
  const phoneX = Math.round((canvasW - phoneW) / 2);
  const phoneY = Math.round(titleY + titleH + (canvasH - titleY - titleH - phoneH) / 2);
  const bezel = Math.max(8, Math.round(Math.min(phoneW, phoneH) * 0.022));
  const iconD = 76;
  const gapIconPhone = 80;
  const padX = 72;
  const featTitleH = 40;
  const bodyH = 96;
  const rowYs = [0.18, 0.5, 0.82].map((t) => Math.round(phoneY + phoneH * t));

  const prevBySlot = new Map(
    elements
      .filter((el) => /^HIGHLIGHT_(ICON|CONN)_/i.test(String(el.slotId || '')))
      .map((el) => [String(el.slotId || '').toUpperCase(), el])
  );
  const stripped = elements.filter((el) => !HIGHLIGHT_DECO.test(String(el.slotId || '')));

  const next = stripped.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();
    const role = String(el.role || '');
    if (sid === 'HEADING') {
      return {
        ...el,
        layer: 14,
        placement: { ...(el.placement || {}), x: padX, y: titleY, width: canvasW - padX * 2, height: titleH, rotation: 0, opacity: 1 },
        content: {
          ...(el.content || {}),
          align: 'center',
          verticalAlign: 'center',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          letterSpacing: '-0.02em',
          padding: 8,
          clipToSlot: false,
        },
      };
    }
    if (role === 'device_frame' || /FRAME$/i.test(sid)) {
      return {
        ...el,
        placement: { ...(el.placement || {}), x: phoneX, y: phoneY, width: phoneW, height: phoneH, rotation: 0, opacity: 1 },
      };
    }
    if (sid === 'DEVICE_IMAGE') {
      return {
        ...el,
        placement: {
          ...(el.placement || {}),
          x: phoneX + bezel,
          y: phoneY + bezel,
          width: Math.max(40, phoneW - bezel * 2),
          height: Math.max(40, phoneH - bezel * 2),
          rotation: 0,
          opacity: 1,
        },
        content: { ...(el.content || {}), borderRadius: 28, shadow: undefined, boxShadow: undefined },
      };
    }
    const featM = sid.match(/^FEATURE_([LR])(\d+)_(HEADING|BODY)$/);
    if (!featM) return el;
    const side = featM[1];
    const idx = Number(featM[2]) - 1;
    const kind = featM[3];
    const cy = rowYs[Math.max(0, Math.min(2, idx))];
    const iconX = side === 'L' ? phoneX - gapIconPhone - iconD : phoneX + phoneW + gapIconPhone;
    const textW = side === 'L' ? iconX - 16 - padX : canvasW - padX - (iconX + iconD + 16);
    const textX = side === 'L' ? padX : iconX + iconD + 16;
    const isHeading = kind === 'HEADING';
    return {
      ...el,
      layer: 12,
      placement: {
        ...(el.placement || {}),
        x: Math.round(textX),
        y: Math.round(isHeading ? cy - featTitleH - 6 : cy + 4),
        width: Math.round(textW),
        height: isHeading ? featTitleH : bodyH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...(el.content || {}),
        align: side === 'L' ? 'right' : 'left',
        verticalAlign: isHeading ? 'flex-end' : 'flex-start',
        fontSize: isHeading ? 22 : 16,
        fontWeight: isHeading ? 700 : 400,
        lineHeight: isHeading ? 1.2 : 1.45,
        color: isHeading ? textColor : muted,
        letterSpacing: '0',
        padding: 0,
        paddingX: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
      },
    };
  });

  const extras = [];
  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()));
  if (!have.has('HEADING')) {
    extras.push({
      id: id('txt'),
      type: 'text',
      role: 'heading',
      slotId: 'HEADING',
      layer: 14,
      placement: { x: padX, y: titleY, width: canvasW - padX * 2, height: titleH, rotation: 0, opacity: 1 },
      content: { text: 'Highlights that matter', align: 'center', verticalAlign: 'center', fontSize: 36, fontWeight: 800, color: textColor, clipToSlot: false },
    });
  }
  for (const feat of HIGHLIGHT_FEATURES) {
    const headId = `FEATURE_${feat.key}_HEADING`;
    const bodyId = `FEATURE_${feat.key}_BODY`;
    const side = feat.side;
    const idx = Number(feat.key.slice(1)) - 1;
    const cy = rowYs[idx];
    const iconX = side === 'L' ? phoneX - gapIconPhone - iconD : phoneX + phoneW + gapIconPhone;
    const textW = side === 'L' ? iconX - 16 - padX : canvasW - padX - (iconX + iconD + 16);
    const textX = side === 'L' ? padX : iconX + iconD + 16;
    if (!have.has(headId)) {
      extras.push({
        id: id('txt'),
        type: 'text',
        role: 'heading',
        slotId: headId,
        layer: 12,
        placement: { x: Math.round(textX), y: Math.round(cy - featTitleH - 6), width: Math.round(textW), height: featTitleH, rotation: 0, opacity: 1 },
        content: { text: feat.heading, align: side === 'L' ? 'right' : 'left', verticalAlign: 'flex-end', fontSize: 22, fontWeight: 700, color: textColor, clipToSlot: false },
      });
    }
    if (!have.has(bodyId)) {
      extras.push({
        id: id('txt'),
        type: 'text',
        role: 'body',
        slotId: bodyId,
        layer: 12,
        placement: { x: Math.round(textX), y: Math.round(cy + 4), width: Math.round(textW), height: bodyH, rotation: 0, opacity: 1 },
        content: { text: feat.body, align: side === 'L' ? 'right' : 'left', verticalAlign: 'flex-start', fontSize: 16, fontWeight: 400, color: muted, wrap: 'pre-wrap', clipToSlot: false },
      });
    }
  }

  const chrome = [];
  HIGHLIGHT_FEATURES.forEach((feat, i) => {
    const side = feat.side;
    const idx = Number(feat.key.slice(1)) - 1;
    const cy = rowYs[idx];
    const iconX = side === 'L' ? phoneX - gapIconPhone - iconD : phoneX + phoneW + gapIconPhone;
    const iconY = cy - iconD / 2;
    const iconId = `HIGHLIGHT_ICON_${i + 1}`;
    const connId = `HIGHLIGHT_CONN_${i + 1}`;
    const prevI = prevBySlot.get(iconId);
    const prevC = prevBySlot.get(connId);
    const fill = prevI?.content?.fill || HIGHLIGHT_ICON_COLORS[i];
    const mark = Math.round(iconD * 0.52);
    const lineX = side === 'L' ? iconX + iconD : iconX - gapIconPhone;
    const lineW = gapIconPhone;
    chrome.push({
      id: prevC?.id || id('shp'),
      type: 'shape',
      role: 'decoration',
      slotId: connId,
      layer: 6,
      placement: { x: Math.round(lineX), y: Math.round(cy - 1), width: Math.max(8, Math.round(lineW)), height: 2, rotation: 0, opacity: 1 },
      content: { shape: 'rounded-rect', fill: '#cbd5e1', borderRadius: 99, layoutSurface: true },
    });
    chrome.push({
      id: prevI?.id || id('shp'),
      type: 'shape',
      role: 'decoration',
      slotId: iconId,
      layer: 8,
      placement: { x: Math.round(iconX), y: Math.round(iconY), width: iconD, height: iconD, rotation: 0, opacity: 1 },
      content: { shape: 'ellipse', fill, layoutSurface: true },
    });
    chrome.push({
      id: id('shp'),
      type: 'graphic',
      role: 'decoration',
      slotId: `${iconId}_MARK`,
      layer: 9,
      placement: {
        x: Math.round(iconX + (iconD - mark) / 2),
        y: Math.round(iconY + (iconD - mark) / 2),
        width: mark,
        height: mark,
        rotation: 0,
        opacity: 1,
      },
      content: { svg: highlightIconSvg(i), colorMode: 'original', alt: feat.heading },
    });
  });

  return [...chrome, ...next, ...extras];
}

function layoutDevicePhoneHighlights(doc, layoutSchema, themeTokens, canvas = {}, newElementId) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = { width: canvas.width || doc.canvas?.width || 1920, height: canvas.height || doc.canvas?.height || 1080 };
  return { ...doc, elements: layoutDevicePhoneHighlightsElements(doc.elements || [], palette, size, newElementId) };
}

module.exports = {
  isDevicePhoneHighlightsLayout,
  layoutDevicePhoneHighlights,
  HIGHLIGHT_FEATURES,
};
