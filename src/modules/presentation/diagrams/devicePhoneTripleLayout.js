const TRIPLE_COPY = [
  { key: 'L', heading: 'Title 01', body: 'Description 01' },
  { key: 'R', heading: 'Title 02', body: 'Description 02' },
];

const LEGACY_SPLIT = /^BODY$/i;
const TRIPLE_DECO = /^(TRIPLE_BAND)$/i;
const MAIN_HEADING = /^HEADING$/i;

const {
  paintDeviceFrameElement,
  ON_LIGHT_SURFACE_TEXT,
  ON_LIGHT_SURFACE_MUTED,
} = require('./deviceChrome.util');

function isDevicePhoneTripleLayout(layoutId) {
  return /device_phone_triple/i.test(String(layoutId || ''));
}

function phoneBezel(w, h) {
  return Math.max(8, Math.round(Math.min(w, h) * 0.022));
}

function tripleGeom(canvasW, canvasH) {
  const padX = 72;
  const titleY = 18;
  const titleH = 92;
  const textW = 340;
  const gap = 28;
  const clusterLeft = padX + textW + gap;
  const clusterRight = canvasW - padX - textW - gap;
  const clusterW = Math.max(400, clusterRight - clusterLeft);

  const phoneTop = 176;
  const bottomPad = 36;
  const centerH = Math.round(Math.min(canvasH * 0.74, canvasH - phoneTop - bottomPad));
  const centerW = Math.round(centerH * (9 / 19.5));
  const sideH = Math.round(centerH * 0.82);
  const sideW = Math.round(sideH * (9 / 19.5));
  const overlap = Math.round(sideW * 0.2);

  const centerX = Math.round(clusterLeft + (clusterW - centerW) / 2);
  const centerY = phoneTop;
  const sideY = centerY + (centerH - sideH);
  let leftX = centerX - sideW + overlap;
  let rightX = centerX + centerW - overlap;
  if (leftX < clusterLeft) leftX = clusterLeft;
  if (rightX + sideW > clusterRight) rightX = clusterRight - sideW;

  const bandY = Math.round(canvasH * 0.3);
  const bandH = Math.round(canvasH * 0.4);
  const textPadY = 40;
  const headH = 52;
  const bodyH = Math.max(80, bandH - textPadY * 2 - headH - 12);

  return {
    padX,
    titleY,
    titleH,
    textW,
    bandY,
    bandH,
    textY: bandY + textPadY,
    headH,
    bodyH,
    phones: [
      { n: 1, x: leftX, y: sideY, w: sideW, h: sideH, layer: 8 },
      { n: 2, x: centerX, y: centerY, w: centerW, h: centerH, layer: 12 },
      { n: 3, x: rightX, y: sideY, w: sideW, h: sideH, layer: 8 },
    ],
  };
}

function placePhone(el, phone) {
  const bezel = phoneBezel(phone.w, phone.h);
  const sid = String(el.slotId || '').toUpperCase();
  const isImage = /^DEVICE_IMAGE_/.test(sid);
  if (isImage) {
    return {
      ...el,
      layer: phone.layer + 1,
      placement: {
        ...(el.placement || {}),
        x: Math.round(phone.x + bezel),
        y: Math.round(phone.y + bezel),
        width: Math.max(40, Math.round(phone.w - bezel * 2)),
        height: Math.max(40, Math.round(phone.h - bezel * 2)),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...(el.content || {}),
        borderRadius: 28,
        shadow: undefined,
        boxShadow: undefined,
      },
    };
  }
  return {
    ...el,
    layer: phone.layer,
    placement: {
      ...(el.placement || {}),
      x: Math.round(phone.x),
      y: Math.round(phone.y),
      width: Math.round(phone.w),
      height: Math.round(phone.h),
      rotation: 0,
      opacity: 1,
    },
  };
}

function textStyle(isHeading, textColor, muted) {
  return {
    align: 'left',
    verticalAlign: isHeading ? 'flex-end' : 'flex-start',
    fontSize: isHeading ? 28 : 16,
    fontWeight: isHeading ? 800 : 400,
    lineHeight: isHeading ? 1.15 : 1.45,
    color: isHeading ? textColor : muted,
    letterSpacing: isHeading ? '-0.02em' : '0',
    padding: 0,
    wrap: 'pre-wrap',
    clipToSlot: false,
  };
}

function layoutDevicePhoneTripleElements(elements, palette = {}, canvas = {}, newElementId, themeTokens = null) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  // Main title sits on dark deck bg → theme text. Side copy sits on light TRIPLE_BAND → always dark ink.
  const titleColor = (palette && palette.text) || '#1F2937';
  const bandText = ON_LIGHT_SURFACE_TEXT;
  const bandMuted = ON_LIGHT_SURFACE_MUTED;
  const id = (prefix) => (typeof newElementId === 'function' ? newElementId(prefix) : `${prefix}_${Math.random().toString(36).slice(2, 9)}`);
  const g = tripleGeom(canvasW, canvasH);

  const priorHeading = elements.find((el) => MAIN_HEADING.test(String(el.slotId || '')));
  const headingText = String(priorHeading?.content?.text || '').trim() || 'Describe this mockup';

  const stripped = elements.filter((el) => {
    const sid = String(el.slotId || '');
    return !LEGACY_SPLIT.test(sid) && !TRIPLE_DECO.test(sid) && !MAIN_HEADING.test(sid);
  });

  const next = stripped.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();
    const role = String(el.role || '');
    const phoneN = sid.match(/^(?:PHONE_FRAME_|DEVICE_IMAGE_)(\d)$/);
    if (phoneN || role === 'device_frame') {
      const n = phoneN ? Number(phoneN[1]) : /_3$/.test(sid) ? 3 : /_2$/.test(sid) ? 2 : /_1$/.test(sid) ? 1 : 0;
      const phone = g.phones.find((p) => p.n === n);
      if (phone) {
        const placed = placePhone(el, phone);
        return role === 'device_frame' || /FRAME/.test(sid)
          ? paintDeviceFrameElement(placed, themeTokens)
          : placed;
      }
    }
    const copyM = sid.match(/^((?:HEADING|BODY))_([LR])$/);
    if (copyM) {
      const kind = copyM[1];
      const side = copyM[2];
      const isHeading = kind === 'HEADING';
      const x = side === 'L' ? g.padX : canvasW - g.padX - g.textW;
      return {
        ...el,
        layer: 14,
        placement: {
          ...(el.placement || {}),
          x: Math.round(x),
          y: Math.round(isHeading ? g.textY : g.textY + g.headH + 10),
          width: Math.round(g.textW),
          height: isHeading ? g.headH : g.bodyH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...(el.content || {}),
          ...textStyle(isHeading, bandText, bandMuted),
          colorRole: isHeading ? 'text' : 'muted',
        },
      };
    }
    return el;
  });

  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()));
  const extras = [];
  extras.push({
    id: id('txt'),
    type: 'text',
    role: 'heading',
    slotId: 'HEADING',
    layer: 20,
    placement: { x: g.padX, y: g.titleY, width: canvasW - g.padX * 2, height: g.titleH, rotation: 0, opacity: 1 },
    content: {
      text: headingText,
      align: 'center',
      verticalAlign: 'flex-start',
      fontSize: 32,
      fontWeight: 800,
      lineHeight: 1.4,
      color: titleColor,
      letterSpacing: '0',
      padding: 12,
      paddingX: 12,
      clipToSlot: false,
    },
  });
  for (const copy of TRIPLE_COPY) {
    const headId = `HEADING_${copy.key}`;
    const bodyId = `BODY_${copy.key}`;
    const x = copy.key === 'L' ? g.padX : canvasW - g.padX - g.textW;
    if (!have.has(headId)) {
      extras.push({
        id: id('txt'),
        type: 'text',
        role: 'heading',
        slotId: headId,
        layer: 14,
        placement: { x: Math.round(x), y: Math.round(g.textY), width: Math.round(g.textW), height: g.headH, rotation: 0, opacity: 1 },
        content: { text: copy.heading, ...textStyle(true, bandText, bandMuted), colorRole: 'text' },
      });
    }
    if (!have.has(bodyId)) {
      extras.push({
        id: id('txt'),
        type: 'text',
        role: 'body',
        slotId: bodyId,
        layer: 14,
        placement: { x: Math.round(x), y: Math.round(g.textY + g.headH + 10), width: Math.round(g.textW), height: g.bodyH, rotation: 0, opacity: 1 },
        content: { text: copy.body, ...textStyle(false, bandText, bandMuted), colorRole: 'muted' },
      });
    }
  }

  const band = {
    id: id('shp'),
    type: 'shape',
    role: 'decoration',
    slotId: 'TRIPLE_BAND',
    layer: 2,
    placement: { x: 0, y: g.bandY, width: canvasW, height: g.bandH, rotation: 0, opacity: 1 },
    content: { shape: 'rect', fill: '#e8eaed', borderRadius: 0, layoutSurface: true },
  };

  return [band, ...next, ...extras];
}

function layoutDevicePhoneTriple(doc, layoutSchema, themeTokens, canvas = {}, newElementId) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = { width: canvas.width || doc.canvas?.width || 1920, height: canvas.height || doc.canvas?.height || 1080 };
  return {
    ...doc,
    elements: layoutDevicePhoneTripleElements(doc.elements || [], palette, size, newElementId, themeTokens),
  };
}

module.exports = {
  isDevicePhoneTripleLayout,
  layoutDevicePhoneTriple,
  TRIPLE_COPY,
};
