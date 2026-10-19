function isDeviceTabletSplitLayout(layoutId) {
  return /device_tablet_split/i.test(String(layoutId || ''));
}

function splitGeom() {
  const padX = 96;
  const copyW = 700;
  const headingY = 300;
  const headingH = 148;
  const tabH = 740;
  const tabW = Math.round(tabH * (3 / 4));
  return {
    padX,
    copyW,
    headingY,
    headingH,
    bodyY: headingY + headingH + 48,
    bodyH: 320,
    tablet: { x: 980, y: 170, w: tabW, h: tabH, layer: 6 },
  };
}

function tabletScreenInset(box) {
  const padX = box.w * 0.07;
  const padY = box.h * 0.055;
  return {
    x: Math.round(box.x + padX),
    y: Math.round(box.y + padY),
    width: Math.max(40, Math.round(box.w - padX * 2)),
    height: Math.max(40, Math.round(box.h - padY * 2)),
  };
}

function layoutDeviceTabletSplitElements(elements, palette = {}) {
  if (!Array.isArray(elements)) return elements;
  const textColor = (palette && palette.text) || '#1F2937';
  const muted = (palette && palette.muted) || '#6B7280';
  const g = splitGeom();

  return elements.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();

    if (sid === 'TABLET_FRAME' || (sid === 'DEVICE_FRAME' && /tablet/i.test(String(el.content?.deviceFrame || '')))) {
      return {
        ...el,
        layer: g.tablet.layer,
        placement: {
          ...(el.placement || {}),
          x: g.tablet.x,
          y: g.tablet.y,
          width: g.tablet.w,
          height: g.tablet.h,
          rotation: 0,
          opacity: 1,
        },
      };
    }

    if (sid === 'DEVICE_IMAGE' || sid === 'TABLET_IMAGE') {
      const inset = tabletScreenInset(g.tablet);
      return {
        ...el,
        layer: g.tablet.layer + 1,
        placement: {
          ...(el.placement || {}),
          x: inset.x,
          y: inset.y,
          width: inset.width,
          height: inset.height,
          rotation: 0,
          opacity: 1,
        },
        content: {
          ...(el.content || {}),
          borderRadius: 8,
          shadow: undefined,
          boxShadow: undefined,
        },
      };
    }

    if (sid === 'HEADING') {
      return {
        ...el,
        layer: 16,
        placement: {
          ...(el.placement || {}),
          x: g.padX,
          y: g.headingY,
          width: g.copyW,
          height: g.headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: el.content?.text,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 36,
          fontWeight: 800,
          lineHeight: 1.2,
          color: textColor,
          padding: 8,
          wrap: 'pre-wrap',
          clipToSlot: false,
          slotMaxHeight: g.headingH,
        },
      };
    }

    if (sid === 'BODY') {
      return {
        ...el,
        layer: 16,
        placement: {
          ...(el.placement || {}),
          x: g.padX,
          y: g.bodyY,
          width: g.copyW,
          height: g.bodyH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: el.content?.text,
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 18,
          fontWeight: 400,
          lineHeight: 1.5,
          color: muted,
          padding: 8,
          wrap: 'pre-wrap',
          clipToSlot: false,
        },
      };
    }

    return el;
  });
}

function layoutDeviceTabletSplit(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  void canvas;
  return { ...doc, elements: layoutDeviceTabletSplitElements(doc.elements || [], palette) };
}

module.exports = {
  isDeviceTabletSplitLayout,
  layoutDeviceTabletSplit,
};
