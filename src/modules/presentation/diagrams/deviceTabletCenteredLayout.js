function isDeviceTabletCenteredLayout(layoutId) {
  return /device_tablet_centered/i.test(String(layoutId || ''));
}

function centeredGeom(canvasW = 1920, canvasH = 1080) {
  const headingY = 48;
  const headingH = 92;
  const bottomPad = 48;
  const gap = 28;
  const tabH = Math.round(canvasH - headingY - headingH - gap - bottomPad);
  const tabW = Math.round(tabH * (4 / 3));
  return {
    headingY,
    headingH,
    headingX: Math.round(canvasW * 0.12),
    headingW: Math.round(canvasW * 0.76),
    tablet: {
      x: Math.round((canvasW - tabW) / 2),
      y: headingY + headingH + gap,
      w: tabW,
      h: tabH,
      layer: 6,
    },
  };
}

function tabletScreenInset(box) {
  const padX = Math.max(14, Math.round(box.w * 0.028));
  const padY = Math.max(12, Math.round(box.h * 0.032));
  return {
    x: Math.round(box.x + padX),
    y: Math.round(box.y + padY),
    width: Math.max(40, Math.round(box.w - padX * 2)),
    height: Math.max(40, Math.round(box.h - padY * 2)),
  };
}

function layoutDeviceTabletCenteredElements(elements, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const textColor = (palette && palette.text) || '#1F2937';
  const g = centeredGeom(canvas.width || 1920, canvas.height || 1080);

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
        content: {
          ...(el.content || {}),
          deviceFrame: 'tablet_landscape',
          shape: 'device-frame',
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
          fit: 'cover',
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
          x: g.headingX,
          y: g.headingY,
          width: g.headingW,
          height: g.headingH,
          rotation: 0,
          opacity: 1,
        },
        content: {
          text: el.content?.text,
          align: 'center',
          verticalAlign: 'center',
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

    return el;
  });
}

function layoutDeviceTabletCentered(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = { width: canvas.width || doc.canvas?.width || 1920, height: canvas.height || doc.canvas?.height || 1080 };
  return { ...doc, elements: layoutDeviceTabletCenteredElements(doc.elements || [], palette, size) };
}

module.exports = {
  isDeviceTabletCenteredLayout,
  layoutDeviceTabletCentered,
};
