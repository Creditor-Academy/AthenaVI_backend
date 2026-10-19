function isDeviceLaptopSplitLayout(layoutId) {
  return /device_laptop_split/i.test(String(layoutId || ''));
}

function splitGeom() {
  const padX = 96;
  const copyW = 760;
  const headingY = 248;
  const headingH = 148;
  return {
    padX,
    copyW,
    headingY,
    headingH,
    bodyY: headingY + headingH + 48,
    bodyH: 420,
    laptop: { x: 980, y: 200, w: 820, h: 700, layer: 6 },
  };
}

function laptopScreenInset(box) {
  const padX = box.w * 0.05;
  const padTop = box.h * 0.08;
  const padBottom = box.h * 0.16;
  return {
    x: Math.round(box.x + padX),
    y: Math.round(box.y + padTop),
    width: Math.max(40, Math.round(box.w - padX * 2)),
    height: Math.max(40, Math.round(box.h - padTop - padBottom)),
  };
}

function layoutDeviceLaptopSplitElements(elements, palette = {}) {
  if (!Array.isArray(elements)) return elements;
  const textColor = (palette && palette.text) || '#1F2937';
  const muted = (palette && palette.muted) || '#6B7280';
  const g = splitGeom();

  return elements.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();

    if (sid === 'LAPTOP_FRAME' || (sid === 'DEVICE_FRAME' && /laptop/i.test(String(el.content?.deviceFrame || '')))) {
      return {
        ...el,
        layer: g.laptop.layer,
        placement: {
          ...(el.placement || {}),
          x: g.laptop.x,
          y: g.laptop.y,
          width: g.laptop.w,
          height: g.laptop.h,
          rotation: 0,
          opacity: 1,
        },
      };
    }

    if (sid === 'DEVICE_IMAGE' || sid === 'LAPTOP_IMAGE') {
      const inset = laptopScreenInset(g.laptop);
      return {
        ...el,
        layer: g.laptop.layer + 1,
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
          borderRadius: 10,
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

function layoutDeviceLaptopSplit(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = { width: canvas.width || doc.canvas?.width || 1920, height: canvas.height || doc.canvas?.height || 1080 };
  void size;
  return { ...doc, elements: layoutDeviceLaptopSplitElements(doc.elements || [], palette) };
}

module.exports = {
  isDeviceLaptopSplitLayout,
  layoutDeviceLaptopSplit,
};
