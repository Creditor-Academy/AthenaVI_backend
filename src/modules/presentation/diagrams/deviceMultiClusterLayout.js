function isDeviceMultiClusterLayout(layoutId) {
  return /device_multi_cluster/i.test(String(layoutId || ''));
}

const CLUSTER_DECO = /^(CLUSTER_GLOW|CLUSTER_RULE|HEADING_2)$/i;

function insetForKind(box, kind) {
  const x = box.x;
  const y = box.y;
  const w = box.w;
  const h = box.h;
  if (kind === 'laptop') {
    const padX = w * 0.05;
    const padTop = h * 0.08;
    const padBottom = h * 0.16;
    return {
      x: Math.round(x + padX),
      y: Math.round(y + padTop),
      width: Math.max(40, Math.round(w - padX * 2)),
      height: Math.max(40, Math.round(h - padTop - padBottom)),
    };
  }
  if (kind === 'tablet') {
    const padX = w * 0.08;
    const padY = h * 0.06;
    return {
      x: Math.round(x + padX),
      y: Math.round(y + padY),
      width: Math.max(40, Math.round(w - padX * 2)),
      height: Math.max(40, Math.round(h - padY * 2)),
    };
  }
  if (kind === 'watch') {
    const caseW = w * 0.76;
    const caseH = h * 0.54;
    return {
      x: Math.round(x + (w - caseW) / 2),
      y: Math.round(y + (h - caseH) / 2),
      width: Math.max(24, Math.round(caseW)),
      height: Math.max(24, Math.round(caseH)),
    };
  }
  const bezel = Math.max(8, Math.round(Math.min(w, h) * 0.022));
  return {
    x: Math.round(x + bezel),
    y: Math.round(y + bezel),
    width: Math.max(40, Math.round(w - bezel * 2)),
    height: Math.max(40, Math.round(h - bezel * 2)),
  };
}

function clusterGeom() {
  const padX = 96;
  const copyW = 540;
  const headingY = 200;
  const headingH = 210;
  const ruleY = 428;
  return {
    padX,
    copyW,
    headingY,
    headingH,
    ruleY,
    subY: 456,
    subH: 56,
    bodyY: 528,
    bodyH: 220,
    glow: { x: 1080, y: 200, w: 620, h: 620 },
    devices: [
      { key: 'TABLET', kind: 'tablet', x: 1180, y: 130, w: 300, h: 620, layer: 6 },
      { key: 'LAPTOP', kind: 'laptop', x: 880, y: 520, w: 470, h: 280, layer: 10 },
      { key: 'PHONE', kind: 'phone', x: 1400, y: 300, w: 168, h: 390, layer: 12 },
      { key: 'WATCH', kind: 'watch', x: 1590, y: 470, w: 155, h: 250, layer: 14 },
    ],
  };
}

function matchDevice(sid) {
  if (/^TABLET_(FRAME|IMAGE)$/i.test(sid)) return 'TABLET';
  if (/^LAPTOP_(FRAME|IMAGE)$/i.test(sid)) return 'LAPTOP';
  if (/^PHONE_(FRAME|IMAGE)$/i.test(sid)) return 'PHONE';
  if (/^WATCH_(FRAME|IMAGE)$/i.test(sid)) return 'WATCH';
  return null;
}

function placeDevice(el, box, kind) {
  const sid = String(el.slotId || '').toUpperCase();
  const isImage = /_IMAGE$/.test(sid);
  if (isImage) {
    const inset = insetForKind(box, kind);
    return {
      ...el,
      layer: box.layer + 1,
      placement: { ...(el.placement || {}), x: inset.x, y: inset.y, width: inset.width, height: inset.height, rotation: 0, opacity: 1 },
      content: {
        ...(el.content || {}),
        borderRadius: kind === 'phone' ? 28 : kind === 'watch' ? 18 : 10,
        shadow: undefined,
        boxShadow: undefined,
      },
    };
  }
  return {
    ...el,
    layer: box.layer,
    placement: {
      ...(el.placement || {}),
      x: Math.round(box.x),
      y: Math.round(box.y),
      width: Math.round(box.w),
      height: Math.round(box.h),
      rotation: 0,
      opacity: 1,
    },
  };
}

function headingLines(raw) {
  const t = String(raw || '').trim();
  if (!t || /describe this mockup/i.test(t)) return { line1: 'Multi-device', line2: 'experience' };
  const parts = t.split(/\n+/).map((s) => s.trim()).filter(Boolean);
  if (parts.length >= 2) return { line1: parts[0], line2: parts.slice(1).join(' ') };
  const m = t.match(/^(multi[-\s]?device)\s+(experience.*)$/i);
  if (m) return { line1: 'Multi-device', line2: m[2] || 'experience' };
  if (/^experience$/i.test(t)) return { line1: 'Multi-device', line2: 'experience' };
  return { line1: t, line2: 'experience' };
}

function headingContent(line1, line2, textColor, accent) {
  const text = `${line1}\n${line2}`;
  return {
    text,
    runs: [
      { text: line1, color: textColor, fontWeight: 800 },
      { text: `\n${line2}`, color: accent, fontWeight: 800 },
    ],
    align: 'left',
    verticalAlign: 'flex-start',
    fontSize: 34,
    fontWeight: 800,
    lineHeight: 1.25,
    color: textColor,
    padding: 4,
    wrap: 'pre-wrap',
    clipToSlot: false,
    slotMaxHeight: 210,
  };
}

function layoutDeviceMultiClusterElements(elements, palette = {}, canvas = {}, newElementId) {
  if (!Array.isArray(elements)) return elements;
  const textColor = (palette && palette.text) || '#1F2937';
  const accent = (palette && palette.primary) || '#2563eb';
  const muted = (palette && palette.muted) || '#6B7280';
  const id = (prefix) => (typeof newElementId === 'function' ? newElementId(prefix) : `${prefix}_${Math.random().toString(36).slice(2, 9)}`);
  const g = clusterGeom();
  const byKey = Object.fromEntries(g.devices.map((d) => [d.key, d]));
  const stripped = elements.filter((el) => !CLUSTER_DECO.test(String(el.slotId || '')));

  const next = stripped.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();
    const key = matchDevice(sid);
    if (key && byKey[key]) return placeDevice(el, byKey[key], byKey[key].kind);
    if (sid === 'HEADING') {
      const lines = headingLines(el.content?.text);
      return {
        ...el,
        layer: 16,
        placement: { ...(el.placement || {}), x: g.padX, y: g.headingY, width: g.copyW, height: g.headingH, rotation: 0, opacity: 1 },
        content: headingContent(lines.line1, lines.line2, textColor, accent),
      };
    }
    if (sid === 'SUBHEADING') {
      return {
        ...el,
        layer: 16,
        placement: { ...(el.placement || {}), x: g.padX, y: g.subY, width: g.copyW, height: g.subH, rotation: 0, opacity: 1 },
        content: {
          text: el.content?.text || 'Title 01',
          align: 'left',
          verticalAlign: 'center',
          fontSize: 18,
          fontWeight: 500,
          color: muted,
          padding: 4,
          wrap: 'pre-wrap',
          clipToSlot: false,
          slotMaxHeight: 56,
        },
      };
    }
    if (sid === 'BODY') {
      return {
        ...el,
        layer: 16,
        placement: { ...(el.placement || {}), x: g.padX, y: g.bodyY, width: g.copyW, height: g.bodyH, rotation: 0, opacity: 1 },
        content: {
          text: el.content?.text || 'Description 01',
          align: 'left',
          verticalAlign: 'flex-start',
          fontSize: 16,
          fontWeight: 400,
          lineHeight: 1.5,
          color: muted,
          padding: 4,
          wrap: 'pre-wrap',
          clipToSlot: false,
        },
      };
    }
    return el;
  });

  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()));
  const extras = [];
  if (!have.has('HEADING')) {
    extras.push({
      id: id('txt'),
      type: 'text',
      role: 'heading',
      slotId: 'HEADING',
      layer: 16,
      placement: { x: g.padX, y: g.headingY, width: g.copyW, height: g.headingH, rotation: 0, opacity: 1 },
      content: headingContent('Multi-device', 'experience', textColor, accent),
    });
  }
  if (!have.has('SUBHEADING')) {
    extras.push({
      id: id('txt'),
      type: 'text',
      role: 'subheading',
      slotId: 'SUBHEADING',
      layer: 16,
      placement: { x: g.padX, y: g.subY, width: g.copyW, height: g.subH, rotation: 0, opacity: 1 },
      content: { text: 'Title 01', align: 'left', verticalAlign: 'center', fontSize: 18, fontWeight: 500, color: muted, padding: 4, clipToSlot: false, slotMaxHeight: 56 },
    });
  }
  if (!have.has('BODY')) {
    extras.push({
      id: id('txt'),
      type: 'text',
      role: 'body',
      slotId: 'BODY',
      layer: 16,
      placement: { x: g.padX, y: g.bodyY, width: g.copyW, height: g.bodyH, rotation: 0, opacity: 1 },
      content: { text: 'Description 01', align: 'left', fontSize: 16, color: muted, wrap: 'pre-wrap', clipToSlot: false },
    });
  }

  const chrome = [
    {
      id: id('shp'),
      type: 'shape',
      role: 'decoration',
      slotId: 'CLUSTER_GLOW',
      layer: 2,
      placement: { x: g.glow.x, y: g.glow.y, width: g.glow.w, height: g.glow.h, rotation: 0, opacity: 1 },
      content: { shape: 'ellipse', fill: '#dce8f4', layoutSurface: true },
    },
    {
      id: id('shp'),
      type: 'shape',
      role: 'decoration',
      slotId: 'CLUSTER_RULE',
      layer: 12,
      placement: { x: g.padX, y: g.ruleY, width: 72, height: 3, rotation: 0, opacity: 1 },
      content: { shape: 'rounded-rect', fill: accent, borderRadius: 99, layoutSurface: true },
    },
  ];

  return [...chrome, ...next, ...extras];
}

function layoutDeviceMultiCluster(doc, layoutSchema, themeTokens, canvas = {}, newElementId) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = { width: canvas.width || doc.canvas?.width || 1920, height: canvas.height || doc.canvas?.height || 1080 };
  return { ...doc, elements: layoutDeviceMultiClusterElements(doc.elements || [], palette, size, newElementId) };
}

module.exports = {
  isDeviceMultiClusterLayout,
  layoutDeviceMultiCluster,
};
