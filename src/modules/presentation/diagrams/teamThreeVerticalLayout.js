const TEAM_HEX_CLIP =
  'polygon(50% 0%, 93% 25%, 93% 75%, 50% 100%, 7% 75%, 7% 25%)';

const TEAM_DECO = /^TEAM_(PANEL_BG|HEX_RING|RULE)_/i;

function isTeamThreeVerticalLayout(layoutId) {
  return /team_three_vertical/i.test(String(layoutId || ''));
}

function teamThreeVerticalGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920;
  const sy = canvasH / 1080;
  const padX = Math.round(72 * sx);
  const splitX = Math.round(canvasW * 0.62);
  const headingY = Math.round(36 * sy);
  const headingH = Math.round(56 * sy);
  const bottomPad = Math.round(36 * sy);
  const hexSize = Math.round(288 * Math.min(sx, sy));
  const ring = Math.max(7, Math.round(10 * Math.min(sx, sy)));
  const imgSize = hexSize - ring * 2;
  const nameH = Math.round(44 * sy);
  const roleH = Math.round(28 * sy);
  const emailH = Math.round(24 * sy);
  const gapText = Math.round(12 * sy);
  const gapDesc = Math.round(18 * sy);
  const ruleH = Math.max(3, Math.round(3 * sy));
  const ruleW = Math.round(160 * sx);
  const descH = Math.round(72 * sy);
  const textW = splitX - padX - Math.round(hexSize / 2) - Math.round(28 * sx);
  const availableTop = headingY + headingH + Math.round(12 * sy);
  const availableH = canvasH - availableTop - bottomPad;
  const rowH = Math.round(availableH / 3);
  const rows = [0, 1, 2].map((i) => {
    const rowTop = availableTop + i * rowH;
    const hexY = rowTop + Math.round((rowH - hexSize) / 2);
    const hexX = splitX - Math.round(hexSize / 2);
    const imgX = hexX + ring;
    const imgY = hexY + ring;
    const textX = padX;
    const stackH = nameH + gapText + roleH + gapText + emailH + gapDesc + ruleH + gapDesc + descH;
    const textTop = hexY + Math.round((hexSize - stackH) / 2);
    const nameY = textTop;
    const roleY = nameY + nameH + gapText;
    const emailY = roleY + roleH + gapText;
    const ruleY = emailY + emailH + gapDesc;
    const descY = ruleY + ruleH + gapDesc;
    return {
      hex: { x: hexX, y: hexY, w: hexSize, h: hexSize },
      img: { x: imgX, y: imgY, w: imgSize, h: imgSize },
      name: { x: textX, y: nameY, w: textW, h: nameH },
      role: { x: textX, y: roleY, w: textW, h: roleH },
      email: { x: textX, y: emailY, w: textW, h: emailH },
      rule: { x: textX + textW - ruleW, y: ruleY, w: ruleW, h: ruleH },
      desc: { x: textX, y: descY, w: textW, h: descH },
    };
  });
  return {
    padX,
    splitX,
    headingY,
    headingH,
    headingW: textW,
    hexSize,
    ring,
    imgSize,
    nameH,
    roleH,
    emailH,
    descH,
    rows,
  };
}

function place(el, box, extraContent = {}, layer = 16) {
  return {
    ...el,
    layer,
    placement: {
      ...(el.placement || {}),
      x: box.x,
      y: box.y,
      width: box.w,
      height: box.h,
      rotation: 0,
      opacity: 1,
    },
    content: {
      ...(el.content || {}),
      ...extraContent,
    },
  };
}

function layoutTeamThreeVerticalElements(elements, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const g = teamThreeVerticalGeom(canvasW, canvasH);
  const textColor = (palette && palette.text) || '#1F2937';
  const muted = (palette && palette.muted) || '#6B7280';
  const accent = (palette && (palette.primary || palette.accent)) || '#2A9B9B';
  const ringFill = '#FFFFFF';

  const stripped = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || '')));
  const next = stripped.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();

    if (sid === 'HEADING') {
      return place(el, {
        x: g.padX,
        y: g.headingY,
        w: g.headingW,
        h: g.headingH,
      }, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 28,
        fontWeight: 800,
        lineHeight: 1.15,
        color: textColor,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      });
    }

    const memberMatch = sid.match(/^MEMBER_([123])_(IMAGE|NAME|ROLE|EMAIL|BIO|BODY|DESC)$/);
    if (!memberMatch) return el;
    const m = g.rows[Number(memberMatch[1]) - 1];
    const field = memberMatch[2];

    if (field === 'IMAGE') {
      return place(el, m.img, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: 0,
        shadow: undefined,
        boxShadow: undefined,
        clipPath: TEAM_HEX_CLIP,
        imageMask: { type: 'hexagon' },
      }, 8);
    }

    if (field === 'NAME') {
      return place(el, m.name, {
        align: 'right',
        verticalAlign: 'center',
        fontSize: 28,
        fontWeight: 800,
        lineHeight: 1.15,
        color: textColor,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.nameH,
      });
    }

    if (field === 'ROLE') {
      return place(el, m.role, {
        align: 'right',
        verticalAlign: 'center',
        fontSize: 15,
        fontWeight: 500,
        lineHeight: 1.25,
        color: muted,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.roleH,
      });
    }

    if (field === 'EMAIL') {
      return place(el, m.email, {
        align: 'right',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 400,
        lineHeight: 1.25,
        color: muted,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.emailH,
      });
    }

    return place(el, m.desc, {
      align: 'right',
      verticalAlign: 'flex-start',
      fontSize: 14,
      fontWeight: 400,
      lineHeight: 1.55,
      color: muted,
      padding: 0,
      wrap: 'pre-wrap',
      clipToSlot: false,
      slotMaxHeight: g.descH,
    });
  });

  const deco = [{
    id: 'shp-team-v-panel',
    type: 'shape',
    layer: 0,
    role: 'decoration',
    slotId: 'TEAM_PANEL_BG',
    placement: {
      x: g.splitX,
      y: 0,
      width: canvasW - g.splitX,
      height: canvasH,
      rotation: 0,
      opacity: 1,
    },
    content: {
      shape: 'rect',
      fill: accent,
      borderRadius: 0,
      layoutSurface: true,
    },
  }];

  g.rows.forEach((m, i) => {
    const n = i + 1;
    deco.push({
      id: `shp-team-v-hex-${n}`,
      type: 'shape',
      layer: 6,
      role: 'decoration',
      slotId: `TEAM_HEX_RING_${n}`,
      placement: {
        x: m.hex.x,
        y: m.hex.y,
        width: m.hex.w,
        height: m.hex.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'hexagon',
        clipPath: TEAM_HEX_CLIP,
        fill: ringFill,
      },
    });
    deco.push({
      id: `shp-team-v-rule-${n}`,
      type: 'shape',
      layer: 4,
      role: 'decoration',
      slotId: `TEAM_RULE_${n}`,
      placement: {
        x: m.rule.x,
        y: m.rule.y,
        width: m.rule.w,
        height: m.rule.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: accent,
        borderRadius: 1,
      },
    });
  });

  return [...deco, ...next];
}

function layoutTeamThreeVertical(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  };
  return { ...doc, elements: layoutTeamThreeVerticalElements(doc.elements || [], palette, size) };
}

module.exports = {
  isTeamThreeVerticalLayout,
  layoutTeamThreeVertical,
};
