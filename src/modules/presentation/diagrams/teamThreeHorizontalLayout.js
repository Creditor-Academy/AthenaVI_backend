const TEAM_HEX_CLIP =
  'polygon(50% 0%, 93% 25%, 93% 75%, 50% 100%, 7% 75%, 7% 25%)';

const TEAM_DECO = /^TEAM_(CARD_BG|HEX_RING)_/i;

function isTeamThreeHorizontalLayout(layoutId) {
  return /team_three_horizontal/i.test(String(layoutId || ''));
}

function teamThreeHorizontalGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920;
  const sy = canvasH / 1080;
  const padX = Math.round(96 * sx);
  const gap = Math.round(48 * sx);
  const colW = Math.round((canvasW - padX * 2 - gap * 2) / 3);
  const headingY = Math.round(40 * sy);
  const headingH = Math.round(56 * sy);
  const gapAfterHeading = Math.round(24 * sy);
  const bottomPad = Math.round(48 * sy);
  const hexSize = Math.round(252 * Math.min(sx, sy));
  const ring = Math.max(8, Math.round(12 * Math.min(sx, sy)));
  const imgSize = hexSize - ring * 2;
  const overlap = Math.round(hexSize * 0.45);
  const nameH = Math.round(48 * sy);
  const roleH = Math.round(32 * sy);
  const emailH = Math.round(30 * sy);
  const gapHexText = Math.round(28 * sy);
  const gapText = Math.round(16 * sy);
  const gapDesc = Math.round(28 * sy);
  const cardPadBottom = Math.round(36 * sy);
  const textPadX = Math.round(28 * sx);
  const minDescH = Math.round(120 * sy);
  const minCardH = (hexSize - overlap) + gapHexText + nameH + gapText + roleH + gapText + emailH + gapDesc + minDescH + cardPadBottom;
  const groupH = overlap + minCardH;
  const availableTop = headingY + headingH + gapAfterHeading;
  const availableH = canvasH - availableTop - bottomPad;
  const cardY = availableTop + Math.max(0, Math.round((availableH - groupH) / 2));
  const hexY = cardY - overlap;
  const cardH = Math.max(minCardH, canvasH - bottomPad - cardY);
  const descY = hexY + hexSize + gapHexText + nameH + gapText + roleH + gapText + emailH + gapDesc;
  const descH = Math.max(minDescH, cardY + cardH - cardPadBottom - descY);
  const cols = [0, 1, 2].map((i) => padX + i * (colW + gap));
  return {
    padX,
    colW,
    cols,
    headingY,
    headingH,
    cardY,
    cardH,
    hexY,
    hexSize,
    ring,
    imgSize,
    overlap,
    nameH,
    roleH,
    emailH,
    descH,
    gapHexText,
    gapText,
    gapDesc,
    textPadX,
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

function memberGeom(g, index) {
  const x = g.cols[index];
  const hexX = x + Math.round((g.colW - g.hexSize) / 2);
  const imgX = hexX + g.ring;
  const imgY = g.hexY + g.ring;
  const textX = x + g.textPadX;
  const textW = g.colW - g.textPadX * 2;
  const nameY = g.hexY + g.hexSize + g.gapHexText;
  const roleY = nameY + g.nameH + g.gapText;
  const emailY = roleY + g.roleH + g.gapText;
  const descY = emailY + g.emailH + g.gapDesc;
  return {
    card: { x, y: g.cardY, w: g.colW, h: g.cardH },
    hex: { x: hexX, y: g.hexY, w: g.hexSize, h: g.hexSize },
    img: { x: imgX, y: imgY, w: g.imgSize, h: g.imgSize },
    name: { x: textX, y: nameY, w: textW, h: g.nameH },
    role: { x: textX, y: roleY, w: textW, h: g.roleH },
    email: { x: textX, y: emailY, w: textW, h: g.emailH },
    desc: { x: textX, y: descY, w: textW, h: g.descH },
  };
}

function layoutTeamThreeHorizontalElements(elements, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const g = teamThreeHorizontalGeom(canvasW, canvasH);
  const textColor = (palette && palette.text) || '#1F2937';
  const muted = (palette && palette.muted) || '#6B7280';
  const cardFill = (palette && (palette.cardBg || palette.surface)) || '#FFFFFF';
  const ringFill = (palette && (palette.primary || palette.accent)) || '#1E3A5F';
  const members = [memberGeom(g, 0), memberGeom(g, 1), memberGeom(g, 2)];

  const stripped = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || '')));
  const next = stripped.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();

    if (sid === 'HEADING') {
      return place(el, {
        x: g.padX,
        y: g.headingY,
        w: canvasW - g.padX * 2,
        h: g.headingH,
      }, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 28,
        fontWeight: 800,
        lineHeight: 1.15,
        color: textColor,
        padding: 4,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      });
    }

    const memberMatch = sid.match(/^MEMBER_([123])_(IMAGE|NAME|ROLE|EMAIL|BIO|BODY|DESC)$/);
    if (!memberMatch) return el;
    const m = members[Number(memberMatch[1]) - 1];
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
        align: 'center',
        verticalAlign: 'center',
        fontSize: 22,
        fontWeight: 800,
        lineHeight: 1.2,
        color: textColor,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.nameH,
      });
    }

    if (field === 'ROLE') {
      return place(el, m.role, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 14,
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
        align: 'center',
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
      align: 'center',
      verticalAlign: 'flex-start',
      fontSize: 14,
      fontWeight: 400,
      lineHeight: 1.65,
      color: muted,
      padding: 0,
      wrap: 'pre-wrap',
      clipToSlot: false,
      slotMaxHeight: g.descH,
    });
  });

  const deco = [];
  members.forEach((m, i) => {
    const n = i + 1;
    deco.push({
      id: `shp-team-card-${n}`,
      type: 'shape',
      layer: 2,
      role: 'decoration',
      slotId: `TEAM_CARD_BG_${n}`,
      placement: {
        x: m.card.x,
        y: m.card.y,
        width: m.card.w,
        height: m.card.h,
        rotation: 0,
        opacity: 1,
      },
      content: {
        shape: 'rect',
        fill: cardFill,
        borderRadius: 22,
        stroke: 'rgba(148,163,184,0.35)',
        strokeWidth: 1,
        shadow: '0 10px 28px rgba(15, 23, 42, 0.08)',
        layoutSurface: true,
      },
    });
    deco.push({
      id: `shp-team-hex-${n}`,
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
  });

  return [...deco, ...next];
}

function layoutTeamThreeHorizontal(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  };
  return { ...doc, elements: layoutTeamThreeHorizontalElements(doc.elements || [], palette, size) };
}

module.exports = {
  isTeamThreeHorizontalLayout,
  layoutTeamThreeHorizontal,
};
