const TEAM_DECO = /^TEAM_FOUR_(TAG|FOLD|PHOTO_BG|NAMEBAR|CARD|STRIP|DOT)_/i;
const CARD_PRESETS = ['#E11D48', '#EA580C', '#0F766E', '#155E75'];
const SAMPLE_MEMBERS = [
  { name: 'Johanna Doe', role: 'Co-founder & CEO' },
  { name: 'Jane Doe', role: 'Co-founder & CTO' },
  { name: 'Joe Doe', role: 'Co-founder & COO' },
  { name: 'Jenny Doe', role: 'President' },
];

function filledText(el, fallback) {
  const t = String(el?.content?.text || '').trim();
  if (!t || /^double-?click to edit$/i.test(t)) return fallback;
  return t;
}

function isTeamFourLayout(layoutId) {
  return /team_four_v1/i.test(String(layoutId || ''));
}

function parseHex(hex) {
  const raw = String(hex || '').replace('#', '');
  if (raw.length !== 6) return null;
  const n = Number.parseInt(raw, 16);
  if (Number.isNaN(n)) return null;
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function toHex(r, g, b) {
  return `#${[r, g, b].map((v) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')).join('')}`;
}

function mixHex(a, b, t) {
  const A = parseHex(a) || [234, 88, 12];
  const B = parseHex(b) || [255, 255, 255];
  return toHex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t);
}

function cardPalette(accent) {
  const theme = parseHex(accent) ? accent : CARD_PRESETS[0];
  return CARD_PRESETS.map((p, i) => (i === 0 ? theme : mixHex(p, theme, 0.16)));
}

function teamFourGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920;
  const sy = canvasH / 1080;
  const padX = Math.round(48 * sx);
  const gap = Math.round(28 * sx);
  const colW = Math.round((canvasW - padX * 2 - gap * 3) / 4);
  const headingY = Math.round(24 * sy);
  const headingH = Math.round(42 * sy);
  const subY = headingY + headingH + Math.round(28 * sy);
  const subH = Math.round(26 * sy);
  const availableTop = subY + subH + Math.round(20 * sy);
  const bottomPad = Math.round(32 * sy);
  const availableH = canvasH - availableTop - bottomPad;
  const radius = Math.round(18 * Math.min(sx, sy));
  const stripH = Math.round(32 * sy);
  const cardPadX = Math.round(16 * sx);
  const cardPadTop = Math.round(36 * sy);
  const nameH = Math.round(44 * sy);
  const roleH = Math.round(32 * sy);
  const gapNameRole = Math.round(10 * sy);
  const cardH = cardPadTop + nameH + gapNameRole + roleH + Math.round(28 * sy) + stripH;
  const imgW = colW;
  let imgH = Math.round(imgW * 1.08);
  let overlap = Math.round(imgH * 0.2);
  let stackH = imgH + cardH - overlap;
  if (stackH > availableH) {
    imgH = Math.max(Math.round(imgW * 0.95), availableH - cardH + Math.round(imgW * 0.24));
    overlap = Math.round(imgH * 0.3);
    stackH = imgH + cardH - overlap;
  }
  const groupY = availableTop + Math.max(0, Math.round((availableH - stackH) / 2));
  const cols = [0, 1, 2, 3].map((i) => padX + i * (colW + gap));

  const rows = cols.map((x, i) => {
    const imgX = x;
    const imgY = groupY;
    const cardY = imgY + imgH - overlap;
    const stripY = cardY + cardH - stripH;
    const textX = x + cardPadX;
    const textW = colW - cardPadX * 2;
    const nameY = cardY + cardPadTop;
    const roleY = nameY + nameH + gapNameRole;
    return {
      photoBg: { x: imgX, y: imgY, w: imgW, h: imgH },
      img: { x: imgX, y: imgY, w: imgW, h: imgH },
      card: { x, y: cardY, w: colW, h: cardH },
      strip: { x, y: stripY, w: colW, h: stripH },
      name: { x: textX, y: nameY, w: textW, h: nameH },
      role: { x: textX, y: roleY, w: textW, h: roleH },
      bio: { x: -900 - i * 48, y: -900 - i * 48, w: 8, h: 8 },
      email: { x: -800 - i * 48, y: -800 - i * 48, w: 8, h: 8 },
    };
  });

  return { padX, colW, headingY, headingH, subY, subH, nameH, roleH, radius, rows };
}

function place(el, box, extraContent = {}, layer = 16) {
  const nextContent = {
    ...(el.content || {}),
    ...extraContent,
  };
  if (extraContent.text != null) nextContent.runs = null;
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
      opacity: extraContent.opacity != null ? extraContent.opacity : 1,
    },
    content: nextContent,
  };
}

function injectSubheading(next, g, muted) {
  const have = new Set(next.map((el) => String(el.slotId || '').toUpperCase()));
  if (have.has('SUBHEADING')) return next;
  return [
    ...next,
    {
      id: 'txt-team-four-subheading',
      type: 'text',
      layer: 16,
      role: 'subheading',
      slotId: 'SUBHEADING',
      placement: {
        x: g.padX,
        y: g.subY,
        width: 900,
        height: g.subH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: 'Enter your sub headline here.',
        align: 'left',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 400,
        color: muted,
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.subH,
      },
    },
  ];
}

function layoutTeamFourElements(elements, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const g = teamFourGeom(canvasW, canvasH);
  const textColor = (palette && palette.text) || '#1F2937';
  const muted = (palette && palette.muted) || '#6B7280';
  const accent = (palette && (palette.primary || palette.accent)) || '#E11D48';
  const colors = cardPalette(accent);

  const stripped = elements.filter((el) => !TEAM_DECO.test(String(el.slotId || '')));
  let next = stripped.map((el) => {
    const sid = String(el.slotId || '').toUpperCase();
    if (sid === 'HEADING') {
      return place(el, {
        x: g.padX,
        y: g.headingY,
        w: Math.round(canvasW * 0.62),
        h: g.headingH,
      }, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 28,
        fontWeight: 800,
        lineHeight: 1.1,
        color: textColor,
        text: filledText(el, 'Meet the team'),
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.headingH,
      });
    }
    if (sid === 'SUBHEADING') {
      return place(el, {
        x: g.padX,
        y: g.subY,
        w: Math.round(canvasW * 0.55),
        h: g.subH,
      }, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 16,
        fontWeight: 400,
        lineHeight: 1.3,
        color: textColor,
        text: filledText(el, 'Enter your sub headline here.'),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: false,
        slotMaxHeight: g.subH,
      });
    }

    const memberMatch = sid.match(/^MEMBER_([1234])_(IMAGE|NAME|ROLE|EMAIL|BIO|BODY|DESC)$/);
    if (!memberMatch) return el;
    const memberIndex = Number(memberMatch[1]) - 1;
    const m = g.rows[memberIndex];
    const sample = SAMPLE_MEMBERS[memberIndex];
    const field = memberMatch[2];

    if (field === 'IMAGE') {
      return place(el, m.img, {
        fit: 'cover',
        objectFit: 'cover',
        borderRadius: g.radius,
        stroke: 'rgba(15, 23, 42, 0.12)',
        strokeWidth: 2,
        border: '2px solid rgba(15, 23, 42, 0.12)',
      }, 5);
    }
    if (field === 'NAME') {
      return place(el, m.name, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 20,
        fontWeight: 800,
        lineHeight: 1.15,
        color: '#FFFFFF',
        text: filledText(el, sample.name),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.nameH,
      }, 18);
    }
    if (field === 'ROLE') {
      return place(el, m.role, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 400,
        italic: true,
        lineHeight: 1.2,
        color: '#FFFFFF',
        text: filledText(el, sample.role),
        padding: 0,
        wrap: 'pre-wrap',
        clipToSlot: true,
        slotMaxHeight: g.roleH,
      }, 18);
    }
    if (field === 'EMAIL') {
      return place(el, m.email, { opacity: 0 }, 0);
    }
    return place(el, m.bio, { opacity: 0 }, 0);
  });

  next = injectSubheading(next, g, muted);

  const deco = [];
  g.rows.forEach((m, i) => {
    const n = i + 1;
    const card = colors[i];
    deco.push({
      id: `shp-team-four-photo-${n}`,
      type: 'shape',
      layer: 3,
      role: 'decoration',
      slotId: `TEAM_FOUR_PHOTO_BG_${n}`,
      placement: { x: m.photoBg.x, y: m.photoBg.y, width: m.photoBg.w, height: m.photoBg.h, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: mixHex(card, '#ffffff', 0.78), borderRadius: g.radius },
    });
    deco.push({
      id: `shp-team-four-card-${n}`,
      type: 'shape',
      layer: 10,
      role: 'decoration',
      slotId: `TEAM_FOUR_CARD_${n}`,
      placement: { x: m.card.x, y: m.card.y, width: m.card.w, height: m.card.h, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: card, borderRadius: g.radius, shadow: '0 10px 24px rgba(15, 23, 42, 0.12)' },
    });
    deco.push({
      id: `shp-team-four-strip-${n}`,
      type: 'shape',
      layer: 11,
      role: 'decoration',
      slotId: `TEAM_FOUR_STRIP_${n}`,
      placement: { x: m.strip.x, y: m.strip.y, width: m.strip.w, height: m.strip.h, rotation: 0, opacity: 1 },
      content: { shape: 'rect', fill: mixHex(card, '#000000', 0.22), borderRadius: `0 0 ${g.radius}px ${g.radius}px` },
    });
  });

  return [...deco, ...next];
}

function layoutTeamFour(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  const palette = themeTokens?.palette || {};
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  };
  return { ...doc, elements: layoutTeamFourElements(doc.elements || [], palette, size) };
}

module.exports = {
  isTeamFourLayout,
  layoutTeamFour,
};
