function isTwoParaRightImageBottomLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase();
  return id === 'two_para_right_image_bottom_v1' || id === 'two_para_right_image_bottom';
}

const TWO_PARA_RIGHT_IMAGE_BOTTOM_DEFAULTS = {
  BODY_1: 'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.',
  BODY_2: 'Our approach combines research, design, and storytelling so every slide earns attention and every message lands with precision.',
};

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 120,
  imgY: 520,
  imgW: 1680,
  imgH: 460,
  radius: 28,
  pad: 14,
  body1X: 120,
  body2X: 1020,
  textW: 780,
  barY: 56,
  barW: 56,
  barH: 6,
  bodyY: 88,
  bodyH: 380,
};

function buildTwoParaRightImageBottomChromeSvg() {
  const { imgX, imgY, imgW, imgH, radius, pad, body1X, body2X, barY, barW, barH } = GEOM;
  const frameX = imgX - pad;
  const frameY = imgY - pad;
  const frameW = imgW + pad * 2;
  const frameH = imgH + pad * 2;
  const frameR = radius + 8;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="tpribShadow" x="-10%" y="-8%" width="120%" height="124%">
        <feDropShadow dx="0" dy="16" stdDeviation="18" flood-color="#94A3B8" flood-opacity="0.18" />
      </filter>
    </defs>
    <ellipse cx="80" cy="36" rx="220" ry="110" fill="currentColor" opacity="0.07" />
    <rect x="${frameX}" y="${frameY}" width="${frameW}" height="${frameH}" rx="${frameR}" fill="#FFFFFF" filter="url(#tpribShadow)" />
    <rect x="${body1X}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
    <rect x="${body2X}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
  </svg>`;
}

function findEl(elements, ids) {
  const set = new Set(ids);
  return (elements || []).find((e) => set.has(String(e.slotId || '').toUpperCase()));
}

function textOf(el, fallback) {
  const txt = el?.content?.text || el?.text;
  if (txt && String(txt).trim()) return String(txt).trim();
  return fallback;
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill;
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill;
  if (fill && typeof fill === 'object' && fill.color) return fill.color;
  return fallback;
}

function buildElements({ canvasW, canvasH, body1Text, body2Text, imageUrl, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW;
  const sy = canvasH / GEOM.viewH;
  const scale = Math.min(sx, sy);
  const radius = Math.round(GEOM.radius * scale);

  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildTwoParaRightImageBottomChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    {
      id: prev.HERO_IMAGE?.id || 'slot-HERO_IMAGE',
      slotId: 'HERO_IMAGE',
      type: 'image',
      role: 'image',
      layer: 6,
      placement: {
        x: Math.round(GEOM.imgX * sx),
        y: Math.round(GEOM.imgY * sy),
        width: Math.round(GEOM.imgW * sx),
        height: Math.round(GEOM.imgH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...(imageUrl ? { url: imageUrl, src: imageUrl } : {}),
        fit: 'cover',
        borderRadius: radius,
        alt: '',
      },
    },
    {
      id: prev.BODY_1?.id || 'slot-BODY_1',
      slotId: 'BODY_1',
      type: 'text',
      role: 'body',
      layer: 10,
      placement: {
        x: Math.round(GEOM.body1X * sx),
        y: Math.round(GEOM.bodyY * sy),
        width: Math.round(GEOM.textW * sx),
        height: Math.round(GEOM.bodyH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: body1Text,
        fontSize: Math.round(24 * scale),
        fontWeight: 700,
        color: textColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.4,
        clipToSlot: true,
        maxLines: 6,
      },
    },
    {
      id: prev.BODY_2?.id || 'slot-BODY_2',
      slotId: 'BODY_2',
      type: 'text',
      role: 'body',
      layer: 10,
      placement: {
        x: Math.round(GEOM.body2X * sx),
        y: Math.round(GEOM.bodyY * sy),
        width: Math.round(GEOM.textW * sx),
        height: Math.round(GEOM.bodyH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: body2Text,
        fontSize: Math.round(20 * scale),
        fontWeight: 400,
        color: mutedColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.5,
        clipToSlot: true,
        maxLines: 6,
      },
    },
  ];
}

function layoutTwoParaRightImageBottom(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080;
  const pal = palette?.primary ? palette : (palette?.palette || palette || {});
  const accent = pal.primary || pal.accent || '#6366F1';
  const textColor = pal.text || '#0F172A';
  const mutedColor = pal.muted || '#64748B';
  const body1El = findEl(elements, ['BODY_1', 'BODY', 'HEADING']);
  const body2El = findEl(elements, ['BODY_2', 'PARAGRAPH']);
  const imageEl = findEl(elements, ['HERO_IMAGE', 'IMAGE']);
  const cardEl = findEl(elements, ['IMAGE_CARD_BG']);
  const out = buildElements({
    canvasW,
    canvasH,
    body1Text: textOf(body1El, TWO_PARA_RIGHT_IMAGE_BOTTOM_DEFAULTS.BODY_1),
    body2Text: textOf(body2El, TWO_PARA_RIGHT_IMAGE_BOTTOM_DEFAULTS.BODY_2),
    imageUrl: imageEl?.content?.url || imageEl?.content?.src || null,
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev: {
      IMAGE_CARD_BG: cardEl,
      HERO_IMAGE: imageEl,
      BODY_1: body1El,
      BODY_2: body2El,
    },
  });
  if (Array.isArray(docOrElements)) return out;
  return { ...docOrElements, elements: out };
}

module.exports = {
  isTwoParaRightImageBottomLayout,
  layoutTwoParaRightImageBottom,
};
