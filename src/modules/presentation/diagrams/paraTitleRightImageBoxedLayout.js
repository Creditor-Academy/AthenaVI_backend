function isParaTitleRightImageBoxedLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase();
  return id === 'para_title_right_image_boxed_v1' || id === 'para_title_right_image_boxed';
}

const PARA_TITLE_RIGHT_IMAGE_BOXED_DEFAULTS = {
  HEADING: 'Describe this slide',
  BODY: 'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.',
};

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 1104,
  imgY: 196,
  imgW: 688,
  imgH: 688,
  radius: 36,
  pad: 14,
  textX: 120,
  textW: 860,
  barY: 300,
  barW: 64,
  barH: 6,
  headingY: 328,
  headingH: 140,
  bodyY: 492,
  bodyH: 320,
};

function buildParaTitleRightImageBoxedChromeSvg() {
  const { imgX, imgY, imgW, imgH, radius, pad, textX, barY, barW, barH } = GEOM;
  const frameX = imgX - pad;
  const frameY = imgY - pad;
  const frameW = imgW + pad * 2;
  const frameH = imgH + pad * 2;
  const frameR = radius + 8;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="ptribShadow" x="-12%" y="-10%" width="124%" height="128%">
        <feDropShadow dx="0" dy="18" stdDeviation="22" flood-color="#94A3B8" flood-opacity="0.22" />
      </filter>
    </defs>
    <rect x="${frameX}" y="${frameY}" width="${frameW}" height="${frameH}" rx="${frameR}" fill="#FFFFFF" filter="url(#ptribShadow)" />
    <rect x="${textX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
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

function buildElements({ canvasW, canvasH, headingText, bodyText, imageUrl, accent, textColor, mutedColor, prev = {} }) {
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
        svg: buildParaTitleRightImageBoxedChromeSvg(),
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
      id: prev.HEADING?.id || 'slot-HEADING',
      slotId: 'HEADING',
      type: 'text',
      role: 'heading',
      layer: 10,
      placement: {
        x: Math.round(GEOM.textX * sx),
        y: Math.round(GEOM.headingY * sy),
        width: Math.round(GEOM.textW * sx),
        height: Math.round(GEOM.headingH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: headingText,
        fontSize: Math.round(40 * scale),
        fontWeight: 800,
        color: textColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.15,
        clipToSlot: true,
        maxLines: 2,
      },
    },
    {
      id: prev.BODY?.id || 'slot-BODY',
      slotId: 'BODY',
      type: 'text',
      role: 'body',
      layer: 10,
      placement: {
        x: Math.round(GEOM.textX * sx),
        y: Math.round(GEOM.bodyY * sy),
        width: Math.round(GEOM.textW * sx),
        height: Math.round(GEOM.bodyH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: bodyText,
        fontSize: Math.round(20 * scale),
        fontWeight: 400,
        color: mutedColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.45,
        clipToSlot: true,
        maxLines: 5,
      },
    },
  ];
}

function layoutParaTitleRightImageBoxed(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080;
  const pal = palette?.primary ? palette : (palette?.palette || palette || {});
  const accent = pal.primary || pal.accent || '#6366F1';
  const textColor = pal.text || '#0F172A';
  const mutedColor = pal.muted || '#64748B';
  const headingEl = findEl(elements, ['HEADING', 'TITLE', 'MAIN_TITLE']);
  const bodyEl = findEl(elements, ['BODY', 'PARAGRAPH']);
  const imageEl = findEl(elements, ['HERO_IMAGE', 'IMAGE']);
  const cardEl = findEl(elements, ['IMAGE_CARD_BG']);
  const out = buildElements({
    canvasW,
    canvasH,
    headingText: textOf(headingEl, PARA_TITLE_RIGHT_IMAGE_BOXED_DEFAULTS.HEADING),
    bodyText: textOf(bodyEl, PARA_TITLE_RIGHT_IMAGE_BOXED_DEFAULTS.BODY),
    imageUrl: imageEl?.content?.url || imageEl?.content?.src || null,
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev: {
      IMAGE_CARD_BG: cardEl,
      HERO_IMAGE: imageEl,
      HEADING: headingEl,
      BODY: bodyEl,
    },
  });
  if (Array.isArray(docOrElements)) return out;
  return { ...docOrElements, elements: out };
}

module.exports = {
  isParaTitleRightImageBoxedLayout,
  layoutParaTitleRightImageBoxed,
};
