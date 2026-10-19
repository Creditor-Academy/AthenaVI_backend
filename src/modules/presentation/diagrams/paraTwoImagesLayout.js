function isParaTwoImagesLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase();
  return id === 'para_two_images_v1' || id === 'para_two_images';
}

const PARA_TWO_IMAGES_DEFAULTS = {
  BODY_1: 'We help teams turn complex ideas into clear narratives that drive decisions and build momentum.',
  BODY_2: 'Our approach combines research, design, and storytelling so every message lands with precision.',
};

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  colXs: [120, 1000],
  colW: 800,
  barY: 96,
  barW: 56,
  barH: 6,
  bodyY: 124,
  bodyH: 200,
  imgY: 372,
  imgH: 600,
  radius: 32,
  pad: 14,
};

function buildParaTwoImagesChromeSvg() {
  const { colXs, colW, barY, barW, barH, imgY, imgH, radius, pad } = GEOM;
  const frames = colXs
    .map((x) => `<rect x="${x - pad}" y="${imgY - pad}" width="${colW + pad * 2}" height="${imgH + pad * 2}" rx="${radius + 8}" fill="#FFFFFF" filter="url(#ptiShadow)" />`)
    .join('');
  const bars = colXs
    .map((x) => `<rect x="${x}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />`)
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="ptiShadow" x="-10%" y="-10%" width="120%" height="130%">
        <feDropShadow dx="0" dy="16" stdDeviation="18" flood-color="#94A3B8" flood-opacity="0.18" />
      </filter>
    </defs>
    <ellipse cx="1840" cy="40" rx="240" ry="110" fill="currentColor" opacity="0.06" />
    ${frames}
    ${bars}
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

function buildElements({ canvasW, canvasH, bodies, imageUrls, accent, textColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW;
  const sy = canvasH / GEOM.viewH;
  const scale = Math.min(sx, sy);
  const radius = Math.round(GEOM.radius * scale);

  const images = GEOM.colXs.map((x, i) => {
    const slotId = `IMAGE_${i + 1}`;
    const url = imageUrls[i];
    return {
      id: prev[slotId]?.id || `slot-${slotId}`,
      slotId,
      type: 'image',
      role: 'image',
      layer: 6,
      placement: {
        x: Math.round(x * sx),
        y: Math.round(GEOM.imgY * sy),
        width: Math.round(GEOM.colW * sx),
        height: Math.round(GEOM.imgH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...(url ? { url, src: url } : {}),
        fit: 'cover',
        borderRadius: radius,
        alt: '',
      },
    };
  });

  const texts = GEOM.colXs.map((x, i) => {
    const slotId = `BODY_${i + 1}`;
    return {
      id: prev[slotId]?.id || `slot-${slotId}`,
      slotId,
      type: 'text',
      role: 'body',
      layer: 10,
      placement: {
        x: Math.round(x * sx),
        y: Math.round(GEOM.bodyY * sy),
        width: Math.round(GEOM.colW * sx),
        height: Math.round(GEOM.bodyH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: bodies[i],
        fontSize: Math.round(22 * scale),
        fontWeight: i === 0 ? 600 : 400,
        color: textColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.5,
        clipToSlot: true,
        maxLines: 5,
      },
    };
  });

  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildParaTwoImagesChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    ...images,
    ...texts,
  ];
}

function layoutParaTwoImages(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080;
  const pal = palette?.primary ? palette : (palette?.palette || palette || {});
  const accent = pal.primary || pal.accent || '#6366F1';
  const textColor = pal.text || '#0F172A';
  const bodyEls = [1, 2].map((n) => findEl(elements, [`BODY_${n}`]));
  const imageEls = [1, 2].map((n) => findEl(elements, [`IMAGE_${n}`]));
  const cardEl = findEl(elements, ['IMAGE_CARD_BG']);
  const out = buildElements({
    canvasW,
    canvasH,
    bodies: bodyEls.map((el, i) => textOf(el, PARA_TWO_IMAGES_DEFAULTS[`BODY_${i + 1}`])),
    imageUrls: imageEls.map((el) => el?.content?.url || el?.content?.src || null),
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    prev: {
      IMAGE_CARD_BG: cardEl,
      BODY_1: bodyEls[0],
      BODY_2: bodyEls[1],
      IMAGE_1: imageEls[0],
      IMAGE_2: imageEls[1],
    },
  });
  if (Array.isArray(docOrElements)) return out;
  return { ...docOrElements, elements: out };
}

module.exports = {
  isParaTwoImagesLayout,
  layoutParaTwoImages,
};
