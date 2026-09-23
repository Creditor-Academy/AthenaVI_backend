function isParaThreeImagesStaggeredLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase();
  return id === 'para_three_images_staggered_v1' || id === 'para_three_images_staggered';
}

const PARA_THREE_IMAGES_STAGGERED_DEFAULTS = {
  BODY: 'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the organization.',
};

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  textX: 120,
  textW: 520,
  barY: 100,
  barW: 56,
  barH: 6,
  bodyY: 128,
  bodyH: 240,
  imgXs: [120, 680, 1240],
  imgYs: [400, 260, 120],
  imgW: 520,
  imgH: 600,
  radius: 28,
  pad: 12,
  dotsX: 1300,
  dotsY: 800,
  dotCols: 8,
  dotRows: 4,
  dotGap: 52,
  dotR: 5,
};

function dotsSvg(fill) {
  const { dotsX, dotsY, dotCols, dotRows, dotGap, dotR } = GEOM;
  let out = '';
  for (let r = 0; r < dotRows; r += 1) {
    for (let c = 0; c < dotCols; c += 1) {
      out += `<circle cx="${dotsX + c * dotGap}" cy="${dotsY + r * dotGap}" r="${dotR}" fill="${fill}" opacity="${0.18 + 0.06 * r}" />`;
    }
  }
  return out;
}

function buildParaThreeImagesStaggeredChromeSvg() {
  const { textX, barY, barW, barH, imgXs, imgYs, imgW, imgH, radius, pad } = GEOM;
  const frames = imgXs
    .map((x, i) => `<rect x="${x - pad}" y="${imgYs[i] - pad}" width="${imgW + pad * 2}" height="${imgH + pad * 2}" rx="${radius + 8}" fill="#FFFFFF" filter="url(#ptsShadow)" />`)
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="ptsShadow" x="-12%" y="-10%" width="124%" height="128%">
        <feDropShadow dx="0" dy="18" stdDeviation="20" flood-color="#94A3B8" flood-opacity="0.22" />
      </filter>
    </defs>
    <path d="M0 1080 L0 820 C 520 760 1180 380 1920 120 L1920 1080 Z" fill="currentColor" opacity="0.05" />
    <circle cx="1860" cy="60" r="140" fill="currentColor" opacity="0.06" />
    ${dotsSvg('currentColor')}
    ${frames}
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

function buildElements({ canvasW, canvasH, bodyText, imageUrls, accent, textColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW;
  const sy = canvasH / GEOM.viewH;
  const scale = Math.min(sx, sy);
  const radius = Math.round(GEOM.radius * scale);

  const images = GEOM.imgXs.map((x, i) => {
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
        y: Math.round(GEOM.imgYs[i] * sy),
        width: Math.round(GEOM.imgW * sx),
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

  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildParaThreeImagesStaggeredChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    ...images,
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
        fontSize: Math.round(28 * scale),
        fontWeight: 600,
        color: textColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.4,
        clipToSlot: true,
        maxLines: 6,
      },
    },
  ];
}

function layoutParaThreeImagesStaggered(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080;
  const pal = palette?.primary ? palette : (palette?.palette || palette || {});
  const accent = pal.primary || pal.accent || '#6366F1';
  const textColor = pal.text || '#0F172A';
  const bodyEl = findEl(elements, ['BODY', 'HEADING', 'PARAGRAPH']);
  const imageEls = [1, 2, 3].map((n) => findEl(elements, [`IMAGE_${n}`]));
  const cardEl = findEl(elements, ['IMAGE_CARD_BG']);
  const out = buildElements({
    canvasW,
    canvasH,
    bodyText: textOf(bodyEl, PARA_THREE_IMAGES_STAGGERED_DEFAULTS.BODY),
    imageUrls: imageEls.map((el) => el?.content?.url || el?.content?.src || null),
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    prev: {
      IMAGE_CARD_BG: cardEl,
      BODY: bodyEl,
      IMAGE_1: imageEls[0],
      IMAGE_2: imageEls[1],
      IMAGE_3: imageEls[2],
    },
  });
  if (Array.isArray(docOrElements)) return out;
  return { ...docOrElements, elements: out };
}

module.exports = {
  isParaThreeImagesStaggeredLayout,
  layoutParaThreeImagesStaggered,
};
