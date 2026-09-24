const STYLES = Object.freeze([
  { id: 'scene', name: 'Scene', promptSuffix: 'Scenic, wide angle, immersive environment, detailed background.' },
  { id: 'photo', name: 'Photo', promptSuffix: 'Realistic photography, 35mm lens, highly detailed, photoreal.' },
  { id: 'still-life', name: 'Still life', promptSuffix: 'Still life photography, studio lighting, detailed macro.' },
  { id: 'spot-color', name: 'Spot Color', promptSuffix: 'Black and white with a single vibrant spot color accent.' },
  { id: 'illustration', name: 'Illustration', promptSuffix: 'Colorful digital illustration, playful design, clean lines.' },
  { id: 'flat-line', name: 'Flat Line Art', promptSuffix: 'Minimalist flat line art, simple vector style, monochrome or limited palette.' },
  { id: 'modern-art', name: 'Modern Art', promptSuffix: 'Abstract modern art, bold shapes, contemporary aesthetic.' },
  { id: 'isometric', name: 'Isometric', promptSuffix: 'Isometric 3D perspective, clean shapes, playful and structured.' },
  { id: 'gouache', name: 'Gouache Paint', promptSuffix: 'Gouache painting, rich opaque colors, painterly brush strokes.' },
  { id: 'bold-poster', name: 'Bold Poster', promptSuffix: 'Bold poster design, striking contrast, graphic design aesthetic.' },
  { id: 'watercolor', name: 'Watercolor', promptSuffix: 'Watercolor painting, soft washes, artistic.' },
  { id: 'bauhaus', name: 'Bauhaus', promptSuffix: 'Bauhaus style, geometric shapes, primary colors, minimalist graphic design.' },
  { id: '3d', name: '3D', promptSuffix: '3D render, soft studio lighting, playful 3D shapes, smooth materials.' },
  { id: 'neon-glow', name: 'Neon Glow', promptSuffix: 'Neon lighting, glowing accents, synthwave style, dark background.' },
  { id: 'cinematic', name: 'Cinematic', promptSuffix: 'Cinematic lighting, dramatic atmosphere, shallow depth of field, film still aesthetic.' },
  { id: 'mesh', name: 'Mesh', promptSuffix: 'Abstract 3D mesh, flowing digital lines, futuristic tech aesthetic.' },
]);

const STYLE_BY_ID = Object.freeze(
  Object.fromEntries(STYLES.map((s) => [s.id, s]))
);

function listStyles() {
  return STYLES.map((s) => ({
    id: s.id,
    name: s.name,
  }));
}

function resolveStyle(styleId) {
  if (!styleId) return null;
  return STYLE_BY_ID[styleId] || null;
}

function styleSuffix(styleId) {
  const style = resolveStyle(styleId);
  return style ? style.promptSuffix : '';
}

module.exports = {
  STYLES,
  STYLE_BY_ID,
  listStyles,
  resolveStyle,
  styleSuffix,
};
