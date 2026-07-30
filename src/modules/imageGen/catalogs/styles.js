const STYLES = Object.freeze([
  {
    id: 'cinematic',
    name: 'Cinematic',
    promptSuffix:
      'Cinematic lighting, dramatic atmosphere, shallow depth of field, film still aesthetic.',
  },
  {
    id: 'photoreal',
    name: 'Photoreal',
    promptSuffix: 'Photorealistic, natural lighting, high detail, DSLR photography look.',
  },
  {
    id: 'flat_illustration',
    name: 'Flat illustration',
    promptSuffix:
      'Flat vector illustration, clean shapes, limited palette, modern graphic style.',
  },
  {
    id: '3d_render',
    name: '3D render',
    promptSuffix: 'Polished 3D render, soft studio lighting, subtle reflections.',
  },
  {
    id: 'watercolor',
    name: 'Watercolor',
    promptSuffix: 'Watercolor painting, soft washes, paper texture, artistic brush strokes.',
  },
  {
    id: 'corporate',
    name: 'Corporate',
    promptSuffix:
      'Clean corporate visual, professional, polished, brand-safe, modern office aesthetic.',
  },
  {
    id: 'playful',
    name: 'Playful',
    promptSuffix: 'Playful, colorful, friendly, energetic design with soft rounded shapes.',
  },
  {
    id: 'dark_moody',
    name: 'Dark / moody',
    promptSuffix: 'Dark moody atmosphere, low-key lighting, rich contrast, dramatic tones.',
  },
  {
    id: 'minimal',
    name: 'Minimal',
    promptSuffix: 'Minimalist composition, generous negative space, restrained color palette.',
  },
  {
    id: 'neon',
    name: 'Neon',
    promptSuffix: 'Neon accents, glowing edges, night-city vibe, high contrast.',
  },
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
