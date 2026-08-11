const FONT_PAIRING_CATALOG = [
  { id: 'inter_space', heading: 'Inter', subheading: 'Space Grotesk', body: 'Inter' },
  { id: 'inter_source', heading: 'Inter', subheading: 'Inter', body: 'Source Sans 3' },
  { id: 'fraunces_inter', heading: 'Fraunces', subheading: 'Inter', body: 'Inter' },
  { id: 'playfair_lato', heading: 'Playfair Display', subheading: 'Plus Jakarta Sans', body: 'Inter' },
  { id: 'outfit_source', heading: 'Outfit', subheading: 'Space Grotesk', body: 'Inter' },
  { id: 'space_grotesk', heading: 'Space Grotesk', subheading: 'Inter', body: 'Inter' },
  { id: 'dm_sans_serif', heading: 'DM Sans', subheading: 'DM Sans', body: 'DM Sans' },
  { id: 'manrope_inter', heading: 'Manrope', subheading: 'Inter', body: 'Inter' },
];

const COLORS_SUGGEST_SYSTEM = [
  'You are a brand designer extracting a professional color palette from a logo.',
  'Return JSON only with keys: colors (array of { id, name, hex }), colorRoles (object), rationale (string).',
  'Provide at least 4 colors including light-theme bg/text/primary and dark-theme bgDark/textDark/primaryDark role ids.',
  'colorRoles must include: bg, text, primary, bgDark, textDark, primaryDark, and optional secondary, accent, muted.',
  'All hex values must be #RRGGBB. Ensure bg/text and bgDark/textDark pairs have strong contrast.',
].join(' ');

const COLORS_SUGGEST_SCHEMA = {
  colors: [{ id: 'c1', name: 'Primary (Light)', hex: '#D51C0B' }],
  colorRoles: {
    bg: 'c2',
    text: 'c3',
    primary: 'c1',
    bgDark: 'c4',
    textDark: 'c3',
    primaryDark: 'c5',
    secondary: 'c1',
    muted: 'c6',
  },
  rationale: 'Brief explanation',
};

const FONTS_SUGGEST_SYSTEM = [
  'You are a typography expert recommending brand font pairings for presentations.',
  'Return JSON only: fonts (heading, subheading, body each with family, weight, sizePx, lineHeight, fontPairingId), rationale.',
  'Prefer Google-font-safe families. fontPairingId should match catalog when possible.',
].join(' ');

const FONTS_SUGGEST_SCHEMA = {
  fonts: {
    heading: { family: 'Outfit', weight: 700, sizePx: 40, lineHeight: 1.2, fontPairingId: 'outfit_source' },
    subheading: { family: 'Space Grotesk', weight: 600, sizePx: 20, lineHeight: 1.4, fontPairingId: 'outfit_source' },
    body: { family: 'Inter', weight: 400, sizePx: 14, lineHeight: 1.6, fontPairingId: 'outfit_source' },
  },
  rationale: 'Brief explanation',
};

const VOICE_SUGGEST_SYSTEM = [
  'You are a brand strategist expanding brand voice guidelines.',
  'Return JSON only: voice { tone, audience, dos[], donts[], vocabulary[] }.',
  'Keep tone professional and actionable for marketing and presentation copy.',
].join(' ');

const VOICE_SUGGEST_SCHEMA = {
  voice: {
    tone: 'Professional, confident',
    audience: 'Enterprise stakeholders',
    dos: ['Use short sentences'],
    donts: ['Avoid slang'],
    vocabulary: ['Brand name'],
  },
};

const IMAGE_STYLE_SUGGEST_SYSTEM = [
  'You recommend image style briefs and chart color selections for a brand.',
  'Return JSON only: imageStyle (string), chartStyles { colorIds: string[] }, rationale.',
  'imageStyle should be a concise prompt for AI image generators (no text overlay).',
].join(' ');

const IMAGE_STYLE_SUGGEST_SCHEMA = {
  imageStyle: 'clean product photography, studio lighting, brand-safe',
  chartStyles: { colorIds: ['c1', 'c2'] },
  rationale: 'Brief explanation',
};

module.exports = {
  FONT_PAIRING_CATALOG,
  COLORS_SUGGEST_SYSTEM,
  COLORS_SUGGEST_SCHEMA,
  FONTS_SUGGEST_SYSTEM,
  FONTS_SUGGEST_SCHEMA,
  VOICE_SUGGEST_SYSTEM,
  VOICE_SUGGEST_SCHEMA,
  IMAGE_STYLE_SUGGEST_SYSTEM,
  IMAGE_STYLE_SUGGEST_SCHEMA,
};
