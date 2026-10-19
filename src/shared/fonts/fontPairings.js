/**
 * Canonical font pairing catalog for Brand Kit AI suggest, AI PPT theme fonts,
 * and GET /api/fonts/catalog. All theme catalog fontPairingId values must exist here.
 */

const FONT_PAIRING_CATALOG = [
  // Existing ids (themes/catalog.json + prior brand-kit suggest)
  {
    id: 'inter_space',
    heading: 'Inter',
    subheading: 'Space Grotesk',
    body: 'Inter',
    moods: ['minimal', 'corporate', 'clean'],
    useCases: ['pitch', 'product', 'saas'],
  },
  {
    id: 'inter_source',
    heading: 'Inter',
    subheading: 'Inter',
    body: 'Source Sans 3',
    moods: ['minimal', 'professional', 'business'],
    useCases: ['pitch', 'report', 'corporate'],
  },
  {
    id: 'fraunces_inter',
    heading: 'Fraunces',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['warm', 'editorial', 'friendly'],
    useCases: ['story', 'brand', 'lifestyle'],
  },
  {
    id: 'playfair_lato',
    heading: 'Playfair Display',
    subheading: 'Plus Jakarta Sans',
    body: 'Inter',
    moods: ['luxury', 'editorial', 'elegant', 'fashion'],
    useCases: ['pitch', 'fashion', 'annual-report'],
  },
  {
    id: 'outfit_source',
    heading: 'Outfit',
    subheading: 'Space Grotesk',
    body: 'Inter',
    moods: ['modern', 'tech', 'startup', 'innovation'],
    useCases: ['saas', 'product', 'pitch'],
  },
  {
    id: 'space_grotesk',
    heading: 'Space Grotesk',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['creative', 'bold', 'design', 'agency'],
    useCases: ['marketing', 'agency', 'pitch'],
  },
  {
    id: 'dm_sans_serif',
    heading: 'DM Sans',
    subheading: 'DM Sans',
    body: 'DM Sans',
    moods: ['clean', 'product', 'modern'],
    useCases: ['product', 'saas', 'ui'],
  },
  {
    id: 'manrope_inter',
    heading: 'Manrope',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['modern', 'friendly', 'tech'],
    useCases: ['saas', 'product', 'pitch'],
  },
  {
    id: 'nunito_inter',
    heading: 'Nunito',
    subheading: 'Nunito',
    body: 'Inter',
    moods: ['friendly', 'warm', 'community', 'nonprofit'],
    useCases: ['nonprofit', 'education', 'community'],
  },
  {
    id: 'libre_ibm',
    heading: 'Libre Baskerville',
    subheading: 'Libre Baskerville',
    body: 'IBM Plex Sans',
    moods: ['classic', 'academic', 'heritage', 'education'],
    useCases: ['education', 'museum', 'report'],
  },

  // Extended pairings
  {
    id: 'cormorant_source',
    heading: 'Cormorant Garamond',
    subheading: 'Source Sans 3',
    body: 'Source Sans 3',
    moods: ['luxury', 'editorial', 'elegant'],
    useCases: ['fashion', 'wedding', 'brand'],
  },
  {
    id: 'cinzel_raleway',
    heading: 'Cinzel',
    subheading: 'Raleway',
    body: 'Raleway',
    moods: ['luxury', 'classic', 'premium'],
    useCases: ['luxury', 'invitation', 'brand'],
  },
  {
    id: 'merriweather_source',
    heading: 'Merriweather',
    subheading: 'Source Sans 3',
    body: 'Source Sans 3',
    moods: ['classic', 'editorial', 'academic'],
    useCases: ['report', 'education', 'blog'],
  },
  {
    id: 'lora_inter',
    heading: 'Lora',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['editorial', 'warm', 'readable'],
    useCases: ['story', 'blog', 'brand'],
  },
  {
    id: 'oswald_dm',
    heading: 'Oswald',
    subheading: 'DM Sans',
    body: 'DM Sans',
    moods: ['bold', 'agency', 'marketing'],
    useCases: ['marketing', 'sports', 'pitch'],
  },
  {
    id: 'syne_inter',
    heading: 'Syne',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['creative', 'bold', 'design', 'tech'],
    useCases: ['agency', 'design', 'saas'],
  },
  {
    id: 'poppins_open',
    heading: 'Poppins',
    subheading: 'Open Sans',
    body: 'Open Sans',
    moods: ['friendly', 'modern', 'clean'],
    useCases: ['product', 'education', 'pitch'],
  },
  {
    id: 'montserrat_open',
    heading: 'Montserrat',
    subheading: 'Open Sans',
    body: 'Open Sans',
    moods: ['corporate', 'clean', 'professional'],
    useCases: ['corporate', 'pitch', 'report'],
  },
  {
    id: 'raleway_lato',
    heading: 'Raleway',
    subheading: 'Lato',
    body: 'Lato',
    moods: ['elegant', 'clean', 'professional'],
    useCases: ['brand', 'pitch', 'product'],
  },
  {
    id: 'ubuntu_inter',
    heading: 'Ubuntu',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['tech', 'friendly', 'modern'],
    useCases: ['tech', 'saas', 'product'],
  },
  {
    id: 'roboto_open',
    heading: 'Roboto',
    subheading: 'Open Sans',
    body: 'Open Sans',
    moods: ['corporate', 'minimal', 'clean'],
    useCases: ['corporate', 'product', 'ui'],
  },
  {
    id: 'plus_jakarta',
    heading: 'Plus Jakarta Sans',
    subheading: 'Plus Jakarta Sans',
    body: 'Inter',
    moods: ['modern', 'saas', 'product'],
    useCases: ['saas', 'product', 'pitch'],
  },
  {
    id: 'bebas_inter',
    heading: 'Bebas Neue',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['bold', 'agency', 'marketing'],
    useCases: ['marketing', 'sports', 'event'],
  },
  {
    id: 'archivo_inter',
    heading: 'Archivo',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['bold', 'modern', 'corporate'],
    useCases: ['pitch', 'marketing', 'corporate'],
  },
  {
    id: 'sora_inter',
    heading: 'Sora',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['tech', 'startup', 'modern'],
    useCases: ['saas', 'product', 'pitch'],
  },
  {
    id: 'work_sans',
    heading: 'Work Sans',
    subheading: 'Work Sans',
    body: 'Work Sans',
    moods: ['clean', 'minimal', 'product'],
    useCases: ['product', 'ui', 'saas'],
  },
  {
    id: 'crimson_source',
    heading: 'Crimson Text',
    subheading: 'Source Sans 3',
    body: 'Source Sans 3',
    moods: ['classic', 'editorial', 'academic'],
    useCases: ['education', 'report', 'book'],
  },
  {
    id: 'josefin_lato',
    heading: 'Josefin Sans',
    subheading: 'Lato',
    body: 'Lato',
    moods: ['elegant', 'creative', 'fashion'],
    useCases: ['fashion', 'lifestyle', 'brand'],
  },
  {
    id: 'barlow_inter',
    heading: 'Barlow',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['tech', 'modern', 'bold'],
    useCases: ['tech', 'sports', 'product'],
  },
  {
    id: 'lexend_inter',
    heading: 'Lexend',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['friendly', 'readable', 'education'],
    useCases: ['education', 'accessibility', 'product'],
  },
  {
    id: 'fira_inter',
    heading: 'Fira Sans',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['tech', 'clean', 'professional'],
    useCases: ['tech', 'saas', 'report'],
  },
  {
    id: 'noto_serif_sans',
    heading: 'Noto Serif',
    subheading: 'Noto Sans',
    body: 'Noto Sans',
    moods: ['classic', 'readable', 'global'],
    useCases: ['education', 'report', 'multilingual'],
  },
  {
    id: 'rubik_inter',
    heading: 'Rubik',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['friendly', 'modern', 'product'],
    useCases: ['product', 'startup', 'community'],
  },
  {
    id: 'cabin_inter',
    heading: 'Cabin',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['warm', 'friendly', 'clean'],
    useCases: ['brand', 'nonprofit', 'product'],
  },
  {
    id: 'exo2_inter',
    heading: 'Exo 2',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['tech', 'bold', 'innovation'],
    useCases: ['tech', 'gaming', 'saas'],
  },
  {
    id: 'pt_serif_sans',
    heading: 'PT Serif',
    subheading: 'PT Sans',
    body: 'PT Sans',
    moods: ['classic', 'editorial', 'professional'],
    useCases: ['report', 'editorial', 'corporate'],
  },
  {
    id: 'quicksand_inter',
    heading: 'Quicksand',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['friendly', 'warm', 'community'],
    useCases: ['nonprofit', 'lifestyle', 'education'],
  },
  {
    id: 'spectral_inter',
    heading: 'Spectral',
    subheading: 'Inter',
    body: 'Inter',
    moods: ['editorial', 'elegant', 'readable'],
    useCases: ['editorial', 'report', 'brand'],
  },
  {
    id: 'ibm_plex',
    heading: 'IBM Plex Sans',
    subheading: 'IBM Plex Sans',
    body: 'IBM Plex Sans',
    moods: ['tech', 'corporate', 'professional'],
    useCases: ['tech', 'corporate', 'report'],
  },
  {
    id: 'public_sans',
    heading: 'Public Sans',
    subheading: 'Public Sans',
    body: 'Public Sans',
    moods: ['clean', 'government', 'minimal'],
    useCases: ['corporate', 'government', 'product'],
  },
];

const PAIRING_BY_ID = Object.fromEntries(FONT_PAIRING_CATALOG.map((p) => [p.id, p]));

/** Families that appear in pairings — always allowed for AI. */
const PAIRING_FAMILIES = [
  ...new Set(
    FONT_PAIRING_CATALOG.flatMap((p) => [p.heading, p.subheading, p.body].filter(Boolean))
  ),
];

/**
 * Featured catalog families (picker defaults + AI allowlist).
 * Includes every pairing family plus popular extras.
 */
const FEATURED_FAMILIES = [
  ...new Set([
    ...PAIRING_FAMILIES,
    'Inter',
    'Roboto',
    'Open Sans',
    'Lato',
    'Montserrat',
    'Poppins',
    'Oswald',
    'Raleway',
    'Nunito',
    'Ubuntu',
    'Playfair Display',
    'Merriweather',
    'Lora',
    'Source Sans 3',
    'Noto Sans',
    'Noto Serif',
    'PT Sans',
    'PT Serif',
    'Work Sans',
    'Fira Sans',
    'Libre Baskerville',
    'IBM Plex Sans',
    'IBM Plex Serif',
    'DM Sans',
    'Space Grotesk',
    'Outfit',
    'Manrope',
    'Plus Jakarta Sans',
    'Fraunces',
    'Syne',
    'Cormorant Garamond',
    'Cinzel',
    'Bebas Neue',
    'Archivo',
    'Sora',
    'Barlow',
    'Josefin Sans',
    'Lexend',
    'Crimson Text',
    'Rubik',
    'Cabin',
    'Exo 2',
    'Quicksand',
    'Spectral',
    'Public Sans',
    'Mulish',
    'Karla',
    'Inconsolata',
    'JetBrains Mono',
    'Space Mono',
    'Pacifico',
    'Dancing Script',
    'Great Vibes',
    'Anton',
    'Bitter',
    'Libre Franklin',
    'Nunito Sans',
    'Titillium Web',
    'Hind',
    'Heebo',
    'Mukta',
    'Overpass',
    'Red Hat Display',
    'Figtree',
    'Geist',
    'Instrument Sans',
    'Schibsted Grotesk',
    'Newsreader',
    'Literata',
    'EB Garamond',
    'Cardo',
    'Alegreya',
    'Alegreya Sans',
    'Commissioner',
    'Epilogue',
    'Urbanist',
    'DM Serif Display',
    'DM Serif Text',
    'Bricolage Grotesque',
    'Young Serif',
    'Instrument Serif',
    'Unbounded',
    'Clash Display',
  ]),
];

const ALLOWED_FAMILIES = new Set(FEATURED_FAMILIES.map((f) => f.toLowerCase()));

function pairingsByMood() {
  const byMood = {};
  for (const pairing of FONT_PAIRING_CATALOG) {
    for (const mood of pairing.moods || []) {
      if (!byMood[mood]) byMood[mood] = [];
      byMood[mood].push(pairing.id);
    }
  }
  return byMood;
}

/** Prompt-friendly string: mood → pairing ids. */
function formatPairingsForPrompt() {
  const byMood = pairingsByMood();
  return Object.entries(byMood)
    .map(([mood, ids]) => `- ${mood}: ${ids.join(', ')}`)
    .join('\n');
}

function isAllowedFontFamily(family) {
  if (!family || typeof family !== 'string') return false;
  return ALLOWED_FAMILIES.has(String(family).trim().toLowerCase());
}

module.exports = {
  FONT_PAIRING_CATALOG,
  PAIRING_BY_ID,
  PAIRING_FAMILIES,
  FEATURED_FAMILIES,
  ALLOWED_FAMILIES,
  pairingsByMood,
  formatPairingsForPrompt,
  isAllowedFontFamily,
};
