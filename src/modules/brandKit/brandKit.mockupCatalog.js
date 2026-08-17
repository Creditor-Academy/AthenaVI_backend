/**
 * Fixed Brand Kit product-mockup catalog + prompt builder.
 */

const MOCKUP_FREE_LIMIT = 2;
const DEFAULT_LOGO_ROLE = 'primary';
const DEFAULT_APPAREL_LOGO_POSITION = 'center_chest';
const APPAREL_TEMPLATE_IDS = Object.freeze(['tshirt', 'hoodie']);
const APPAREL_LOGO_POSITIONS = Object.freeze([
  'center_chest',
  'left_chest',
  'full_front',
  'center_back',
  'full_back',
]);
const APPAREL_LOGO_POSITION_ALIASES = Object.freeze({
  back_center: 'center_back',
});

const SCENE_COPY = Object.freeze({
  mug: 'A clean ceramic coffee mug on a soft studio surface, logo centered on the mug body, soft natural shadows, product photography.',
  tshirt: 'A folded or worn crew-neck t-shirt on a neutral backdrop, apparel catalog photography.',
  hoodie: 'A premium hoodie laid flat or on a hanger, soft fabric texture, studio lighting.',
  tote: 'A canvas tote bag standing upright, logo centered on the front panel, lifestyle product shot.',
  cap: 'A baseball cap angled slightly, logo on the front panel, clean studio background.',
  business_card: 'A pair of business cards on a desk, logo on the card face with minimal layout, shallow depth of field.',
  laptop_lid: 'A closed laptop on a desk, logo centered on the lid, modern workspace photography.',
  phone_case: 'A smartphone in a slim case, logo on the back of the case, clean product photography.',
  packaging_box: 'A branded shipping or gift box, logo on the lid or front panel, packaging photography.',
  storefront_sign: 'A storefront or hanging sign above a shop entrance, logo on the signage panel, daytime exterior.',
});

const APPAREL_POSITION_COPY = Object.freeze({
  center_chest: 'Place the logo clearly on the center chest of the garment.',
  left_chest: "Place a smaller logo on the left chest (wearer's left, over the heart).",
  full_front: 'Place a large logo print across the front of the garment.',
  center_back:
    'Show the back of the garment with the logo centered on the upper back. Do not show the front of the garment.',
  full_back:
    'Show the back of the garment with a large logo print across the back. Do not show the front of the garment.',
});

const MOCKUP_TEMPLATES = Object.freeze([
  {
    id: 'mug',
    label: 'Mug',
    description: 'Ceramic mug with your logo',
    category: 'desk',
    preferredLogoRoles: ['dark', 'black', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'tshirt',
    label: 'T-Shirt',
    description: 'Crew-neck tee with chest logo',
    category: 'apparel',
    preferredLogoRoles: ['white', 'light', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'hoodie',
    label: 'Hoodie',
    description: 'Hoodie with chest logo',
    category: 'apparel',
    preferredLogoRoles: ['white', 'light', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'tote',
    label: 'Tote bag',
    description: 'Canvas tote with front logo',
    category: 'apparel',
    preferredLogoRoles: ['dark', 'black', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'cap',
    label: 'Cap',
    description: 'Baseball cap with front logo',
    category: 'apparel',
    preferredLogoRoles: ['white', 'light', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'business_card',
    label: 'Business card',
    description: 'Business card with logo mark',
    category: 'desk',
    preferredLogoRoles: ['primary', 'dark', 'black'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'laptop_lid',
    label: 'Laptop lid',
    description: 'Laptop lid with centered logo',
    category: 'digital',
    preferredLogoRoles: ['white', 'light', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'phone_case',
    label: 'Phone case',
    description: 'Phone case back with logo',
    category: 'digital',
    preferredLogoRoles: ['white', 'light', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'packaging_box',
    label: 'Packaging box',
    description: 'Branded box with logo',
    category: 'packaging',
    preferredLogoRoles: ['primary', 'dark', 'black'],
    size: '1024x1024',
    thumbnailHint: null,
  },
  {
    id: 'storefront_sign',
    label: 'Storefront sign',
    description: 'Exterior signage with logo',
    category: 'signage',
    preferredLogoRoles: ['white', 'light', 'primary'],
    size: '1024x1024',
    thumbnailHint: null,
  },
]);

const TEMPLATE_BY_ID = Object.freeze(
  Object.fromEntries(MOCKUP_TEMPLATES.map((t) => [t.id, t]))
);

function supportsApparelLogoPosition(templateId) {
  return APPAREL_TEMPLATE_IDS.includes(String(templateId || '').trim());
}

function withCatalogFlags(template) {
  const apparel = supportsApparelLogoPosition(template.id);
  return {
    ...template,
    supportsItemColor: true,
    supportsLogoPosition: apparel,
    logoPositions: apparel ? [...APPAREL_LOGO_POSITIONS] : [],
    defaultLogoPosition: apparel ? DEFAULT_APPAREL_LOGO_POSITION : null,
    defaultLogoRole: DEFAULT_LOGO_ROLE,
  };
}

function getTemplate(templateId) {
  return TEMPLATE_BY_ID[String(templateId || '').trim()] || null;
}

function listTemplates() {
  return MOCKUP_TEMPLATES.map((t) => withCatalogFlags(t));
}

function canonicalizeApparelLogoPosition(logoPosition) {
  const pos = String(logoPosition || '').trim();
  if (!pos) return DEFAULT_APPAREL_LOGO_POSITION;
  const canonical = APPAREL_LOGO_POSITION_ALIASES[pos] || pos;
  if (!APPAREL_LOGO_POSITIONS.includes(canonical)) return DEFAULT_APPAREL_LOGO_POSITION;
  return canonical;
}

function resolveApparelLogoPosition(templateId, logoPosition) {
  if (!supportsApparelLogoPosition(templateId)) return null;
  return canonicalizeApparelLogoPosition(logoPosition);
}

function buildMockupPrompt({
  template,
  brandName,
  tagline,
  primaryHex,
  bgHex,
  itemColor,
  logoPosition,
}) {
  const scene = SCENE_COPY[template.id] || `A realistic product mockup for ${template.label}.`;
  const name = String(brandName || 'Brand').slice(0, 80);
  const tag = tagline ? String(tagline).slice(0, 120) : '';
  const productColor = String(itemColor || '').trim() || null;
  const apparelPosition = resolveApparelLogoPosition(template.id, logoPosition);

  const parts = [
    `Create a photorealistic brand application mockup for "${name}".`,
    scene,
    'Use the provided reference image as the ONLY logo artwork. Place that exact logo on the product.',
    'Do not invent, redraw, distort, or replace the logo. Do not add extra slogans, watermarks, or text overlays.',
    'Keep the logo sharp and legible. No mock UI chrome, no collage.',
  ];

  if (apparelPosition) {
    parts.push(APPAREL_POSITION_COPY[apparelPosition] || APPAREL_POSITION_COPY[DEFAULT_APPAREL_LOGO_POSITION]);
  }

  if (tag) parts.push(`Brand tagline context (do not print unless naturally on packaging): ${tag}.`);

  if (productColor) {
    parts.push(
      `The product, garment, or object itself MUST be colored ${productColor}. Do not recolor, tint, or alter the logo artwork to match the product.`
    );
  } else {
    const primary = primaryHex || null;
    const bg = bgHex || null;
    if (primary) parts.push(`Brand primary accent color hint: ${primary} (use subtly on product or set if natural).`);
    if (bg) parts.push(`Brand background color hint: ${bg} (optional backdrop or fabric tint when appropriate).`);
  }

  return parts.join(' ');
}

module.exports = {
  MOCKUP_FREE_LIMIT,
  MOCKUP_TEMPLATES,
  DEFAULT_LOGO_ROLE,
  DEFAULT_APPAREL_LOGO_POSITION,
  APPAREL_LOGO_POSITIONS,
  APPAREL_LOGO_POSITION_ALIASES,
  APPAREL_TEMPLATE_IDS,
  getTemplate,
  listTemplates,
  supportsApparelLogoPosition,
  resolveApparelLogoPosition,
  buildMockupPrompt,
};
