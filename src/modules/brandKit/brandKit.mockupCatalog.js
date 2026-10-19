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
const BACK_APPAREL_POSITIONS = Object.freeze(['center_back', 'full_back']);
const APPAREL_LOGO_POSITION_ALIASES = Object.freeze({
  back_center: 'center_back',
  back: 'center_back',
  rear: 'center_back',
  rear_center: 'center_back',
  upper_back: 'center_back',
  back_full: 'full_back',
  full_rear: 'full_back',
  rear_full: 'full_back',
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
  center_chest:
    'Print the provided logo on the CENTER CHEST of the FRONT. This is a front-of-garment mockup.',
  left_chest:
    "Print a smaller logo on the LEFT CHEST of the FRONT (wearer's left, over the heart). Front view only.",
  full_front: 'Print a LARGE logo across the FRONT of the garment. Front view only.',
  center_back:
    'Print the provided logo on the UPPER BACK, centered between the shoulder blades. BACK VIEW ONLY. Do not place the logo on the chest or front.',
  full_back:
    'Print a LARGE logo covering the BACK PANEL from the shoulders downward. BACK VIEW ONLY. Do not place the logo on the chest or front.',
});

function isBackApparelPosition(position) {
  return BACK_APPAREL_POSITIONS.includes(String(position || '').trim());
}

function apparelSceneCopy(templateId, position) {
  const isHoodie = String(templateId) === 'hoodie';
  const garment = isHoodie ? 'premium pullover hoodie' : 'crew-neck t-shirt';

  if (position === 'center_back') {
    return [
      `Photorealistic BACK-SIDE catalog photo of a ${garment}.`,
      'The camera MUST face the rear of the garment: the wearer faces away from the camera, or the garment is laid flat with the back panel facing up.',
      isHoodie
        ? 'Visible: hood from behind, rear shoulder seams, and upper back. The front kangaroo pocket, zipper, and face opening must not appear.'
        : 'Visible: rear collar, shoulder seams, and upper back. The front neckline and chest print area must not appear.',
      'Studio lighting, neutral backdrop.',
    ].join(' ');
  }

  if (position === 'full_back') {
    return [
      `Photorealistic BACK-SIDE catalog photo of a ${garment}.`,
      'The camera MUST face the rear of the garment only (wearer facing away, or laid flat back-side up).',
      'Show the full back panel from the shoulders to the hem. Do not show the front of the garment.',
      'Studio lighting, neutral backdrop.',
    ].join(' ');
  }

  const frontView = `Photorealistic FRONT VIEW of a ${garment} on a neutral backdrop, apparel catalog photography.`;
  if (position === 'left_chest') {
    return `${frontView} Small logo placement on the left chest.`;
  }
  if (position === 'full_front') {
    return `${frontView} Large logo print across the front.`;
  }
  return `${frontView} Logo on the center chest.`;
}

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
  const pos = String(logoPosition || '')
    .trim()
    .toLowerCase()
    .replace(/[-\s]+/g, '_');
  if (!pos) return DEFAULT_APPAREL_LOGO_POSITION;
  const canonical = APPAREL_LOGO_POSITION_ALIASES[pos] || pos;
  if (!APPAREL_LOGO_POSITIONS.includes(canonical)) return null;
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
  const name = String(brandName || 'Brand').slice(0, 80);
  const tag = tagline ? String(tagline).slice(0, 120) : '';
  const productColor = String(itemColor || '').trim() || null;
  const apparelPosition = resolveApparelLogoPosition(template.id, logoPosition);
  const isBackView = isBackApparelPosition(apparelPosition);
  const scene = apparelPosition
    ? apparelSceneCopy(template.id, apparelPosition)
    : SCENE_COPY[template.id] || `A realistic product mockup for ${template.label}.`;

  const parts = [];
  if (isBackView) {
    parts.push(
      'CRITICAL: This is a BACK VIEW mockup. Photograph the garment from behind. The logo is printed on the BACK, never on the chest or front.'
    );
  }
  parts.push(
    `Create a photorealistic brand application mockup for "${name}".`,
    scene,
    'Use the provided reference image as the ONLY logo artwork. Place that exact logo on the product.',
    'Do not invent, redraw, distort, or replace the logo. Do not add extra slogans, watermarks, or text overlays.',
    'Keep the logo sharp and legible. No mock UI chrome, no collage.'
  );

  if (apparelPosition) {
    parts.push(APPAREL_POSITION_COPY[apparelPosition] || APPAREL_POSITION_COPY[DEFAULT_APPAREL_LOGO_POSITION]);
  }
  if (isBackView) {
    parts.push(
      'Forbidden: front view, chest print, model facing the camera, front neckline, or kangaroo pocket. The logo must sit on the back fabric only.'
    );
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
  BACK_APPAREL_POSITIONS,
  getTemplate,
  listTemplates,
  supportsApparelLogoPosition,
  canonicalizeApparelLogoPosition,
  resolveApparelLogoPosition,
  isBackApparelPosition,
  buildMockupPrompt,
};
