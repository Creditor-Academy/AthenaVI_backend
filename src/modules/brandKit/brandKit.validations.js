const Joi = require('joi');

const workspaceIdParam = Joi.string().uuid().required();
const brandKitIdParam = Joi.string().trim().min(1).max(64).required();
const mediaIdParam = Joi.string().trim().min(1).max(64).required();

const hexColor = Joi.string()
  .trim()
  .pattern(/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/)
  .required();

const colorEntrySchema = Joi.object({
  id: Joi.string().trim().min(1).max(64).required(),
  name: Joi.string().trim().min(1).max(64).required(),
  hex: hexColor,
}).required();

const fontFaceSchema = Joi.object({
  fontPairingId: Joi.string().trim().max(64).allow(null, '').optional(),
  family: Joi.string().trim().max(128).allow(null, '').optional(),
  weight: Joi.number().integer().min(100).max(900).optional(),
  sizePx: Joi.number().integer().min(8).max(200).optional(),
  lineHeight: Joi.number().min(0.8).max(3).optional(),
  lightTextColorId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
  darkTextColorId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
}).optional();

const buttonStyleSchema = Joi.object({
  label: Joi.string().trim().max(64).allow('', null).optional(),
  backgroundColorId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
  textColorId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
  borderColorId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
  borderWidthPx: Joi.number().integer().min(0).max(12).optional(),
  borderRadiusPx: Joi.number().integer().min(0).max(64).optional(),
  paddingXPx: Joi.number().integer().min(0).max(80).optional(),
  paddingYPx: Joi.number().integer().min(0).max(48).optional(),
  fontWeight: Joi.number().integer().min(100).max(900).optional(),
  fontSizePx: Joi.number().integer().min(10).max(32).optional(),
})
  .unknown(true)
  .optional();

const brandKitDataSchema = Joi.object({
  meta: Joi.object({
    tagline: Joi.string().trim().max(256).allow('', null).optional(),
    industry: Joi.string().trim().max(128).allow('', null).optional(),
    guidelineProjectId: Joi.string().trim().max(64).allow('', null).optional(),
  })
    .unknown(true)
    .optional(),
  colors: Joi.array().items(colorEntrySchema).min(2).max(32).required(),
  colorRoles: Joi.object({
    bg: Joi.string().trim().min(1).max(64).required(),
    text: Joi.string().trim().min(1).max(64).required(),
    primary: Joi.string().trim().min(1).max(64).required(),
    secondary: Joi.string().trim().min(1).max(64).optional(),
    accent: Joi.string().trim().min(1).max(64).optional(),
    muted: Joi.string().trim().min(1).max(64).optional(),
    bgDark: Joi.string().trim().min(1).max(64).optional(),
    textDark: Joi.string().trim().min(1).max(64).optional(),
    primaryDark: Joi.string().trim().min(1).max(64).optional(),
  })
    .unknown(true)
    .required(),
  fonts: Joi.object({
    heading: fontFaceSchema,
    subheading: fontFaceSchema,
    body: fontFaceSchema,
    tertiary: fontFaceSchema,
  })
    .unknown(true)
    .optional(),
  buttons: Joi.object({
    primary: buttonStyleSchema,
    secondary: buttonStyleSchema,
  })
    .unknown(true)
    .optional(),
  voice: Joi.object({
    tone: Joi.string().trim().max(256).allow('', null).optional(),
    audience: Joi.string().trim().max(256).allow('', null).optional(),
    dos: Joi.array().items(Joi.string().trim().max(256)).max(40).optional(),
    donts: Joi.array().items(Joi.string().trim().max(256)).max(40).optional(),
    vocabulary: Joi.array().items(Joi.string().trim().max(128)).max(60).optional(),
  })
    .unknown(true)
    .optional(),
  usage: Joi.object({
    logoClearSpace: Joi.string().trim().max(256).allow('', null).optional(),
    logoMinSizePx: Joi.number().integer().min(8).max(512).optional(),
    doNot: Joi.array().items(Joi.string().trim().max(256)).max(20).optional(),
  })
    .unknown(true)
    .optional(),
  chartStyles: Joi.object({
    colorIds: Joi.array().items(Joi.string().trim().max(64)).max(16).optional(),
  })
    .unknown(true)
    .optional(),
  wordmarks: Joi.object({
    lightTextColorId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
    darkTextColorId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
  })
    .unknown(true)
    .optional(),
  imageStyle: Joi.string().trim().max(512).allow('', null).optional(),
})
  .unknown(true)
  .required();

const listBrandKitsSchema = Joi.object({
  params: Joi.object({ workspaceId: workspaceIdParam }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const createBrandKitSchema = Joi.object({
  params: Joi.object({ workspaceId: workspaceIdParam }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(120).required(),
    data: brandKitDataSchema,
    isDefault: Joi.boolean().optional(),
  }).required(),
  query: Joi.object({}).unknown(false),
});

const brandKitByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    brandKitId: brandKitIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const updateBrandKitSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    brandKitId: brandKitIdParam,
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(120).optional(),
    data: brandKitDataSchema.optional(),
    isDefault: Joi.boolean().optional(),
  })
    .min(1)
    .required(),
  query: Joi.object({}).unknown(false),
});

const uploadBrandKitMediaSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    brandKitId: brandKitIdParam,
  }),
  body: Joi.object({
    kind: Joi.string().valid('logo', 'photo', 'graphic', 'mockup').required(),
    role: Joi.string()
      .valid(
        'primary',
        'secondary',
        'icon',
        'light',
        'dark',
        'main',
        'light-mode',
        'dark-mode',
        'with-name-below',
        'with-name-adjacent',
        'with-name-below-dark',
        'with-name-adjacent-dark',
        'black',
        'white',
        'mug',
        'tshirt',
        'hoodie',
        'tote',
        'cap',
        'business_card',
        'laptop_lid',
        'phone_case',
        'packaging_box',
        'storefront_sign'
      )
      .allow(null, '')
      .optional(),
    name: Joi.string().trim().max(255).allow(null, '').optional(),
  }).required(),
  query: Joi.object({}).unknown(false),
});

const deleteBrandKitMediaSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    brandKitId: brandKitIdParam,
    mediaId: mediaIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const suggestColorsSchema = Joi.object({
  params: Joi.object({ workspaceId: workspaceIdParam }),
  body: Joi.object({
    tone: Joi.string().trim().max(256).allow('', null).optional(),
    tagline: Joi.string().trim().max(256).allow('', null).optional(),
    mediaId: Joi.string().trim().max(64).allow('', null).optional(),
    brandKitId: Joi.string().trim().max(64).allow('', null).optional(),
  })
    .default({})
    .unknown(true),
  query: Joi.object({}).unknown(false),
});

const suggestFontsSchema = Joi.object({
  params: Joi.object({ workspaceId: workspaceIdParam }),
  body: Joi.object({
    tone: Joi.string().trim().max(256).allow('', null).optional(),
    primaryHex: Joi.string()
      .trim()
      .pattern(/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/)
      .allow('', null)
      .optional(),
    brandKitId: Joi.string().trim().max(64).allow('', null).optional(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
});

const suggestVoiceSchema = Joi.object({
  params: Joi.object({ workspaceId: workspaceIdParam }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(120).required(),
    tagline: Joi.string().trim().max(256).allow('', null).optional(),
    tone: Joi.string().trim().max(256).allow('', null).optional(),
    brandKitId: Joi.string().trim().max(64).allow('', null).optional(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
});

const suggestImageStyleSchema = Joi.object({
  params: Joi.object({ workspaceId: workspaceIdParam }),
  body: Joi.object({
    tone: Joi.string().trim().max(256).allow('', null).optional(),
    colors: Joi.array()
      .items(
        Joi.object({
          id: Joi.string().required(),
          hex: hexColor,
          name: Joi.string().optional(),
        })
      )
      .optional(),
    colorRoles: Joi.object().unknown(true).optional(),
    brandKitId: Joi.string().trim().max(64).allow('', null).optional(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
});

const suggestLogoVariantsSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    brandKitId: brandKitIdParam,
  }),
  body: Joi.object({
    applyRoles: Joi.array()
      .items(
        Joi.string().valid(
          'light',
          'dark',
          'black',
          'white',
          'with-name-below',
          'with-name-adjacent',
          'with-name-below-dark',
          'with-name-adjacent-dark',
          'light-mode',
          'dark-mode'
        )
      )
      .optional(),
  }).unknown(false),
  query: Joi.object({}).unknown(false),
});

const generateGuidelineSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    brandKitId: brandKitIdParam,
  }),
  body: Joi.object({
    folderId: Joi.string().uuid().required(),
  }).required(),
  query: Joi.object({}).unknown(false),
});

const mockupTemplateIds = [
  'mug',
  'tshirt',
  'hoodie',
  'tote',
  'cap',
  'business_card',
  'laptop_lid',
  'phone_case',
  'packaging_box',
  'storefront_sign',
];

const apparelMockupTemplateIds = ['tshirt', 'hoodie'];
const apparelLogoPositions = [
  'center_chest',
  'left_chest',
  'full_front',
  'center_back',
  'full_back',
  'back_center',
  'back',
  'rear',
  'rear_center',
  'upper_back',
  'back_full',
  'full_rear',
  'rear_full',
];

const generateMockupSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    brandKitId: brandKitIdParam,
  }),
  body: Joi.object({
    templateId: Joi.string()
      .valid(...mockupTemplateIds)
      .required(),
    itemColor: Joi.string()
      .trim()
      .pattern(/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/)
      .allow('', null)
      .optional(),
    logoRole: Joi.string()
      .valid(
        'primary',
        'secondary',
        'icon',
        'light',
        'dark',
        'main',
        'light-mode',
        'dark-mode',
        'with-name-below',
        'with-name-adjacent',
        'with-name-below-dark',
        'with-name-adjacent-dark',
        'black',
        'white'
      )
      .allow('', null)
      .optional(),
    logoPosition: Joi.when('templateId', {
      is: Joi.valid(...apparelMockupTemplateIds),
      then: Joi.string()
        .valid(...apparelLogoPositions)
        .optional()
        .allow('', null),
      otherwise: Joi.forbidden(),
    }),
    save: Joi.boolean().optional(),
  }).required(),
  query: Joi.object({}).unknown(false),
});

module.exports = {
  brandKitDataSchema,
  listBrandKitsSchema,
  createBrandKitSchema,
  brandKitByIdSchema,
  updateBrandKitSchema,
  uploadBrandKitMediaSchema,
  deleteBrandKitMediaSchema,
  suggestColorsSchema,
  suggestFontsSchema,
  suggestVoiceSchema,
  suggestImageStyleSchema,
  suggestLogoVariantsSchema,
  generateGuidelineSchema,
  generateMockupSchema,
};
