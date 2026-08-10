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
}).optional();

const brandKitDataSchema = Joi.object({
  colors: Joi.array().items(colorEntrySchema).min(2).max(32).required(),
  colorRoles: Joi.object({
    bg: Joi.string().trim().min(1).max(64).required(),
    text: Joi.string().trim().min(1).max(64).required(),
    primary: Joi.string().trim().min(1).max(64).required(),
    secondary: Joi.string().trim().min(1).max(64).optional(),
    accent: Joi.string().trim().min(1).max(64).optional(),
    muted: Joi.string().trim().min(1).max(64).optional(),
  })
    .unknown(true)
    .required(),
  fonts: Joi.object({
    heading: fontFaceSchema,
    body: fontFaceSchema,
    tertiary: fontFaceSchema,
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
  chartStyles: Joi.object({
    colorIds: Joi.array().items(Joi.string().trim().max(64)).max(16).optional(),
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
    kind: Joi.string().valid('logo', 'photo', 'graphic').required(),
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
        'black',
        'white'
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

module.exports = {
  brandKitDataSchema,
  listBrandKitsSchema,
  createBrandKitSchema,
  brandKitByIdSchema,
  updateBrandKitSchema,
  uploadBrandKitMediaSchema,
  deleteBrandKitMediaSchema,
};
