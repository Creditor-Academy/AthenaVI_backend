const Joi = require('joi');

const presentationIdParam = Joi.string().required();
const workspaceIdParam = Joi.string().uuid().required();
const slideIdParam = Joi.string().required();
const exportIdParam = Joi.string().required();

const densityField = Joi.string().valid('concise', 'balanced', 'detailed').default('balanced');
const localeField = Joi.string().trim().min(2).max(16).default('en');
const slideCountField = Joi.number().integer().min(5).max(20);

const outlineSlideSchema = Joi.object({
  order: Joi.number().integer().min(1).required(),
  title: Joi.string().trim().min(1).max(500).required(),
  summary: Joi.string().trim().allow('', null).max(2000).optional(),
  suggestedContentType: Joi.string().trim().max(64).allow(null).optional(),
}).unknown(true);

const outlineObjectSchema = Joi.object({
  title: Joi.string().trim().min(1).max(500).required(),
  slideCount: slideCountField.required(),
  density: densityField,
  locale: localeField.optional(),
  slides: Joi.array().items(outlineSlideSchema).min(1).max(20).required(),
}).unknown(true);

const themeTokensSchema = Joi.object({
  palette: Joi.object({
    bg: Joi.string().required(),
    text: Joi.string().required(),
    surface: Joi.string().optional(),
    primary: Joi.string().optional(),
    secondary: Joi.string().optional(),
    muted: Joi.string().optional(),
  })
    .unknown(true)
    .required(),
  fontPairingId: Joi.string().optional(),
  typeScale: Joi.object().unknown(true).optional(),
  spacingScale: Joi.object().unknown(true).optional(),
  imageStyle: Joi.string().allow('', null).optional(),
  colorTreatment: Joi.string().allow('', null).optional(),
}).unknown(true);

const createPresentationSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
  }),
  body: Joi.object({
    title: Joi.string().trim().min(1).max(255),
    name: Joi.string().trim().min(1).max(255),
    folderId: Joi.string().uuid().required(),
    themeId: Joi.string().trim().max(64).allow(null).optional(),
    themeTokens: themeTokensSchema.allow(null).optional(),
    locale: localeField.optional(),
    aspectRatio: Joi.string().valid('16:9').default('16:9'),
  })
    .or('title', 'name')
    .required(),
  query: Joi.object({}).unknown(false),
});

const presentationByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
});

const generateOutlineSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    source: Joi.string().valid('prompt', 'outline', 'document').required(),
    prompt: Joi.string().trim().min(1).max(8000).when('source', {
      is: 'prompt',
      then: Joi.required(),
      otherwise: Joi.optional().allow('', null),
    }),
    outlineText: Joi.string().trim().min(1).max(50_000).when('source', {
      is: 'outline',
      then: Joi.required(),
      otherwise: Joi.optional().allow('', null),
    }),
    // document: multipart file handled by multer; optional text fields still allowed
    documentText: Joi.string().trim().min(1).max(100_000).optional(),
    slideCount: slideCountField.default(12),
    density: densityField,
    locale: localeField,
  }).required(),
});

const patchOutlineSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: outlineObjectSchema.required(),
});

const setThemeSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    themeId: Joi.string().trim().max(64).allow(null).optional(),
    themeTokens: themeTokensSchema.allow(null).optional(),
  })
    .or('themeId', 'themeTokens')
    .required(),
});

const generateDeckSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    density: densityField,
    overwriteManualEdits: Joi.boolean().default(false),
    requestHash: Joi.string().trim().max(128).optional(),
  })
    .default({})
    .optional(),
});

const slideContentSchema = Joi.object({
  title: Joi.string().allow('', null).optional(),
  subtitle: Joi.string().allow('', null).optional(),
  body: Joi.string().allow('', null).optional(),
  bullets: Joi.array().items(Joi.alternatives().try(Joi.string(), Joi.object().unknown(true))).optional(),
  stats: Joi.array().items(Joi.object().unknown(true)).optional(),
  quote: Joi.string().allow('', null).optional(),
  chart: Joi.object().unknown(true).allow(null).optional(),
  comparison: Joi.any().optional(),
  timeline: Joi.any().optional(),
  notes: Joi.string().allow('', null).optional(),
  pathBSpec: Joi.any().optional(),
}).unknown(true);

const patchSlideSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  body: Joi.object({
    content: slideContentSchema.optional(),
    layoutId: Joi.string().trim().max(128).allow(null).optional(),
    contentType: Joi.string().trim().max(64).allow(null).optional(),
    imageRef: Joi.object().unknown(true).allow(null).optional(),
    manuallyEdited: Joi.boolean().optional(),
  })
    .min(1)
    .required(),
});

const regenerateSlideSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  body: Joi.object({
    target: Joi.string().valid('content', 'image', 'all').default('all'),
    overwriteManualEdits: Joi.boolean().default(true),
  })
    .default({})
    .optional(),
});

const exportDeckSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    format: Joi.string().valid('PPTX', 'PDF').required(),
  }).required(),
});

const exportByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    exportId: exportIdParam,
  }),
});

const creditEstimateSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  query: Joi.object({
    slideCount: slideCountField.optional(),
  }).default({}),
});

const templateIdParam = Joi.string().trim().min(1).required();

const createPresentationTemplateSchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    contentType: Joi.string().trim().max(64).allow(null, '').optional(),
    variant: Joi.string().trim().max(64).allow(null, '').optional(),
    schema: Joi.object().unknown(true).required(),
    type: Joi.string().valid('DECK_LAYOUT').default('DECK_LAYOUT'),
    isActive: Joi.boolean().default(true),
    version: Joi.number().integer().min(1).default(1),
  }).required(),
});

const listPresentationTemplatesSchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    type: Joi.string().valid('DECK_LAYOUT').optional(),
    contentType: Joi.string().trim().max(64).optional(),
    isActive: Joi.boolean().optional(),
  }).default({}),
  body: Joi.object({}).unknown(false),
});

const presentationTemplateIdParamsSchema = Joi.object({
  params: Joi.object({
    templateId: templateIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const updatePresentationTemplateSchema = Joi.object({
  params: Joi.object({
    templateId: templateIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).optional(),
    schema: Joi.object().unknown(true).optional(),
    isActive: Joi.boolean().optional(),
  })
    .min(1)
    .required(),
});

module.exports = {
  createPresentationSchema,
  presentationByIdSchema,
  generateOutlineSchema,
  patchOutlineSchema,
  setThemeSchema,
  generateDeckSchema,
  patchSlideSchema,
  regenerateSlideSchema,
  exportDeckSchema,
  exportByIdSchema,
  creditEstimateSchema,
  outlineObjectSchema,
  themeTokensSchema,
  listPresentationTemplatesSchema,
  presentationTemplateIdParamsSchema,
  createPresentationTemplateSchema,
  updatePresentationTemplateSchema,
};
