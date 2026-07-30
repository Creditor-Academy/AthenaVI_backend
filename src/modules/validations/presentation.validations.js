const Joi = require('joi');
const {
  AI_SLIDE_MAX,
  MAX_ELEMENTS_PER_SLIDE,
  ELEMENT_TYPES,
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
} = require('../presentation/presentation.constants');

const presentationIdParam = Joi.string().required();
const workspaceIdParam = Joi.string().uuid().required();
const slideIdParam = Joi.string().required();
const exportIdParam = Joi.string().required();
const elementIdParam = Joi.string().required();
const templateIdField = Joi.string().trim().min(1);

const densityField = Joi.string().valid('concise', 'balanced', 'detailed').default('balanced');
const localeField = Joi.string().trim().min(2).max(16).default('en');
const slideCountField = Joi.number().integer().min(5).max(AI_SLIDE_MAX);

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
  slides: Joi.array().items(outlineSlideSchema).min(1).max(AI_SLIDE_MAX).required(),
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

const placementSchema = Joi.object({
  x: Joi.number().required(),
  y: Joi.number().required(),
  width: Joi.number().positive().required(),
  height: Joi.number().positive().required(),
  rotation: Joi.number().optional(),
  opacity: Joi.number().min(0).max(1).optional(),
}).unknown(true);

const canvasElementSchema = Joi.object({
  id: Joi.string().trim().required(),
  type: Joi.string()
    .valid(...ELEMENT_TYPES)
    .required(),
  layer: Joi.number().integer().min(1).optional(),
  placement: placementSchema.required(),
  content: Joi.object().unknown(true).optional(),
  role: Joi.string().trim().allow('', null).optional(),
}).unknown(true);

const canvasDocSchema = Joi.object({
  version: Joi.number().integer().min(1).default(1),
  canvas: Joi.object({
    width: Joi.number().integer().min(1).default(CANVAS_WIDTH),
    height: Joi.number().integer().min(1).default(CANVAS_HEIGHT),
  })
    .default({ width: CANVAS_WIDTH, height: CANVAS_HEIGHT })
    .unknown(true),
  elements: Joi.array().items(canvasElementSchema).max(MAX_ELEMENTS_PER_SLIDE).required(),
}).unknown(true);

const createPresentationSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
  }),
  body: Joi.object({
    title: Joi.string().trim().min(1).max(255).optional().allow(null, ''),
    name: Joi.string().trim().min(1).max(255).optional().allow(null, ''),
    folderId: Joi.string().uuid().required(),
    themeId: Joi.string().trim().max(64).allow(null).optional(),
    themeTokens: themeTokensSchema.allow(null).optional(),
    locale: localeField.optional(),
    aspectRatio: Joi.string().valid('16:9').default('16:9'),
    createMode: Joi.string().valid('blank', 'template').default('blank'),
    templateId: templateIdField.when('createMode', {
      is: 'template',
      then: Joi.required(),
      otherwise: Joi.optional().allow(null, ''),
    }),
  }).required(),
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
    elements: canvasDocSchema.optional(),
    manuallyEdited: Joi.boolean().optional(),
  })
    .min(1)
    .required(),
});

const slideAiPromptField = Joi.string().trim().min(1).max(2000);

const addSlideSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    afterSlideId: Joi.string().trim().optional(),
    templateId: templateIdField.optional(),
    layoutId: Joi.string().trim().max(128).optional(),
    content: slideContentSchema.optional(),
    generate: Joi.boolean().default(false),
    prompt: slideAiPromptField.optional(),
    target: Joi.string().valid('content', 'image', 'all').default('all'),
  })
    .custom((value, helpers) => {
      if (!value || !value.generate) return value;
      const hasPrompt = Boolean(value.prompt && String(value.prompt).trim());
      const hasTitle = Boolean(value.content && value.content.title && String(value.content.title).trim());
      if (!hasPrompt && !hasTitle) {
        return helpers.message('When generate is true, provide prompt or content.title');
      }
      return value;
    })
    .default({})
    .optional(),
});

const slideByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
});

const reorderSlidesSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    slideIds: Joi.array().items(Joi.string().required()).min(1).required(),
  }).required(),
});

const applyLayoutSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  body: Joi.object({
    templateId: templateIdField.required(),
  }).required(),
});

const putCanvasSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  body: canvasDocSchema.required(),
});

const addElementSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  body: Joi.object({
    presetId: Joi.string().trim().optional(),
    element: Joi.object({
      type: Joi.string()
        .valid(...ELEMENT_TYPES)
        .optional(),
      placement: placementSchema.optional(),
      content: Joi.object().unknown(true).optional(),
      role: Joi.string().optional(),
      layer: Joi.number().integer().optional(),
    })
      .unknown(true)
      .optional(),
  })
    .or('presetId', 'element')
    .required(),
});

const patchElementSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
    elementId: elementIdParam,
  }),
  body: Joi.object({
    type: Joi.string()
      .valid(...ELEMENT_TYPES)
      .optional(),
    placement: placementSchema.optional(),
    content: Joi.object().unknown(true).optional(),
    role: Joi.string().optional(),
    layer: Joi.number().integer().optional(),
  })
    .min(1)
    .unknown(true)
    .required(),
});

const elementByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
    elementId: elementIdParam,
  }),
});

const reorderElementsSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  body: Joi.object({
    elementIds: Joi.array().items(Joi.string().required()).min(1).required(),
  }).required(),
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
    prompt: slideAiPromptField.optional(),
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
    format: Joi.string().valid('PPTX', 'PDF', 'PNG', 'JPEG').required(),
    slideId: Joi.string().trim().optional(),
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

const listWorkspacePresentationTemplatesSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
  }),
  query: Joi.object({
    contentType: Joi.string().trim().max(64).optional(),
  }).default({}),
  body: Joi.object({}).unknown(false),
});

const listWorkspacePresentationThemesSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const listWorkspacePresentationElementsSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

/** Strict DECK_LAYOUT schema for superadmin / seed */
const deckLayoutSlotSchema = Joi.object({
  id: Joi.string().trim().required(),
  region: Joi.string().trim().required(),
  max_lines: Joi.number().integer().min(1).optional(),
  max_words: Joi.number().integer().min(1).optional(),
  max_items: Joi.number().integer().min(1).optional(),
  fit: Joi.string().trim().optional(),
  crop: Joi.string().trim().optional(),
}).unknown(true);

const deckLayoutTemplateSchemaObject = Joi.object({
  layout_id: Joi.string().trim().required(),
  content_type: Joi.string().trim().required(),
  grid: Joi.string().trim().required(),
  slots: Joi.array().items(deckLayoutSlotSchema).min(1).required(),
  scene: Joi.forbidden(),
  videoSettings: Joi.forbidden(),
  elements: Joi.forbidden(),
  clips: Joi.forbidden(),
})
  .unknown(true)
  .required();

function assertDeckLayoutTemplateSchema(schema) {
  const { error, value } = deckLayoutTemplateSchemaObject.validate(schema, {
    abortEarly: false,
    stripUnknown: false,
  });
  if (error) {
    const details = error.details.map((d) => d.message.replace(/"/g, '')).join('; ');
    const err = new Error(details);
    err.isJoi = true;
    err.statusCode = 400;
    throw err;
  }
  return value;
}

const templateIdParam = Joi.string().trim().min(1).required();

const createPresentationTemplateSchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    contentType: Joi.string().trim().max(64).allow(null, '').optional(),
    variant: Joi.string().trim().max(64).allow(null, '').optional(),
    schema: deckLayoutTemplateSchemaObject.required(),
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
    schema: deckLayoutTemplateSchemaObject.optional(),
    isActive: Joi.boolean().optional(),
  })
    .min(1)
    .required(),
});

module.exports = {
  AI_SLIDE_MAX,
  createPresentationSchema,
  presentationByIdSchema,
  generateOutlineSchema,
  patchOutlineSchema,
  setThemeSchema,
  generateDeckSchema,
  patchSlideSchema,
  addSlideSchema,
  slideByIdSchema,
  reorderSlidesSchema,
  applyLayoutSchema,
  putCanvasSchema,
  addElementSchema,
  patchElementSchema,
  elementByIdSchema,
  reorderElementsSchema,
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
  listWorkspacePresentationTemplatesSchema,
  listWorkspacePresentationThemesSchema,
  listWorkspacePresentationElementsSchema,
  deckLayoutTemplateSchemaObject,
  assertDeckLayoutTemplateSchema,
  canvasDocSchema,
};
