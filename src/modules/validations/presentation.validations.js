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
  layer: Joi.number().integer().min(0).optional(),
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
    aspectRatio: Joi.string().valid('16:9', '4:3').default('16:9'),
    createMode: Joi.string().valid('blank', 'template', 'pack').default('blank'),
    templateId: templateIdField.when('createMode', {
      is: 'template',
      then: Joi.required(),
      otherwise: Joi.optional().allow(null, ''),
    }),
    packId: templateIdField.when('createMode', {
      is: 'pack',
      then: Joi.required(),
      otherwise: Joi.optional().allow(null, ''),
    }),
    brandKitId: Joi.string().trim().min(1).max(64).allow(null, '').optional(),
  }).required(),
  query: Joi.object({}).unknown(false),
});

const listPresentationsSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
  }),
  query: Joi.object({
    folderId: Joi.string().uuid().optional(),
  }),
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
    voiceAndTone: Joi.string().trim().max(64).allow('', null).optional(),
    audience: Joi.string().trim().max(64).allow('', null).optional(),
    purpose: Joi.string().trim().max(64).allow('', null).optional(),
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

const generationFlowSelectionsSchema = Joi.object({
  prompt: Joi.string().trim().max(8000).allow('', null).optional(),
  title: Joi.string().trim().max(255).allow('', null).optional(),
  outlineNotes: Joi.string().trim().max(4000).allow('', null).optional(),
  voiceAndTone: Joi.string().trim().max(64).allow('', null).optional(),
  audience: Joi.string().trim().max(64).allow('', null).optional(),
  purpose: Joi.string().trim().max(64).allow('', null).optional(),
  style: Joi.string().trim().max(128).allow('', null).optional(),
  color: Joi.string().trim().max(64).allow('', null).optional(),
  industries: Joi.array().items(Joi.string().trim().max(64)).max(20).optional(),
  baseTemplate: Joi.string().trim().max(64).allow('', null).optional(),
  colorTheme: Joi.string().trim().max(64).allow('', null).optional(),
  canvasSize: Joi.string().valid('16:9', '4:3').allow('', null).optional(),
  imageType: Joi.string()
    .valid('ai', 'web', 'stock', 'placeholders', 'none')
    .allow('', null)
    .optional(),
  imageStyle: Joi.string().trim().max(64).allow('', null).optional(),
  imageStyleFilter: Joi.string().trim().max(64).allow('', null).optional(),
  textContent: Joi.string().trim().max(64).allow('', null).optional(),
  density: Joi.string().valid('concise', 'balanced', 'detailed').allow('', null).optional(),
  slideCount: Joi.number().integer().min(5).max(AI_SLIDE_MAX).optional(),
  locale: Joi.string().trim().min(2).max(16).allow('', null).optional(),
  packId: Joi.string().trim().min(1).max(64).allow('', null).optional(),
  brandKitId: Joi.string().trim().min(1).max(64).allow('', null).optional(),
}).unknown(true);

const generationFlowSchema = Joi.object({
  version: Joi.number().integer().min(1).default(1),
  source: Joi.string().trim().max(64).allow('', null).optional(),
  selections: generationFlowSelectionsSchema.default({}),
  availableOptions: Joi.object().unknown(true).optional(),
}).unknown(true);

const generateDeckSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    density: Joi.string().valid('concise', 'balanced', 'detailed').optional(),
    overwriteManualEdits: Joi.boolean().default(false),
    requestHash: Joi.string().trim().max(128).optional(),
    generationFlow: generationFlowSchema.optional(),
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
  table: Joi.object({
    headers: Joi.array().items(Joi.string()).optional(),
    rows: Joi.array().items(Joi.array().items(Joi.string())).optional(),
  }).unknown(true).allow(null).optional(),
  members: Joi.array().items(Joi.object({
    name: Joi.string().allow('', null).optional(),
    role: Joi.string().allow('', null).optional(),
    title: Joi.string().allow('', null).optional(),
    email: Joi.string().allow('', null).optional(),
  }).unknown(true)).optional(),
  plans: Joi.array().items(Joi.object({
    label: Joi.string().allow('', null).optional(),
    name: Joi.string().allow('', null).optional(),
    price: Joi.string().allow('', null).optional(),
    items: Joi.array().items(Joi.string()).optional(),
    bullets: Joi.array().items(Joi.string()).optional(),
    highlighted: Joi.boolean().optional(),
  }).unknown(true)).optional(),
  contact: Joi.object({
    address: Joi.string().allow('', null).optional(),
    phone: Joi.string().allow('', null).optional(),
    email: Joi.string().allow('', null).optional(),
  }).unknown(true).allow(null).optional(),
  agenda: Joi.object({
    columns: Joi.array().items(Joi.object({
      heading: Joi.string().allow('', null).optional(),
      items: Joi.array().items(Joi.string()).optional(),
    }).unknown(true)).optional(),
  }).unknown(true).allow(null).optional(),
  comparison: Joi.any().optional(),
  timeline: Joi.any().optional(),
  notes: Joi.string().allow('', null).optional(),
  pathBSpec: Joi.any().optional(),
  background: Joi.object({
    color: Joi.string().allow('', null).optional(),
    imageUrl: Joi.string().uri().allow('', null).optional(),
  })
    .unknown(true)
    .optional(),
}).unknown(true);

const patchSlideSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  body: Joi.object({
    title: Joi.string().allow('', null).optional(),
    content: slideContentSchema.optional(),
    layoutId: Joi.string().trim().max(128).allow(null).optional(),
    contentType: Joi.string().trim().max(64).allow(null).optional(),
    imageRef: Joi.object().unknown(true).allow(null).optional(),
    elements: canvasDocSchema.optional(),
    manuallyEdited: Joi.boolean().optional(),
    background: Joi.object({
      color: Joi.string().allow('', null).optional(),
      imageUrl: Joi.string().allow('', null).optional(),
    })
      .unknown(true)
      .optional(),
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
    title: Joi.string().trim().max(500).allow('', null).optional(),
    content: slideContentSchema.optional(),
    generate: Joi.boolean().default(false),
    prompt: slideAiPromptField.optional(),
    target: Joi.string().valid('content', 'image', 'all', 'full').default('all'),
  })
    .custom((value, helpers) => {
      if (!value || !value.generate) return value;
      const hasPrompt = Boolean(value.prompt && String(value.prompt).trim());
      const hasTitle = Boolean(
        (value.content && value.content.title && String(value.content.title).trim()) ||
          (value.title && String(value.title).trim())
      );
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
    type: Joi.string()
      .valid(...ELEMENT_TYPES)
      .optional(),
    placement: placementSchema.optional(),
    content: Joi.object().unknown(true).optional(),
    role: Joi.string().optional(),
    layer: Joi.number().integer().optional(),
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
    .or('presetId', 'element', 'type')
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
    target: Joi.string().valid('content', 'image', 'all', 'full').default('all'),
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
    category: Joi.string()
      .trim()
      .valid(
        'all',
        'simple_slides',
        'grid',
        'charts_and_data',
        'timeline_and_plans',
        'pricing',
        'agenda',
        'people_and_team',
        'quotes_and_testimonials',
        'device_frames',
        'closing'
      )
      .optional(),
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

const listWorkspacePresentationDeckPacksSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const workspacePresentationDeckPackByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    packId: templateIdField.required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const applyBrandKitSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
  }),
  body: Joi.object({
    brandKitId: Joi.string().trim().min(1).max(64).required(),
  }).required(),
  query: Joi.object({}).unknown(false),
});

const uploadSlideMediaSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    elementId: Joi.string().trim().max(64).allow('', null).optional(),
  }).default({}),
});

const attachSlideAssetSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    assetId: Joi.string().trim().min(1).max(64).required(),
    elementId: Joi.string().trim().max(64).allow('', null).optional(),
  }).required(),
});

const insertSlideStockSchema = Joi.object({
  params: Joi.object({
    workspaceId: workspaceIdParam,
    presentationId: presentationIdParam,
    slideId: slideIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    query: Joi.string().trim().max(256).allow('', null).optional(),
    provider: Joi.string().trim().max(32).allow('', null).optional(),
    externalId: Joi.string().trim().max(128).allow('', null).optional(),
    elementId: Joi.string().trim().max(64).allow('', null).optional(),
  })
    .or('query', 'externalId')
    .required(),
});

const slotRoleSchema = Joi.string()
  .trim()
  .valid(
    'heading',
    'subheading',
    'body',
    'caption',
    'stat',
    'stat_label',
    'decoration',
    'background',
    'image',
    'chart',
    'table',
    'quote',
    'attribution',
    'cta',
    'contact',
    'eyebrow',
    'divider'
  )
  .optional();

const colorRoleSchema = Joi.string()
  .trim()
  .valid(
    'bg',
    'surface',
    'primary',
    'secondary',
    'text',
    'muted',
    'accent',
    'divider',
    'cardBg',
    'gradientStart',
    'gradientEnd',
    'textOnImage',
    'textOnImageMuted',
    'overlayScrim'
  )
  .optional();

const gradientFillSchema = Joi.object({
  type: Joi.string().valid('gradient').required(),
  direction: Joi.string().trim().max(32).optional(),
  stops: Joi.array()
    .items(
      Joi.object({
        color: Joi.string().trim().max(64).optional(),
        colorRole: colorRoleSchema,
        position: Joi.number().min(0).max(100).optional(),
      }).unknown(true)
    )
    .min(2)
    .max(8)
    .required(),
}).unknown(true);

const solidFillSchema = Joi.object({
  type: Joi.string().valid('solid').required(),
  color: Joi.string().trim().max(64).optional(),
  colorRole: colorRoleSchema,
}).unknown(true);

const slotShapeSchema = Joi.object({
  type: Joi.string().trim().valid('rect', 'ellipse', 'line').default('rect'),
  fillColorRole: colorRoleSchema,
  fill: Joi.alternatives().try(gradientFillSchema, solidFillSchema, Joi.string().trim()).optional(),
  borderRadius: Joi.number().min(0).max(200).optional(),
}).unknown(true);

const slotTypographySchema = Joi.object({
  fontSize: Joi.number().integer().min(8).max(200).optional(),
  fontWeight: Joi.number().integer().min(100).max(900).optional(),
  letterSpacing: Joi.number().min(-0.2).max(0.5).optional(),
  lineHeight: Joi.number().min(0.8).max(3).optional(),
  align: Joi.string().valid('left', 'center', 'right').optional(),
  colorRole: colorRoleSchema,
}).unknown(true);

/** Strict DECK_LAYOUT schema for superadmin / seed */
const deckLayoutSlotSchema = Joi.object({
  id: Joi.string().trim().required(),
  region: Joi.string().trim().required(),
  role: slotRoleSchema,
  typography: slotTypographySchema.optional(),
  shape: slotShapeSchema.optional(),
  layer: Joi.number().integer().min(-10).max(100).optional(),
  placeholder_text: Joi.string().trim().max(500).allow('', null).optional(),
  max_lines: Joi.number().integer().min(1).optional(),
  max_words: Joi.number().integer().min(1).optional(),
  max_items: Joi.number().integer().min(1).optional(),
  fit: Joi.string().trim().optional(),
  crop: Joi.string().trim().optional(),
}).unknown(true);

const deckLayoutTemplateSchemaObject = Joi.object({
  schemaVersion: Joi.number().integer().min(1).max(10).optional(),
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

const designTokensSchema = Joi.object({
  backgroundStyle: Joi.string().valid('solid', 'gradient', 'image', 'split').optional(),
  accentPosition: Joi.string()
    .valid('none', 'left-bar', 'top-bar', 'bottom-bar', 'corner')
    .optional(),
  imagePosition: Joi.string()
    .valid('none', 'left-half', 'right-half', 'full-bleed', 'top-third', 'avatar-grid')
    .optional(),
  overlayOpacity: Joi.number().min(0).max(1).optional(),
  textContrast: Joi.string().valid('normal', 'high').optional(),
})
  .unknown(true)
  .optional();

const generationHintsSchema = Joi.object({
  maxTitleWords: Joi.number().integer().min(1).max(40).optional(),
  maxBodyWords: Joi.number().integer().min(1).max(200).optional(),
  maxLines: Joi.number().integer().min(1).max(20).optional(),
  itemCountMin: Joi.number().integer().min(1).max(20).optional(),
  itemCountMax: Joi.number().integer().min(1).max(20).optional(),
  titleLength: Joi.string().trim().max(256).optional(),
  subtitleLength: Joi.string().trim().max(256).optional(),
  bodyLength: Joi.string().trim().max(256).optional(),
  itemCount: Joi.string().trim().max(64).optional(),
  itemLength: Joi.string().trim().max(256).optional(),
  avoidClichés: Joi.array().items(Joi.string().trim().max(64)).max(20).optional(),
  avoidCliches: Joi.array().items(Joi.string().trim().max(64)).max(20).optional(),
  statFormat: Joi.string().trim().max(256).optional(),
  labelLength: Joi.string().trim().max(256).optional(),
  calloutLength: Joi.string().trim().max(256).optional(),
  titleTone: Joi.string().trim().max(256).optional(),
  ctaFormat: Joi.string().trim().max(256).optional(),
  imagePromptStyle: Joi.string().trim().max(256).optional(),
  parallelStructure: Joi.string().trim().max(256).optional(),
  pointCount: Joi.string().trim().max(64).optional(),
  pointLength: Joi.string().trim().max(256).optional(),
  bioLength: Joi.string().trim().max(256).optional(),
  nameFormat: Joi.string().trim().max(256).optional(),
  chartDataStyle: Joi.string().trim().max(256).optional(),
  sourceNote: Joi.string().trim().max(256).optional(),
})
  .unknown(true)
  .optional();

const deckPackSlideSnapshotSchema = Joi.object({
  elements: Joi.object({
    version: Joi.number().optional(),
    canvas: Joi.object().unknown(true).optional(),
    elements: Joi.array().items(Joi.object().unknown(true)).optional(),
  })
    .unknown(true)
    .required(),
  imageS3Key: Joi.string().trim().max(1024).allow('', null).optional(),
})
  .unknown(true)
  .optional();

const deckPackSlideSchema = Joi.object({
  order: Joi.number().integer().min(1).required(),
  layout_id: Joi.string().trim().allow('', null).optional(),
  contentType: Joi.string().trim().max(64).required(),
  intent: Joi.string().trim().max(280).allow('', null).optional(),
  designTokens: designTokensSchema,
  generationHints: generationHintsSchema,
  placeholder: Joi.object().unknown(true).default({}),
  snapshot: deckPackSlideSnapshotSchema,
})
  .unknown(true)
  .custom((value, helpers) => {
    const hasLayout = Boolean(value.layout_id && String(value.layout_id).trim());
    const hasSnapshot = Boolean(value.snapshot?.elements);
    if (!hasLayout && !hasSnapshot) {
      return helpers.message('Each pack slide requires layout_id or snapshot.elements');
    }
    return value;
  });

const contentDistributionSchema = Joi.object({
  maxConsecutiveBulletSlides: Joi.number().integer().min(0).max(10).optional(),
  requireStatSlide: Joi.boolean().optional(),
  requireImageSlide: Joi.boolean().optional(),
  requireChartSlide: Joi.boolean().optional(),
  requireComparisonSlide: Joi.boolean().optional(),
})
  .unknown(true)
  .optional();

const deckPackTemplateSchemaObject = Joi.object({
  schemaVersion: Joi.number().integer().min(1).max(10).optional(),
  pack_id: Joi.string().trim().required(),
  themeId: Joi.string().trim().max(64).allow(null, '').optional(),
  aspectRatio: Joi.string().valid('16:9', '4:3').default('16:9'),
  meta: Joi.object({
    name: Joi.string().trim().max(255).optional(),
    description: Joi.string().trim().max(2000).optional(),
    useCase: Joi.string().trim().max(64).optional(),
    audience: Joi.string().trim().max(128).optional(),
    tone: Joi.string().trim().max(256).optional(),
    industry: Joi.array().items(Joi.string().trim().max(64)).max(20).optional(),
    authoredVia: Joi.string().trim().max(64).optional(),
    aiReady: Joi.boolean().optional(),
  })
    .unknown(true)
    .optional(),
  narrative: Joi.object({
    arc: Joi.string().trim().max(128).optional(),
    summary: Joi.string().trim().max(2000).optional(),
  })
    .unknown(true)
    .optional(),
  slides: Joi.array().items(deckPackSlideSchema).min(1).max(40).required(),
  generationDefaults: Joi.object({
    baseTemplate: Joi.string().trim().max(64).optional(),
    imageStyle: Joi.string().trim().max(128).optional(),
    preferVisuals: Joi.boolean().optional(),
    density: Joi.string().valid('concise', 'balanced', 'detailed').optional(),
    imageType: Joi.string().trim().max(32).optional(),
    slideCount: Joi.number().integer().min(1).max(40).optional(),
    locale: Joi.string().trim().max(16).optional(),
    layoutWhitelist: Joi.array().items(Joi.string().trim().max(128)).max(40).optional(),
    slideOrder: Joi.string().valid('fixed', 'flexible').optional(),
    titleSlide: Joi.object({
      layout_id: Joi.string().trim().optional(),
      alwaysFirst: Joi.boolean().optional(),
    })
      .unknown(true)
      .optional(),
    closingSlide: Joi.object({
      layout_id: Joi.string().trim().optional(),
      alwaysLast: Joi.boolean().optional(),
    })
      .unknown(true)
      .optional(),
    contentDistribution: contentDistributionSchema,
  })
    .unknown(true)
    .optional(),
  preview: Joi.object({
    label: Joi.string().trim().max(255).optional(),
    color: Joi.string().trim().max(32).optional(),
    accentColor: Joi.string().trim().max(32).optional(),
    description: Joi.string().trim().max(2000).optional(),
    useCase: Joi.string().trim().max(64).optional(),
    slideCount: Joi.number().integer().min(1).max(40).optional(),
    tags: Joi.array().items(Joi.string().trim().max(64)).max(20).optional(),
  })
    .unknown(true)
    .optional(),
  scene: Joi.forbidden(),
  videoSettings: Joi.forbidden(),
})
  .unknown(true)
  .required();

function assertDeckPackTemplateSchema(schema) {
  const { error, value } = deckPackTemplateSchemaObject.validate(schema, {
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
  listPresentationsSchema,
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
  listWorkspacePresentationDeckPacksSchema,
  workspacePresentationDeckPackByIdSchema,
  applyBrandKitSchema,
  uploadSlideMediaSchema,
  attachSlideAssetSchema,
  insertSlideStockSchema,
  deckLayoutTemplateSchemaObject,
  assertDeckLayoutTemplateSchema,
  deckPackTemplateSchemaObject,
  assertDeckPackTemplateSchema,
  canvasDocSchema,
};
