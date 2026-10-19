const Joi = require('joi');
const { ELEMENT_TYPES, DEFAULT_VIDEO_SETTINGS } = require('../../shared/constants/videoEditor');

const uuidParam = Joi.string().uuid().required();
const templateIdParam = Joi.string().trim().min(1).required();

/** Element shape for VIDEO_SCENE blueprints (aligned with editor elements). */
const blueprintElementSchema = Joi.object({
  id: Joi.string().trim().required(),
  type: Joi.string()
    .valid(...ELEMENT_TYPES)
    .required(),
  layer: Joi.number().integer().required(),
  startFrame: Joi.number().integer().min(0).optional(),
  durationInFrames: Joi.number().integer().min(1).optional(),
  timing: Joi.object({
    startFrame: Joi.number().integer().min(0).required(),
    durationInFrames: Joi.number().integer().min(1).required(),
  })
    .unknown(true)
    .optional(),
  placement: Joi.object({
    x: Joi.number().optional(),
    y: Joi.number().optional(),
    width: Joi.number().positive().optional(),
    height: Joi.number().positive().optional(),
    rotation: Joi.number().optional(),
    scale: Joi.number().positive().optional(),
    opacity: Joi.number().min(0).max(1).optional(),
  })
    .unknown(true)
    .optional(),
  content: Joi.object().unknown(true).optional(),
  style: Joi.object().unknown(true).optional(),
  role: Joi.string().trim().optional(),
})
  .unknown(true)
  .custom((value, helpers) => {
    const timing = value.timing && typeof value.timing === 'object' ? value.timing : {};
    const startFrame = value.startFrame != null ? value.startFrame : timing.startFrame;
    const durationInFrames =
      value.durationInFrames != null ? value.durationInFrames : timing.durationInFrames;
    if (startFrame == null || durationInFrames == null) {
      return helpers.message(
        'Each element requires startFrame and durationInFrames (or timing.*)'
      );
    }
    return value;
  });

/** Scene blueprint — no sceneId (generated on apply). Rejects deck-style slots/grid. */
const videoSceneBlueprintSceneSchema = Joi.object({
  name: Joi.string().trim().max(255).optional(),
  order: Joi.number().integer().min(0).optional(),
  durationInFrames: Joi.number().integer().min(1).required(),
  locked: Joi.boolean().optional(),
  layout: Joi.string().trim().optional(),
  background: Joi.object({
    type: Joi.string().trim().required(),
    value: Joi.alternatives().try(Joi.string(), Joi.number(), Joi.object().unknown(true)).optional(),
  })
    .unknown(true)
    .required(),
  elements: Joi.array().items(blueprintElementSchema).min(1).required(),
  clips: Joi.forbidden(),
  slots: Joi.forbidden(),
  grid: Joi.forbidden(),
})
  .unknown(true)
  .required();

const videoSettingsSchema = Joi.object({
  width: Joi.number().integer().min(1).default(DEFAULT_VIDEO_SETTINGS.width),
  height: Joi.number().integer().min(1).default(DEFAULT_VIDEO_SETTINGS.height),
  fps: Joi.number().integer().min(1).default(DEFAULT_VIDEO_SETTINGS.fps),
  backgroundColor: Joi.string().trim().optional(),
}).unknown(true);

const videoSceneTemplateSchemaObject = Joi.object({
  version: Joi.number().integer().min(1).default(1),
  videoSettings: videoSettingsSchema.optional(),
  scene: videoSceneBlueprintSceneSchema,
  meta: Joi.object({
    authoredVia: Joi.string().trim().max(64).optional(),
    name: Joi.string().trim().max(255).optional(),
    description: Joi.string().trim().max(2000).optional(),
  })
    .unknown(true)
    .optional(),
  slots: Joi.forbidden(),
  grid: Joi.forbidden(),
  layout_id: Joi.forbidden(),
})
  .unknown(true)
  .required();

function assertVideoSceneTemplateSchema(schema) {
  const { error, value } = videoSceneTemplateSchemaObject.validate(schema, {
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

/** Full editor scene snapshot for VIDEO_PACK (looser than VIDEO_SCENE blueprint). */
const videoPackSceneSchema = Joi.object({
  sceneId: Joi.string().trim().optional(),
  name: Joi.string().trim().max(255).optional(),
  order: Joi.number().integer().min(0).optional(),
  durationInFrames: Joi.number().integer().min(1).required(),
  locked: Joi.boolean().optional(),
  layout: Joi.string().trim().optional(),
  templateId: Joi.string().trim().optional(),
  background: Joi.object().unknown(true).required(),
  elements: Joi.array().items(Joi.object().unknown(true)).min(1).required(),
})
  .unknown(true)
  .required();

const videoPackTemplateSchemaObject = Joi.object({
  schemaVersion: Joi.number().integer().min(1).max(10).default(1),
  pack_id: Joi.string().trim().required(),
  meta: Joi.object({
    authoredVia: Joi.string().trim().max(64).optional(),
    name: Joi.string().trim().max(255).optional(),
    description: Joi.string().trim().max(2000).optional(),
  })
    .unknown(true)
    .optional(),
  videoSettings: videoSettingsSchema.optional(),
  scenes: Joi.array().items(videoPackSceneSchema).min(1).max(80).required(),
  preview: Joi.object({
    label: Joi.string().trim().max(255).optional(),
    sceneCount: Joi.number().integer().min(1).max(80).optional(),
    description: Joi.string().trim().max(2000).optional(),
  })
    .unknown(true)
    .optional(),
  scene: Joi.forbidden(),
  slots: Joi.forbidden(),
  grid: Joi.forbidden(),
  layout_id: Joi.forbidden(),
})
  .unknown(true)
  .required();

function assertVideoPackTemplateSchema(schema) {
  const { error, value } = videoPackTemplateSchemaObject.validate(schema, {
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

const listWorkspaceVideoTemplatesSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  query: Joi.object({
    contentType: Joi.string().trim().max(64).optional(),
    type: Joi.string().valid('VIDEO_SCENE', 'VIDEO_PACK').optional(),
  }).default({}),
  body: Joi.object({}).unknown(false),
});

const workspaceVideoTemplateByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    templateId: templateIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const appendSceneFromTemplateSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    templateId: templateIdParam,
  }).required(),
});

const createVideoTemplateAdminSchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    contentType: Joi.string().trim().max(64).allow(null, '').optional(),
    variant: Joi.string().trim().max(64).allow(null, '').optional(),
    schema: videoSceneTemplateSchemaObject.required(),
    type: Joi.string().valid('VIDEO_SCENE').default('VIDEO_SCENE'),
    isActive: Joi.boolean().default(true),
    version: Joi.number().integer().min(1).default(1),
  }).required(),
});

const updateVideoTemplateAdminSchema = Joi.object({
  params: Joi.object({
    templateId: templateIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).optional(),
    schema: videoSceneTemplateSchemaObject.optional(),
    isActive: Joi.boolean().optional(),
  })
    .min(1)
    .required(),
});

/** Superadmin create: type required; schema validated in service by type. */
const createTemplateAdminBodySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    contentType: Joi.string().trim().max(64).allow(null, '').optional(),
    variant: Joi.string().trim().max(64).allow(null, '').optional(),
    schema: Joi.object().unknown(true).required(),
    type: Joi.string().valid('DECK_LAYOUT', 'VIDEO_SCENE', 'DECK_PACK', 'VIDEO_PACK').required(),
    isActive: Joi.boolean().default(true),
    version: Joi.number().integer().min(1).default(1),
  }).required(),
});

const listTemplatesAdminSchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    type: Joi.string().valid('DECK_LAYOUT', 'VIDEO_SCENE', 'DECK_PACK', 'VIDEO_PACK').optional(),
    contentType: Joi.string().trim().max(64).optional(),
    isActive: Joi.boolean().optional(),
  }).default({}),
  body: Joi.object({}).unknown(false),
});

const templateIdAdminParamsSchema = Joi.object({
  params: Joi.object({
    templateId: templateIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const updateTemplateAdminSchema = Joi.object({
  params: Joi.object({
    templateId: templateIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).optional(),
    schema: Joi.object().unknown(true).optional(),
    isActive: Joi.boolean().optional(),
    contentType: Joi.string().trim().max(64).allow(null, '').optional(),
    variant: Joi.string().trim().max(64).allow(null, '').optional(),
  })
    .min(1)
    .required(),
});

const templateMediaIdAdminParamsSchema = Joi.object({
  params: Joi.object({
    templateId: templateIdParam,
    mediaId: Joi.string().trim().min(1).required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({}).unknown(false),
});

const uploadTemplateMediaAdminSchema = Joi.object({
  params: Joi.object({
    templateId: templateIdParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    kind: Joi.string().valid('photo', 'preview', 'graphic').default('photo'),
    slotHint: Joi.string().trim().max(128).allow('', null).optional(),
    name: Joi.string().trim().max(255).allow('', null).optional(),
    setAsPreview: Joi.boolean().optional(),
  }).default({}),
});

const publishPresentationAsPackSchema = Joi.object({
  params: Joi.object({
    presentationId: uuidParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    packId: Joi.string().trim().min(1).max(128).required(),
    themeId: Joi.string().trim().max(64).allow('', null).optional(),
    isActive: Joi.boolean().default(true),
    variant: Joi.string().trim().max(64).allow('', null).optional(),
    contentType: Joi.string().trim().max(64).allow('', null).optional(),
    description: Joi.string().trim().max(2000).allow('', null).optional(),
  }).required(),
});

const publishProjectSceneAsTemplateSchema = Joi.object({
  params: Joi.object({
    projectId: uuidParam,
    sceneId: Joi.string().trim().min(1).required(),
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    contentType: Joi.string().trim().max(64).allow('', null).optional(),
    variant: Joi.string().trim().max(64).allow('', null).optional(),
    isActive: Joi.boolean().default(true),
  }).required(),
});

const publishProjectAsVideoPackSchema = Joi.object({
  params: Joi.object({
    projectId: uuidParam,
  }),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    packId: Joi.string().trim().min(1).max(128).required(),
    isActive: Joi.boolean().default(true),
    variant: Joi.string().trim().max(64).allow('', null).optional(),
    contentType: Joi.string().trim().max(64).allow('', null).optional(),
    description: Joi.string().trim().max(2000).allow('', null).optional(),
  }).required(),
});

module.exports = {
  videoSceneTemplateSchemaObject,
  assertVideoSceneTemplateSchema,
  videoPackTemplateSchemaObject,
  assertVideoPackTemplateSchema,
  listWorkspaceVideoTemplatesSchema,
  workspaceVideoTemplateByIdSchema,
  appendSceneFromTemplateSchema,
  createVideoTemplateAdminSchema,
  updateVideoTemplateAdminSchema,
  createTemplateAdminBodySchema,
  listTemplatesAdminSchema,
  templateIdAdminParamsSchema,
  updateTemplateAdminSchema,
  templateMediaIdAdminParamsSchema,
  uploadTemplateMediaAdminSchema,
  publishPresentationAsPackSchema,
  publishProjectSceneAsTemplateSchema,
  publishProjectAsVideoPackSchema,
};
