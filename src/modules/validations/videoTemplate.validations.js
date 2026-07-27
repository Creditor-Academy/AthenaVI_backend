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
  slots: Joi.forbidden(),
  grid: Joi.forbidden(),
  layout_id: Joi.forbidden(),
})
  .unknown(false)
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

const listWorkspaceVideoTemplatesSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  query: Joi.object({
    contentType: Joi.string().trim().max(64).optional(),
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

/** Superadmin create: type discriminator; schema validated in service by type. */
const createTemplateAdminBodySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({}).unknown(false),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    contentType: Joi.string().trim().max(64).allow(null, '').optional(),
    variant: Joi.string().trim().max(64).allow(null, '').optional(),
    schema: Joi.object().unknown(true).required(),
    type: Joi.string().valid('DECK_LAYOUT', 'VIDEO_SCENE').default('DECK_LAYOUT'),
    isActive: Joi.boolean().default(true),
    version: Joi.number().integer().min(1).default(1),
  }).required(),
});

const listTemplatesAdminSchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    type: Joi.string().valid('DECK_LAYOUT', 'VIDEO_SCENE').optional(),
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
  })
    .min(1)
    .required(),
});

module.exports = {
  videoSceneTemplateSchemaObject,
  assertVideoSceneTemplateSchema,
  listWorkspaceVideoTemplatesSchema,
  workspaceVideoTemplateByIdSchema,
  appendSceneFromTemplateSchema,
  createVideoTemplateAdminSchema,
  updateVideoTemplateAdminSchema,
  createTemplateAdminBodySchema,
  listTemplatesAdminSchema,
  templateIdAdminParamsSchema,
  updateTemplateAdminSchema,
};
