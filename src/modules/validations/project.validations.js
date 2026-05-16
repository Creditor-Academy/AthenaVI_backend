const Joi = require('joi');
const {
  ELEMENT_TYPES,
  TRANSITION_TYPES,
  ANIMATION_TYPES,
  PROJECT_STATUSES,
  DEFAULT_VIDEO_SETTINGS,
  CANVAS_ASPECT_RATIOS,
} = require('../../shared/constants/videoEditor');

const uuidParam = Joi.string().uuid().required();

const placementSchema = Joi.object({
  x: Joi.number().required(),
  y: Joi.number().required(),
  width: Joi.number().positive().required(),
  height: Joi.number().positive().required(),
  rotation: Joi.number().default(0),
  scale: Joi.number().positive().default(1),
  opacity: Joi.number().min(0).max(1).default(1),
}).required();

const transitionStepSchema = Joi.object({
  type: Joi.string()
    .valid(...TRANSITION_TYPES)
    .required(),
  durationInFrames: Joi.number().integer().min(0).required(),
  easing: Joi.string().trim().optional(),
}).unknown(true);

const transitionSchema = Joi.object({
  in: transitionStepSchema.optional(),
  out: transitionStepSchema.optional(),
})
  .or('in', 'out')
  .optional();

const animationSchema = Joi.object({
  type: Joi.string()
    .valid(...ANIMATION_TYPES)
    .required(),
  startFrame: Joi.number().integer().min(0).required(),
  durationInFrames: Joi.number().integer().min(0).required(),
  easing: Joi.string().trim().optional(),
  trigger: Joi.string().trim().optional(),
}).unknown(true);

const baseElementSchema = Joi.object({
  id: Joi.string().trim().required(),
  type: Joi.string()
    .valid(...ELEMENT_TYPES)
    .required(),
  layer: Joi.number().integer().required(),
  startFrame: Joi.number().integer().min(0).required(),
  durationInFrames: Joi.number().integer().min(1).required(),
  placement: placementSchema,
  content: Joi.object().unknown(true).required(),
  animations: Joi.array().items(animationSchema).default([]),
}).required();

const sceneSchema = Joi.object({
  sceneId: Joi.string().trim().required(),
  name: Joi.string().trim().max(255).optional(),
  durationInFrames: Joi.number().integer().min(1).required(),
  background: Joi.object({
    type: Joi.string().trim().required(),
    value: Joi.alternatives().try(Joi.string(), Joi.number(), Joi.object().unknown(true)).optional(),
  })
    .unknown(true)
    .required(),
  transition: transitionSchema,
  elements: Joi.array().items(baseElementSchema).required(),
}).required();

const videoSettingsSchema = Joi.object({
  width: Joi.number().integer().min(1).required(),
  height: Joi.number().integer().min(1).required(),
  fps: Joi.number().integer().min(1).required(),
  backgroundColor: Joi.string().trim().optional(),
});

const projectMetaSchema = Joi.object({
  aspectRatio: Joi.string()
    .valid(...CANVAS_ASPECT_RATIOS)
    .optional(),
  tags: Joi.array().items(Joi.string().trim().min(1).max(64)).max(32).optional(),
}).unknown(true);

const editorStateSchema = Joi.object({
  videoSettings: videoSettingsSchema.default(DEFAULT_VIDEO_SETTINGS).required(),
  scenes: Joi.array().items(sceneSchema).required(),
  meta: projectMetaSchema.optional(),
}).required();

/** Partial editor payload allowed on create (wizard may send empty scenes). */
const createEditorStateSchema = Joi.object({
  videoSettings: videoSettingsSchema.optional(),
  /** Empty array allowed on create; full scene shape validated on PATCH .../data */
  scenes: Joi.array().default([]),
  meta: projectMetaSchema.optional(),
});

const canvasAspectField = Joi.string().valid(...CANVAS_ASPECT_RATIOS);

const createProjectSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255),
    title: Joi.string().trim().min(1).max(255),
    /** Optional echo of URL `:workspaceId` (Details workspace dropdown); must match params when sent */
    workspaceId: Joi.string().uuid().optional(),
    folderId: Joi.string().uuid().required(),
    projectState: createEditorStateSchema.optional(),
    data: createEditorStateSchema.optional(),
    aspectRatio: canvasAspectField,
    canvasSize: canvasAspectField,
    customWidth: Joi.number().integer().min(1).max(7680),
    customHeight: Joi.number().integer().min(1).max(7680),
    tags: Joi.array().items(Joi.string().trim().min(1).max(64)).max(32),
    thumbnail: Joi.string().uri().optional(),
    duration: Joi.number().integer().min(0).optional(),
    status: Joi.string()
      .valid(...PROJECT_STATUSES)
      .optional(),
  })
    .or('name', 'title')
    .custom((value, helpers) => {
      if (value.projectState && value.data) {
        return helpers.message('Provide either data or projectState, not both');
      }
      const aspect = value.aspectRatio || value.canvasSize;
      if (aspect === 'custom') {
        if (!value.customWidth || !value.customHeight) {
          return helpers.message(
            'customWidth and customHeight are required when aspectRatio (or canvasSize) is custom'
          );
        }
      }
      return value;
    }),
  query: Joi.object({}).unknown(false),
}).custom((value, helpers) => {
  const bodyWorkspaceId = value.body?.workspaceId;
  if (
    bodyWorkspaceId &&
    value.params?.workspaceId &&
    bodyWorkspaceId !== value.params.workspaceId
  ) {
    return helpers.message('workspaceId in body must match workspaceId in the URL path');
  }
  return value;
});

const listProjectsSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  query: Joi.object({
    folderId: Joi.string().uuid().optional(),
  }),
});

const projectByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
});

const updateProjectSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).optional(),
    thumbnail: Joi.string().uri().allow(null).optional(),
    duration: Joi.number().integer().min(0).allow(null).optional(),
    status: Joi.string()
      .valid(...PROJECT_STATUSES)
      .optional(),
  }).min(1),
});

const saveProjectDataSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
  body: Joi.object({
    data: editorStateSchema.required(),
  }),
});

const moveProjectFolderSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
  body: Joi.object({
    folderId: Joi.string().uuid().required(),
  }),
});

const deleteProjectSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    projectId: uuidParam,
  }),
});

module.exports = {
  ELEMENT_TYPES,
  TRANSITION_TYPES,
  ANIMATION_TYPES,
  editorStateSchema,
  createProjectSchema,
  listProjectsSchema,
  projectByIdSchema,
  updateProjectSchema,
  saveProjectDataSchema,
  moveProjectFolderSchema,
  deleteProjectSchema,
};
