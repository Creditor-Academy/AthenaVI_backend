const Joi = require('joi');

const uuidParam = Joi.string().uuid().required();

/** Design-canvas element types (text/image/shape editor — distinct from the video/PPT element sets). */
const CANVAS_ELEMENT_TYPES = [
  'text',
  'textbox',
  'image',
  'icon',
  'graphic',
  'shape',
  'chart',
  'table',
  'embed',
  'group',
];

const canvasPlacementSchema = Joi.object({
  x: Joi.number().required(),
  y: Joi.number().required(),
  width: Joi.number().positive().required(),
  height: Joi.number().positive().required(),
  rotation: Joi.number().default(0),
  opacity: Joi.number().min(0).max(1).default(1),
  locked: Joi.boolean().optional(),
})
  .unknown(true)
  .required();

const canvasElementSchema = Joi.object({
  id: Joi.string().trim().required(),
  type: Joi.string()
    .valid(...CANVAS_ELEMENT_TYPES)
    .required(),
  layer: Joi.number().integer().optional(),
  presetId: Joi.string().trim().optional(),
  role: Joi.string().trim().optional(),
  groupId: Joi.string().trim().allow(null).optional(),
  childIds: Joi.array().items(Joi.string().trim()).optional(),
  placement: canvasPlacementSchema,
  content: Joi.object().unknown(true).default({}),
}).unknown(true);

const canvasPageSchema = Joi.object({
  id: Joi.string().trim().required(),
  width: Joi.number().integer().min(1).max(7680).required(),
  height: Joi.number().integer().min(1).max(7680).required(),
  background: Joi.alternatives()
    .try(Joi.string().allow(''), Joi.object().unknown(true))
    .optional(),
  elements: Joi.array().items(canvasElementSchema).max(200).default([]),
}).unknown(true);

const canvasSizeSchema = Joi.object({
  width: Joi.number().integer().min(1).max(7680).required(),
  height: Joi.number().integer().min(1).max(7680).required(),
}).unknown(true);

/** Full canvas document persisted on Project.data for type === 'CANVAS'. */
const canvasDataSchema = Joi.object({
  version: Joi.number().integer().min(1).default(1),
  docTitle: Joi.string().trim().max(255).allow('').optional(),
  size: canvasSizeSchema.optional(),
  canvases: Joi.array().items(canvasPageSchema).min(1).max(40).required(),
})
  .unknown(true)
  .required();

/** Partial payload allowed on create (client may create blank, then autosave). */
const createCanvasDataSchema = Joi.object({
  version: Joi.number().integer().min(1).default(1),
  docTitle: Joi.string().trim().max(255).allow('').optional(),
  size: canvasSizeSchema.optional(),
  canvases: Joi.array().items(canvasPageSchema).max(40).default([]),
}).unknown(true);

const createCanvasSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
    folderId: Joi.string().uuid().required(),
    data: createCanvasDataSchema.optional(),
    thumbnail: Joi.string().uri().optional(),
  }),
  query: Joi.object({}).unknown(false),
});

const listCanvasesSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  query: Joi.object({
    folderId: Joi.string().uuid().optional(),
  }),
});

const canvasByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    canvasId: uuidParam,
  }),
});

const updateCanvasSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    canvasId: uuidParam,
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).optional(),
    thumbnail: Joi.string().uri().allow(null).optional(),
  }).min(1),
});

const saveCanvasDataSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    canvasId: uuidParam,
  }),
  body: Joi.object({
    data: canvasDataSchema.required(),
  }),
});

const moveCanvasFolderSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    canvasId: uuidParam,
  }),
  body: Joi.object({
    folderId: Joi.string().uuid().required(),
  }),
});

const deleteCanvasSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
    canvasId: uuidParam,
  }),
});

module.exports = {
  CANVAS_ELEMENT_TYPES,
  canvasDataSchema,
  createCanvasSchema,
  listCanvasesSchema,
  canvasByIdSchema,
  updateCanvasSchema,
  saveCanvasDataSchema,
  moveCanvasFolderSchema,
  deleteCanvasSchema,
};
