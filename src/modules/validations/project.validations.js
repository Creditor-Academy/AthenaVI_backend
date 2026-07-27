const Joi = require('joi');
const {
  ELEMENT_TYPES,
  AUDIO_MEDIA_TYPES,
  TRANSITION_TYPES,
  ANIMATION_TYPES,
  PROJECT_STATUSES,
  DEFAULT_VIDEO_SETTINGS,
  CANVAS_ASPECT_RATIOS,
} = require('../../shared/constants/videoEditor');
const { avatarEngineField } = require('../../shared/validations/heygenFields');
const { normalizeTransitionPayload } = require('../../shared/utils/projectTransition');
const {
  AUDIO_PLAYBACK_RATE_MIN,
  AUDIO_PLAYBACK_RATE_MAX,
  normalizeAudioSettings,
} = require('../../shared/utils/audioSettings');

const uuidParam = Joi.string().uuid().required();

const placementSchema = Joi.object({
  x: Joi.number().required(),
  y: Joi.number().required(),
  width: Joi.number().positive().required(),
  height: Joi.number().positive().required(),
  rotation: Joi.number().default(0),
  scale: Joi.number().positive().default(1),
  opacity: Joi.number().min(0).max(1).default(1),
})
  .unknown(true)
  .required();

const transitionStepSchema = Joi.object({
  type: Joi.string()
    .valid(...TRANSITION_TYPES)
    .required(),
  durationInFrames: Joi.number().integer().min(0).required(),
  easing: Joi.string().trim().optional(),
  direction: Joi.any().optional(),
}).unknown(true);

const transitionInOutSchema = Joi.object({
  in: transitionStepSchema.optional(),
  out: transitionStepSchema.optional(),
})
  .or('in', 'out')
  .unknown(true);

/** Flat transition shape from V2 editor: { type, durationInFrames, direction } */
const transitionFlatSchema = Joi.object({
  type: Joi.string()
    .valid(...TRANSITION_TYPES)
    .required(),
  durationInFrames: Joi.number().integer().min(0).required(),
  direction: Joi.any().optional(),
  easing: Joi.string().trim().optional(),
}).unknown(true);

const transitionShapeSchema = Joi.alternatives().try(
  transitionInOutSchema,
  transitionFlatSchema
);

/** Accept null, aliases (fadeIn → fade), camelCase, and default missing durationInFrames. */
const transitionSchema = Joi.custom((value, helpers) => {
  const normalized = normalizeTransitionPayload(value);
  if (normalized === undefined) return undefined;
  if (normalized === null) {
    return helpers.message(
      `transition type must be one of: ${TRANSITION_TYPES.join(', ')} (or omit transition / use null)`
    );
  }
  const { error, value: coerced } = transitionShapeSchema.validate(normalized, {
    abortEarly: false,
  });
  if (error) {
    return helpers.message(error.details.map((d) => d.message.replace(/"/g, '')).join('; '));
  }
  return coerced;
})
  .optional()
  .allow(null);

const animationSchema = Joi.object({
  type: Joi.string()
    .valid(...ANIMATION_TYPES)
    .required(),
  startFrame: Joi.number().integer().min(0).required(),
  durationInFrames: Joi.number().integer().min(0).required(),
  easing: Joi.string().trim().optional(),
  trigger: Joi.string().trim().optional(),
}).unknown(true);

const timingSchema = Joi.object({
  startFrame: Joi.number().integer().min(0).required(),
  durationInFrames: Joi.number().integer().min(1).required(),
}).unknown(true);

const presenterSchema = Joi.object({
  avatarId: Joi.string().allow('', null).optional(),
  avatarLookId: Joi.string().allow('', null).optional(),
  avatarGroupId: Joi.string().allow('', null).optional(),
  avatarName: Joi.string().allow('', null).optional(),
  avatarPreviewSrc: Joi.string().allow('', null).optional(),
  avatarType: Joi.string().valid('studio_avatar', 'digital_twin', 'photo_avatar').optional(),
  avatarEngine: avatarEngineField({ optional: true, withDefault: false }),
  voiceId: Joi.string().allow('', null).optional(),
  voiceName: Joi.string().allow('', null).optional(),
  voiceSettings: Joi.object().unknown(true).optional(),
  script: Joi.string().allow('', null).optional(),
}).unknown(true);

const generationSchema = Joi.object({
  status: Joi.string().allow('', null).optional(),
  heygenVideoId: Joi.alternatives().try(Joi.string().uuid(), Joi.string().trim()).optional(),
  speechGenerationId: Joi.string().uuid().optional(),
  generatedVideoUrl: Joi.string().allow('', null).optional(),
  thumbnailUrl: Joi.string().allow('', null).optional(),
}).unknown(true);

const audioFadeStepSchema = Joi.object({
  durationInFrames: Joi.number().integer().min(0).required(),
  startFrame: Joi.number().integer().min(0).optional(),
  easing: Joi.string().trim().optional(),
}).unknown(true);

const audioTrimSchema = Joi.object({
  startFrame: Joi.number().integer().min(0).optional(),
  endFrame: Joi.number().integer().min(0).optional(),
}).unknown(true);

const audioSettingsSchema = Joi.object({
  volume: Joi.number().min(0).max(1).optional(),
  fadeIn: audioFadeStepSchema.optional(),
  fadeOut: audioFadeStepSchema.optional(),
  playbackRate: Joi.number().min(AUDIO_PLAYBACK_RATE_MIN).max(AUDIO_PLAYBACK_RATE_MAX).optional(),
  playbackSpeed: Joi.number().min(AUDIO_PLAYBACK_RATE_MIN).max(AUDIO_PLAYBACK_RATE_MAX).optional(),
  pitch: Joi.number().min(AUDIO_PLAYBACK_RATE_MIN).max(AUDIO_PLAYBACK_RATE_MAX).optional(),
  pitchSemitones: Joi.number().min(-24).max(24).optional(),
  preservePitch: Joi.boolean().optional(),
  muted: Joi.boolean().optional(),
  loop: Joi.boolean().optional(),
  pan: Joi.number().min(-1).max(1).optional(),
  trim: audioTrimSchema.optional(),
  trimStartFrame: Joi.number().integer().min(0).optional(),
  trimEndFrame: Joi.number().integer().min(0).optional(),
  trimBefore: Joi.number().integer().min(0).optional(),
  trimAfter: Joi.number().integer().min(0).optional(),
  reverse: Joi.boolean().optional(),
  normalize: Joi.boolean().optional(),
})
  .unknown(true)
  .custom((value) => normalizeAudioSettings(value));

const audioContentSchema = Joi.object({
  assetId: Joi.string().uuid().optional(),
  mediaType: Joi.string()
    .valid(...AUDIO_MEDIA_TYPES)
    .optional(),
  speechGenerationId: Joi.string().uuid().optional(),
  voiceId: Joi.string().trim().allow('', null).optional(),
  script: Joi.string().allow('', null).optional(),
  volume: Joi.number().min(0).max(1).optional(),
  audio: audioSettingsSchema.optional(),
}).unknown(true);

const baseElementSchema = Joi.object({
  id: Joi.string().trim().required(),
  type: Joi.string()
    .valid(...ELEMENT_TYPES)
    .required(),
  layer: Joi.number().integer().required(),
  startFrame: Joi.number().integer().min(0).optional(),
  durationInFrames: Joi.number().integer().min(1).optional(),
  timing: timingSchema.optional(),
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
  filters: Joi.object().unknown(true).optional(),
  animations: Joi.alternatives()
    .try(Joi.array().items(animationSchema), Joi.object().unknown(true))
    .default([]),
  role: Joi.string().trim().optional(),
  visible: Joi.boolean().optional(),
  editable: Joi.boolean().optional(),
  isBackground: Joi.boolean().optional(),
  headingLevel: Joi.alternatives().try(Joi.string(), Joi.number()).optional(),
  audio: audioSettingsSchema.optional(),
})
  .unknown(true)
  .custom((value, helpers) => {
    const inputTiming = value.timing && typeof value.timing === 'object' ? value.timing : {};
    const startFrame = value.startFrame != null ? value.startFrame : inputTiming.startFrame;
    const durationInFrames =
      value.durationInFrames != null ? value.durationInFrames : inputTiming.durationInFrames;

    if (startFrame == null || durationInFrames == null) {
      return helpers.message(
        'Each element requires startFrame and durationInFrames (or timing.startFrame / timing.durationInFrames)'
      );
    }

    const placement = value.placement && typeof value.placement === 'object' ? value.placement : {};
    const normalizedPlacement = {
      x: Number(placement.x) || 0,
      y: Number(placement.y) || 0,
      width: Number(placement.width) > 0 ? Number(placement.width) : 100,
      height: Number(placement.height) > 0 ? Number(placement.height) : 100,
      rotation: Number(placement.rotation) || 0,
      scale: Number(placement.scale) > 0 ? Number(placement.scale) : 1,
      opacity: placement.opacity != null ? Number(placement.opacity) : 1,
    };

    const animations = Array.isArray(value.animations)
      ? value.animations
      : value.animations && typeof value.animations === 'object'
        ? value.animations
        : [];

    let content = value.content && typeof value.content === 'object' ? { ...value.content } : {};
    let audioSettings =
      value.audio && typeof value.audio === 'object' ? { ...value.audio } : undefined;
    if (value.type === 'audio') {
      const { error: audioContentError, value: coercedAudioContent } = audioContentSchema.validate(
        content,
        { abortEarly: false }
      );
      if (audioContentError) {
        return helpers.message(
          audioContentError.details.map((d) => d.message.replace(/"/g, '')).join('; ')
        );
      }
      content = coercedAudioContent;
      if (content.assetId && !content.mediaType) {
        content.mediaType = 'audio';
      }

      const nestedAudio =
        content.audio && typeof content.audio === 'object' ? { ...content.audio } : {};
      const mergedAudio = { ...nestedAudio, ...(audioSettings || {}) };
      if (content.volume != null && mergedAudio.volume == null) {
        mergedAudio.volume = content.volume;
      }
      if (Object.keys(mergedAudio).length > 0) {
        const { error: audioSettingsError, value: coercedAudio } = audioSettingsSchema.validate(
          mergedAudio,
          { abortEarly: false }
        );
        if (audioSettingsError) {
          return helpers.message(
            audioSettingsError.details.map((d) => d.message.replace(/"/g, '')).join('; ')
          );
        }
        audioSettings = coercedAudio;
        content.audio = coercedAudio;
      }
    }

    const timing = {
      ...inputTiming,
      startFrame,
      durationInFrames,
    };

    return {
      ...value,
      layer: Number.isFinite(Number(value.layer)) ? Math.trunc(Number(value.layer)) : value.layer,
      startFrame,
      durationInFrames,
      timing,
      placement: normalizedPlacement,
      content,
      ...(audioSettings ? { audio: audioSettings } : {}),
      animations,
    };
  });

const sceneSchema = Joi.object({
  sceneId: Joi.string().trim().required(),
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
  transition: transitionSchema.optional(),
  presenter: presenterSchema.optional(),
  generation: generationSchema.optional(),
  elements: Joi.array().items(baseElementSchema).optional(),
  clips: Joi.array().items(baseElementSchema).optional(),
})
  .unknown(true)
  .custom((value, helpers) => {
    const elements = value.elements ?? value.clips;
    if (!Array.isArray(elements)) {
      return helpers.message('Each scene requires elements (or clips) array');
    }
    const { clips: _clips, ...rest } = value;
    return { ...rest, elements };
  });

const videoSettingsSchema = Joi.object({
  width: Joi.number().integer().min(1).required(),
  height: Joi.number().integer().min(1).required(),
  fps: Joi.number().integer().min(1).required(),
  backgroundColor: Joi.string().trim().optional(),
}).unknown(true);

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
})
  .unknown(true)
  .required();

/** Partial editor payload allowed on create (wizard may send empty scenes). */
const createEditorStateSchema = Joi.object({
  videoSettings: videoSettingsSchema.optional(),
  scenes: Joi.array().items(Joi.object().unknown(true)).default([]),
  meta: projectMetaSchema.optional(),
}).unknown(true);

const canvasAspectField = Joi.string().valid(...CANVAS_ASPECT_RATIOS);

const createProjectSchema = Joi.object({
  params: Joi.object({
    workspaceId: uuidParam,
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255),
    title: Joi.string().trim().min(1).max(255),
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
    templateId: Joi.string().trim().min(1).optional(),
  })
    .or('name', 'title')
    .custom((value, helpers) => {
      if (value.projectState && value.data) {
        return helpers.message('Provide either data or projectState, not both');
      }
      const scenes =
        value.projectState?.scenes || value.data?.scenes || [];
      if (value.templateId && Array.isArray(scenes) && scenes.length > 0) {
        return helpers.message(
          'Cannot use templateId together with a non-empty data.scenes / projectState.scenes'
        );
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
