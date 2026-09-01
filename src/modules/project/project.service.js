const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const projectDao = require('./project.dao');
const heygenDao = require('../video/heygen.dao');
const speechDao = require('../speech/speech.dao');
const { enrichProject, enrichProjects } = require('./project.format');
const projectStorageService = require('./projectStorage.service');
const { rehydrateHeygenAvatarsInProjectData } = require('./projectHeygenRehydrate');
const { rehydrateSpeechInProjectData } = require('./projectSpeechRehydrate');
const { normalizeEditorProjectData } = require('./projectEditorNormalize');
const { deleteFile, copyFile, buildPublicUrl } = require('../s3/s3.service');
const {
  extractSlideCover,
  extractVideoCover,
  toCoverUrls,
  persistCoverIfEmpty,
} = require('../../shared/utils/coverThumbnail');
const prisma = require('../../shared/config/prismaClient');
const {
  DEFAULT_VIDEO_SETTINGS,
  CANVAS_PRESETS,
} = require('../../shared/constants/videoEditor');
const {
  buildHeygenSceneVideoKey,
  buildProjectRenderFinalKey,
  buildProjectSceneCacheKey,
} = require('../../shared/utils/videoStorageKeys');
const storageAccounting = require('../storage/storageAccounting.service');
const videoTemplateService = require('./videoTemplate.service');
const presentationShareService = require('../presentationShare/presentationShare.service');

function buildDefaultProjectData() {
  return {
    videoSettings: { ...DEFAULT_VIDEO_SETTINGS },
    scenes: [],
  };
}

function normalizeProjectState(projectState) {
  if (!projectState) {
    return buildDefaultProjectData();
  }

  const normalized = {
    ...projectState,
    videoSettings: {
      ...DEFAULT_VIDEO_SETTINGS,
      ...(projectState.videoSettings || {}),
    },
    scenes: Array.isArray(projectState.scenes) ? projectState.scenes : [],
  };

  if (projectState.meta && typeof projectState.meta === 'object') {
    normalized.meta = { ...projectState.meta };
  }

  return normalizeEditorProjectData(normalized);
}

function resolveVideoSettingsFromCanvas({
  aspectRatio,
  canvasSize,
  customWidth,
  customHeight,
  videoSettings,
}) {
  const base = {
    ...DEFAULT_VIDEO_SETTINGS,
    ...(videoSettings && typeof videoSettings === 'object' ? videoSettings : {}),
  };

  const aspect = aspectRatio || canvasSize;
  if (!aspect) {
    return base;
  }

  if (aspect === 'custom') {
    return {
      ...base,
      width: Number(customWidth),
      height: Number(customHeight),
    };
  }

  const preset = CANVAS_PRESETS[aspect];
  if (!preset) {
    return base;
  }

  return {
    ...base,
    width: preset.width,
    height: preset.height,
  };
}

function buildProjectMeta({ aspectRatio, canvasSize, tags, existingMeta }) {
  const meta = {
    ...(existingMeta && typeof existingMeta === 'object' ? existingMeta : {}),
  };
  const aspect = aspectRatio || canvasSize;
  if (aspect) meta.aspectRatio = aspect;
  if (Array.isArray(tags) && tags.length > 0) {
    meta.tags = tags.map((t) => String(t).trim()).filter(Boolean);
  }
  return Object.keys(meta).length > 0 ? meta : undefined;
}

function buildCreateProjectEditorState({
  editorState,
  aspectRatio,
  canvasSize,
  customWidth,
  customHeight,
  tags,
}) {
  const partial =
    editorState && typeof editorState === 'object' ? editorState : { scenes: [] };

  const videoSettings = resolveVideoSettingsFromCanvas({
    aspectRatio,
    canvasSize,
    customWidth,
    customHeight,
    videoSettings: partial.videoSettings,
  });

  const meta = buildProjectMeta({
    aspectRatio,
    canvasSize,
    tags: tags ?? partial.meta?.tags,
    existingMeta: partial.meta,
  });

  const state = {
    ...partial,
    videoSettings,
    scenes: Array.isArray(partial.scenes) ? partial.scenes : [],
  };

  if (meta) {
    state.meta = meta;
  }

  return normalizeProjectState(state);
}

function estimateProjectDuration(projectState) {
  const total = (projectState.scenes || []).reduce(
    (sum, scene) => sum + Number(scene.durationInFrames || 0),
    0
  );
  if (!Number.isFinite(total) || total < 0) {
    return 0;
  }
  return Math.trunc(total);
}

async function assertFolderInWorkspace(folderId, workspaceId) {
  const folder = await projectDao.findFolderById(folderId);

  if (!folder || folder.workspaceId !== workspaceId) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }

  return folder;
}

async function assertProjectInWorkspace(workspaceId, projectId) {
  const project = await projectDao.findProjectById(workspaceId, projectId);

  if (!project) {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }

  return project;
}

const createProject = async (workspaceId, userId, input) => {
  const {
    name,
    folderId,
    editorState,
    thumbnail,
    duration,
    status,
    aspectRatio,
    canvasSize,
    customWidth,
    customHeight,
    tags,
    templateId,
  } = input;

  await assertFolderInWorkspace(folderId, workspaceId);

  const incomingScenes = Array.isArray(editorState?.scenes) ? editorState.scenes : [];
  if (templateId && incomingScenes.length > 0) {
    throw new AppError(messages.VIDEO_TEMPLATE_CONFLICTS_WITH_SCENES, 400);
  }

  let normalizedState;
  if (templateId) {
    const template = await videoTemplateService.getActiveVideoTemplate(templateId);
    normalizedState = await videoTemplateService.applyTemplateToNewProjectState({
      template,
      aspectRatio,
      canvasSize,
      customWidth,
      customHeight,
      tags,
      resolveVideoSettingsFromCanvas,
      buildProjectMeta,
      normalizeProjectState,
    });
  } else {
    normalizedState = buildCreateProjectEditorState({
      editorState,
      aspectRatio,
      canvasSize,
      customWidth,
      customHeight,
      tags,
    });
  }

  const project = await projectDao.createProject({
    name,
    workspaceId,
    folderId,
    createdBy: userId,
    updatedBy: userId,
    type: 'VIDEO',
    data: normalizedState,
    thumbnail: thumbnail || (await resolveVideoCoverPersistUrl(normalizedState)),
    duration: duration ?? estimateProjectDuration(normalizedState),
    status: status ?? 'draft',
  });

  await projectStorageService.recalculateProjectStorage(project.id);
  const refreshed = await projectDao.findProjectById(workspaceId, project.id);
  return enrichProject(refreshed);
};

const appendSceneFromVideoTemplate = async (workspaceId, projectId, userId, templateId) => {
  const project = await assertProjectInWorkspace(workspaceId, projectId);

  if (project.type === 'PRESENTATION') {
    throw new AppError(messages.VIDEO_TEMPLATE_NOT_FOR_PRESENTATION, 400);
  }

  const template = await videoTemplateService.getActiveVideoSceneTemplate(templateId);
  const currentData =
    project.data && typeof project.data === 'object'
      ? project.data
      : buildDefaultProjectData();
  const scenes = Array.isArray(currentData.scenes) ? [...currentData.scenes] : [];
  const nextOrder =
    scenes.reduce((max, s) => Math.max(max, Number(s.order) || 0), -1) + 1;

  const hydratedSchema = await videoTemplateService.hydrateVideoTemplateSchema(
    template.schema,
    template.media
  );

  let schema;
  try {
    schema = require('../validations/videoTemplate.validations').assertVideoSceneTemplateSchema(
      hydratedSchema
    );
  } catch (err) {
    throw new AppError(err.message || 'Invalid VIDEO_SCENE template schema', 400);
  }

  const scene = videoTemplateService.schemaToScene(schema, {
    templateId: template.id,
    order: nextOrder,
  });
  scenes.push(scene);

  const nextData = normalizeProjectState({
    ...currentData,
    scenes,
  });

  return saveProjectData(workspaceId, projectId, userId, nextData);
};

const listProjects = async (workspaceId, folderId, type) => {
  if (folderId) {
    await assertFolderInWorkspace(folderId, workspaceId);
  }

  const projects = await projectDao.listProjects({ workspaceId, folderId, type });
  const withCovers = await attachProjectCoverThumbnails(projects);
  return enrichProjects(withCovers, { includeData: false });
};

async function resolveVideoCoverPersistUrl(data) {
  const cover = await toCoverUrls(extractVideoCover(data));
  return cover.persistUrl || null;
}

async function attachProjectCoverThumbnails(projects) {
  if (!Array.isArray(projects) || projects.length === 0) return projects;
  const missingIds = projects.filter((p) => !p.thumbnail).map((p) => p.id);
  const sources = missingIds.length ? await projectDao.findCoverSourcesByIds(missingIds) : [];
  const byId = new Map(sources.map((row) => [row.id, row]));

  return Promise.all(
    projects.map(async (project) => {
      if (project.thumbnail) {
        const cover = await toCoverUrls({ url: project.thumbnail });
        const thumbnailUrl = cover.displayUrl || project.thumbnail;
        return { ...project, thumbnail: thumbnailUrl, thumbnailUrl };
      }

      const source = byId.get(project.id);
      const extracted =
        source?.type === 'PRESENTATION'
          ? extractSlideCover(source?.deck?.slides?.[0])
          : extractVideoCover(source?.data);

      const cover = await toCoverUrls(extracted);
      if (cover.persistUrl) {
        persistCoverIfEmpty(prisma, project.id, cover.persistUrl);
      }
      const thumbnailUrl = cover.displayUrl || null;
      return { ...project, thumbnail: thumbnailUrl, thumbnailUrl };
    })
  );
}

async function attachRehydratedProjectData(workspaceId, projectId, project) {
  if (!project?.data) {
    return project;
  }

  const [heygenRows, speechRows] = await Promise.all([
    heygenDao.listHeygenResponsesByProject(workspaceId, projectId),
    speechDao.listSpeechGenerationsByProject(workspaceId, projectId),
  ]);

  if (!heygenRows.length && !speechRows.length) {
    return project;
  }

  let data = project.data;
  let changed = false;

  if (heygenRows.length) {
    const heygenResult = rehydrateHeygenAvatarsInProjectData({
      workspaceId,
      projectId,
      data,
      heygenRows,
    });
    data = heygenResult.data;
    changed = changed || heygenResult.changed;
  }

  if (speechRows.length) {
    const speechResult = rehydrateSpeechInProjectData({
      workspaceId,
      projectId,
      data,
      speechRows,
    });
    data = speechResult.data;
    changed = changed || speechResult.changed;
  }

  if (!changed) {
    return project;
  }

  const normalized = normalizeEditorProjectData(data);
  await projectDao.updateProject(projectId, { data: normalized });
  return { ...project, data: normalized };
}

const getProjectById = async (workspaceId, projectId) => {
  const project = await assertProjectInWorkspace(workspaceId, projectId);
  const enriched = await attachRehydratedProjectData(workspaceId, projectId, project);
  const withData = enriched?.data
    ? { ...enriched, data: normalizeEditorProjectData(enriched.data) }
    : enriched;
  return enrichProject(withData);
};

const updateProject = async (workspaceId, projectId, userId, payload) => {
  await assertProjectInWorkspace(workspaceId, projectId);
  const updated = await projectDao.updateProject(projectId, {
    ...payload,
    updatedBy: userId,
  });
  return enrichProject(updated);
};

const saveProjectData = async (workspaceId, projectId, userId, data) => {
  await assertProjectInWorkspace(workspaceId, projectId);
  const normalizedState = normalizeProjectState(data);
  const [heygenRows, speechRows] = await Promise.all([
    heygenDao.listHeygenResponsesByProject(workspaceId, projectId),
    speechDao.listSpeechGenerationsByProject(workspaceId, projectId),
  ]);

  let mergedState = normalizedState;
  if (heygenRows.length) {
    const heygenResult = rehydrateHeygenAvatarsInProjectData({
      workspaceId,
      projectId,
      data: mergedState,
      heygenRows,
    });
    mergedState = heygenResult.data;
  }
  if (speechRows.length) {
    const speechResult = rehydrateSpeechInProjectData({
      workspaceId,
      projectId,
      data: mergedState,
      speechRows,
    });
    mergedState = speechResult.data;
  }

  const finalState = normalizeEditorProjectData(mergedState);

  const coverUrl = await resolveVideoCoverPersistUrl(finalState);

  await projectDao.updateProject(projectId, {
    data: finalState,
    duration: estimateProjectDuration(finalState),
    updatedBy: userId,
    ...(coverUrl ? { thumbnail: coverUrl } : {}),
  });
  await projectStorageService.recalculateProjectStorage(projectId);
  const refreshed = await projectDao.findProjectById(workspaceId, projectId);
  if (!refreshed) {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }
  return enrichProject(refreshed);
};

async function migrateProjectS3Assets(project, nextFolderId, userId) {
  const copies = [];

  const queueCopy = async (sourceKey, destinationKey) => {
    if (!sourceKey || sourceKey === destinationKey) {
      return null;
    }

    await copyFile(sourceKey, destinationKey);
    copies.push({ sourceKey, destinationKey });
    return { s3Key: destinationKey, url: buildPublicUrl(destinationKey) };
  };

  try {
    const heygenUpdates = [];
    for (const row of project.heygenResponses) {
      if (!row.s3Key) {
        continue;
      }

      const destinationKey = buildHeygenSceneVideoKey({
        workspaceId: project.workspaceId,
        folderId: nextFolderId,
        projectId: project.id,
        sceneId: row.sceneId || 'scene',
        heygenVideoId: row.id,
        outputFormat: row.s3Key?.endsWith('.webm') ? 'webm' : 'mp4',
      });

      const migrated = await queueCopy(row.s3Key, destinationKey);
      if (migrated) {
        heygenUpdates.push({
          id: row.id,
          folderId: nextFolderId,
          s3Key: migrated.s3Key,
          videoUrl: migrated.url,
        });
      }
    }

    const renderUpdates = [];
    for (const row of project.projectRenders) {
      if (!row.s3Key) {
        continue;
      }

      const destinationKey = buildProjectRenderFinalKey({
        workspaceId: project.workspaceId,
        folderId: nextFolderId,
        projectId: project.id,
        renderId: row.id,
      });

      const migrated = await queueCopy(row.s3Key, destinationKey);
      if (migrated) {
        renderUpdates.push({
          id: row.id,
          folderId: nextFolderId,
          s3Key: migrated.s3Key,
          outputUrl: migrated.url,
        });
      }
    }

    const cacheUpdates = [];
    for (const row of project.sceneRenderCaches) {
      const destinationKey = buildProjectSceneCacheKey({
        workspaceId: project.workspaceId,
        folderId: nextFolderId,
        projectId: project.id,
        sceneId: row.sceneId,
        sceneHash: row.sceneHash,
      });

      const migrated = await queueCopy(row.s3Key, destinationKey);
      if (migrated) {
        cacheUpdates.push({
          id: row.id,
          folderId: nextFolderId,
          s3Key: migrated.s3Key,
          outputUrl: migrated.url,
        });
      }
    }

    await projectDao.transaction(async (tx) => {
      await tx.project.update({
        where: { id: project.id },
        data: { folderId: nextFolderId, updatedBy: userId },
      });

      for (const row of project.heygenResponses) {
        const update = heygenUpdates.find((item) => item.id === row.id);
        await tx.heygenResponse.update({
          where: { id: row.id },
          data: {
            folderId: nextFolderId,
            ...(update || {}),
          },
        });
      }

      for (const row of project.projectRenders) {
        const update = renderUpdates.find((item) => item.id === row.id);
        await tx.projectRender.update({
          where: { id: row.id },
          data: {
            folderId: nextFolderId,
            ...(update || {}),
          },
        });
      }

      for (const row of project.sceneRenderCaches) {
        const update = cacheUpdates.find((item) => item.id === row.id);
        await tx.sceneRenderCache.update({
          where: { id: row.id },
          data: {
            folderId: nextFolderId,
            ...(update || {}),
          },
        });
      }
    });

    for (const item of copies) {
      await deleteFile(item.sourceKey);
    }
  } catch (error) {
    for (const item of copies) {
      try {
        await deleteFile(item.destinationKey);
      } catch (cleanupError) {
        void cleanupError;
      }
    }
    throw error;
  }
}

const moveProjectToFolder = async (workspaceId, projectId, userId, folderId) => {
  const project = await projectDao.findProjectByIdWithAssets(workspaceId, projectId);

  if (!project) {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }

  if (project.folderId === folderId) {
    const current = await projectDao.findProjectById(workspaceId, projectId);
    const rehydrated = await attachRehydratedProjectData(workspaceId, projectId, current);
    return enrichProject(rehydrated);
  }

  await assertFolderInWorkspace(folderId, workspaceId);
  await migrateProjectS3Assets(project, folderId, userId);
  const moved = await projectDao.findProjectById(workspaceId, projectId);
  const rehydrated = await attachRehydratedProjectData(workspaceId, projectId, moved);
  return enrichProject(rehydrated);
};

const deleteProject = async (workspaceId, projectId) => {
  const project = await projectDao.findProjectByIdWithAssets(workspaceId, projectId);

  if (!project) {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }

  const keys = [
    ...project.heygenResponses.map((item) => item.s3Key).filter(Boolean),
    ...project.projectRenders.map((item) => item.s3Key).filter(Boolean),
    ...project.sceneRenderCaches.map((item) => item.s3Key).filter(Boolean),
  ];

  for (const key of keys) {
    try {
      await deleteFile(key);
    } catch (error) {
      void error;
    }
  }

  // Drop cached share metadata and the live viewer room before the row (and its FK cascade) goes.
  await presentationShareService.invalidateForProject(project.id);

  await projectDao.deleteProject(project.id);
  const owner = await storageAccounting.getWorkspaceOwnerOrThrow(workspaceId);
  await storageAccounting.recalculateUserStorageUsed(owner.id);
};

module.exports = {
  createProject,
  listProjects,
  getProjectById,
  updateProject,
  saveProjectData,
  moveProjectToFolder,
  deleteProject,
  buildDefaultProjectData,
  appendSceneFromVideoTemplate,
};
