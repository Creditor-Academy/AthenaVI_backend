const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const projectDao = require('./project.dao');
const { deleteFile, copyFile, buildPublicUrl } = require('../s3/s3.service');
const {
  DEFAULT_VIDEO_SETTINGS,
  CANVAS_PRESETS,
} = require('../../shared/constants/videoEditor');
const {
  buildHeygenSceneVideoKey,
  buildProjectRenderFinalKey,
  buildProjectSceneCacheKey,
} = require('../../shared/utils/videoStorageKeys');

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

  return normalized;
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
  return (projectState.scenes || []).reduce(
    (sum, scene) => sum + Number(scene.durationInFrames || 0),
    0
  );
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
  } = input;

  await assertFolderInWorkspace(folderId, workspaceId);
  const normalizedState = buildCreateProjectEditorState({
    editorState,
    aspectRatio,
    canvasSize,
    customWidth,
    customHeight,
    tags,
  });

  const project = await projectDao.createProject({
    name,
    workspaceId,
    folderId,
    createdBy: userId,
    data: normalizedState,
    thumbnail,
    duration: duration ?? estimateProjectDuration(normalizedState),
    status: status ?? 'draft',
  });

  return project;
};

const listProjects = async (workspaceId, folderId) => {
  if (folderId) {
    await assertFolderInWorkspace(folderId, workspaceId);
  }

  return projectDao.listProjects({ workspaceId, folderId });
};

const getProjectById = async (workspaceId, projectId) => {
  return assertProjectInWorkspace(workspaceId, projectId);
};

const updateProject = async (workspaceId, projectId, payload) => {
  await assertProjectInWorkspace(workspaceId, projectId);
  return projectDao.updateProject(projectId, payload);
};

const saveProjectData = async (workspaceId, projectId, data) => {
  await assertProjectInWorkspace(workspaceId, projectId);
  const normalizedState = normalizeProjectState(data);

  return projectDao.updateProject(projectId, {
    data: normalizedState,
    duration: estimateProjectDuration(normalizedState),
  });
};

async function migrateProjectS3Assets(project, nextFolderId) {
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
        data: { folderId: nextFolderId },
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

const moveProjectToFolder = async (workspaceId, projectId, folderId) => {
  const project = await projectDao.findProjectByIdWithAssets(workspaceId, projectId);

  if (!project) {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }

  if (project.folderId === folderId) {
    return projectDao.findProjectById(workspaceId, projectId);
  }

  await assertFolderInWorkspace(folderId, workspaceId);
  await migrateProjectS3Assets(project, folderId);
  return projectDao.findProjectById(workspaceId, projectId);
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

  await projectDao.deleteProject(project.id);
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
};
