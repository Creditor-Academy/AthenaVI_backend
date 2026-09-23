const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const projectDao = require('../project/project.dao');
const projectStorageService = require('../project/projectStorage.service');
const { enrichProject, enrichProjects } = require('../project/project.format');

const CANVAS_TYPE = 'CANVAS';

function buildDefaultCanvasData(size) {
  const width = Number(size?.width) > 0 ? Number(size.width) : 1080;
  const height = Number(size?.height) > 0 ? Number(size.height) : 1080;

  return {
    version: 1,
    docTitle: null,
    size: { width, height },
    canvases: [
      {
        id: `canvas-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        width,
        height,
        background: '#FFFFFF',
        elements: [],
      },
    ],
  };
}

function normalizeCanvasData(data, fallbackSize) {
  if (!data || !Array.isArray(data.canvases) || data.canvases.length === 0) {
    return buildDefaultCanvasData(fallbackSize || data?.size);
  }

  return {
    version: data.version || 1,
    docTitle: data.docTitle ?? null,
    size: data.size || {
      width: data.canvases[0].width,
      height: data.canvases[0].height,
    },
    canvases: data.canvases,
  };
}

async function assertFolderInWorkspace(folderId, workspaceId) {
  const folder = await projectDao.findFolderById(folderId);
  if (!folder || folder.workspaceId !== workspaceId) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }
  return folder;
}

async function assertCanvasInWorkspace(workspaceId, canvasId) {
  const project = await projectDao.findProjectById(workspaceId, canvasId);
  if (!project || project.type !== CANVAS_TYPE) {
    throw new AppError(messages.CANVAS_NOT_FOUND, 404);
  }
  return project;
}

const createCanvas = async (workspaceId, userId, { name, folderId, data, thumbnail }) => {
  await assertFolderInWorkspace(folderId, workspaceId);

  const normalizedData = normalizeCanvasData(data);

  const project = await projectDao.createProject({
    name,
    workspaceId,
    folderId,
    createdBy: userId,
    updatedBy: userId,
    type: CANVAS_TYPE,
    data: normalizedData,
    thumbnail: thumbnail || null,
    status: 'draft',
  });

  await projectStorageService.recalculateProjectStorage(project.id);
  const refreshed = await projectDao.findProjectById(workspaceId, project.id);
  return enrichProject(refreshed);
};

const listCanvases = async (workspaceId, folderId) => {
  if (folderId) {
    await assertFolderInWorkspace(folderId, workspaceId);
  }

  const projects = await projectDao.listProjects({
    workspaceId,
    folderId,
    type: CANVAS_TYPE,
  });
  return enrichProjects(projects, { includeData: false });
};

const getCanvasById = async (workspaceId, canvasId) => {
  const project = await assertCanvasInWorkspace(workspaceId, canvasId);
  return enrichProject(project);
};

const updateCanvasMeta = async (workspaceId, canvasId, userId, payload) => {
  await assertCanvasInWorkspace(workspaceId, canvasId);
  const updated = await projectDao.updateProject(canvasId, {
    ...payload,
    updatedBy: userId,
  });
  return enrichProject(updated);
};

const saveCanvasData = async (workspaceId, canvasId, userId, data) => {
  await assertCanvasInWorkspace(workspaceId, canvasId);
  const normalizedData = normalizeCanvasData(data);

  await projectDao.updateProject(canvasId, {
    data: normalizedData,
    updatedBy: userId,
  });
  await projectStorageService.recalculateProjectStorage(canvasId);
  const refreshed = await projectDao.findProjectById(workspaceId, canvasId);
  if (!refreshed) {
    throw new AppError(messages.CANVAS_NOT_FOUND, 404);
  }
  return enrichProject(refreshed);
};

const moveCanvasToFolder = async (workspaceId, canvasId, userId, folderId) => {
  const project = await assertCanvasInWorkspace(workspaceId, canvasId);

  if (project.folderId === folderId) {
    return enrichProject(project);
  }

  await assertFolderInWorkspace(folderId, workspaceId);
  const updated = await projectDao.updateProject(canvasId, {
    folderId,
    updatedBy: userId,
  });
  return enrichProject(updated);
};

const deleteCanvas = async (workspaceId, canvasId) => {
  await assertCanvasInWorkspace(workspaceId, canvasId);
  await projectDao.deleteProject(canvasId);
};

module.exports = {
  createCanvas,
  listCanvases,
  getCanvasById,
  updateCanvasMeta,
  saveCanvasData,
  moveCanvasToFolder,
  deleteCanvas,
};
