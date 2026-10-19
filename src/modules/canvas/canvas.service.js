const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const projectDao = require('../project/project.dao');
const projectStorageService = require('../project/projectStorage.service');
const { enrichProject, enrichProjects } = require('../project/project.format');

const {
  CANVAS_TYPE,
  readRevision,
  isRevisionConflict,
  normalizeCanvasData,
} = require('./canvas.data');

/** Attempts at the conditional write before giving up on unrelated concurrent row updates. */
const SAVE_WRITE_ATTEMPTS = 3;

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

  const normalizedData = normalizeCanvasData(data, { revision: 1 });

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

/**
 * Save the full document. When `baseRevision` is given, the save is refused with 409 if
 * someone else saved since that revision, so two tabs never silently overwrite each other.
 * Clients that omit it (older builds) keep last-write-wins.
 */
const saveCanvasData = async (workspaceId, canvasId, userId, data, { baseRevision } = {}) => {
  for (let attempt = 0; attempt < SAVE_WRITE_ATTEMPTS; attempt += 1) {
    const project = await assertCanvasInWorkspace(workspaceId, canvasId);
    const storedRevision = readRevision(project.data);
    if (isRevisionConflict(baseRevision, storedRevision)) {
      throw new AppError(messages.CANVAS_REVISION_CONFLICT, 409);
    }

    const normalizedData = normalizeCanvasData(data, { revision: storedRevision + 1 });
    // `updatedAt` pins the row we just read: any write in between (another save, or an
    // unrelated rename/move) makes this match nothing, and we re-check the revision.
    const written = await projectDao.updateProjectIfUnchanged(canvasId, project.updatedAt, {
      data: normalizedData,
      updatedBy: userId,
    });
    if (written) break;
    if (attempt === SAVE_WRITE_ATTEMPTS - 1) {
      throw new AppError(messages.CANVAS_REVISION_CONFLICT, 409);
    }
  }

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
