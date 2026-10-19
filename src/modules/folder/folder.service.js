const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { attachUsers } = require('../../shared/utils/attachUsers');
const { sumPrismaAggregate } = require('../../shared/utils/byteSize');
const folderDao = require('./folder.dao');
const threadDao = require('../imageGen/imageGen.thread.dao');

const FOLDER_USER_FIELD_MAP = [
  { sourceField: 'createdBy', targetField: 'owner' },
  { sourceField: 'updatedBy', targetField: 'lastModifiedBy' },
];

async function validateWorkspaceAccess(workspaceId, userId) {
  const workspace = await folderDao.findWorkspaceById(workspaceId);
  if (!workspace) {
    throw new AppError(messages.WORKSPACE_NOT_FOUND, 404);
  }

  const member = await folderDao.findWorkspaceMember(workspaceId, userId);
  if (!member) {
    throw new AppError(messages.WORKSPACE_FORBIDDEN, 403);
  }

  return { workspace, member };
}

function formatFolderBase(folder, stats) {
  const projectCount = stats?.projectCount ?? 0;
  const imageThreadCount = stats?.imageThreadCount ?? 0;
  const sizeBytes = stats?.sizeBytes ?? 0;
  const lastActivityAt = stats?.lastActivityAt ?? null;

  return {
    id: folder.id,
    name: folder.name,
    workspaceId: folder.workspaceId,
    createdBy: folder.createdBy,
    updatedBy: folder.updatedBy ?? null,
    createdAt: folder.createdAt,
    lastModifiedAt: folder.updatedAt,
    projectCount,
    imageThreadCount,
    sizeBytes,
    lastActivityAt,
  };
}

function mergeFolderStats(projectRows, threadRows) {
  const map = new Map();
  for (const row of projectRows || []) {
    map.set(row.folderId, {
      projectCount: row._count.id,
      imageThreadCount: 0,
      sizeBytes: sumPrismaAggregate(row._sum.storageBytes),
      lastActivityAt: row._max.updatedAt ?? null,
    });
  }
  for (const row of threadRows || []) {
    const existing = map.get(row.folderId) || {
      projectCount: 0,
      imageThreadCount: 0,
      sizeBytes: 0,
      lastActivityAt: null,
    };
    existing.imageThreadCount = row._count.id;
    const threadUpdated = row._max.updatedAt ?? null;
    if (
      threadUpdated &&
      (!existing.lastActivityAt || threadUpdated > existing.lastActivityAt)
    ) {
      existing.lastActivityAt = threadUpdated;
    }
    map.set(row.folderId, existing);
  }
  return map;
}

async function enrichFolders(folders, statsMap) {
  const formatted = folders.map((folder) =>
    formatFolderBase(folder, statsMap.get(folder.id))
  );
  const withUsers = await attachUsers(formatted, FOLDER_USER_FIELD_MAP);
  return withUsers.map((folder) => ({
    ...folder,
    creator: folder.owner,
  }));
}

async function listFolders(workspaceId, userId) {
  await validateWorkspaceAccess(workspaceId, userId);
  const [folders, statsRows, threadStatsRows] = await Promise.all([
    folderDao.listFoldersByWorkspace(workspaceId),
    folderDao.getFolderProjectStatsByWorkspace(workspaceId),
    threadDao.getFolderThreadStatsByWorkspace(workspaceId),
  ]);
  const statsMap = mergeFolderStats(statsRows, threadStatsRows);
  return enrichFolders(folders, statsMap);
}

async function createFolder(workspaceId, userId, name) {
  await validateWorkspaceAccess(workspaceId, userId);
  const folder = await folderDao.createFolder({
    name,
    workspaceId,
    createdBy: userId,
    updatedBy: userId,
  });
  const [enriched] = await enrichFolders([folder], new Map());
  return enriched;
}

const renameFolder = async (folderId, userId, name) => {
  const folder = await folderDao.renameFolder(folderId, name, userId);
  const [statsRows, threadStatsRows] = await Promise.all([
    folderDao.getFolderProjectStatsByWorkspace(folder.workspaceId),
    threadDao.getFolderThreadStatsByWorkspace(folder.workspaceId),
  ]);
  const statsMap = mergeFolderStats(statsRows, threadStatsRows);
  const [enriched] = await enrichFolders([folder], statsMap);
  return enriched;
};

const deleteFolder = async (folderId) => {
  const deletedFolder = await folderDao.deleteFolder(folderId);
  const [enriched] = await enrichFolders([deletedFolder], new Map());
  return enriched;
};

module.exports = {
  validateWorkspaceAccess,
  listFolders,
  createFolder,
  renameFolder,
  deleteFolder,
};
