const AppError = require('../../shared/utils/AppError');
const projectService = require('../project/project.service');
const presentationService = require('../presentation/presentation.service');
const imageGenService = require('../imageGen/imageGen.service');
const workspaceLibraryDao = require('./workspaceLibrary.dao');
const { buildAssignmentWhere } = require('../project/project.assignment');

const CATEGORIES = Object.freeze({
  video: {
    id: 'video',
    label: 'Videos',
    projectType: 'VIDEO',
  },
  presentation: {
    id: 'presentation',
    label: 'Presentations',
    projectType: 'PRESENTATION',
  },
  image: {
    id: 'image',
    label: 'Images',
  },
});

function assertCategory(category) {
  if (!category || !CATEGORIES[category]) {
    throw new AppError(
      'category must be one of: video, presentation, image',
      400
    );
  }
  return CATEGORIES[category];
}

function withKind(kind, item) {
  if (!item || typeof item !== 'object') return item;
  return { ...item, kind, category: kind };
}

function assignmentQueryFrom(query = {}) {
  const { assignedTo, assigneeId, unassigned } = query;
  return { assignedTo, assigneeId, unassigned };
}

async function getLibrarySummary({ userId, workspace, query = {} }) {
  const isPrivate = workspace.type === 'PRIVATE';
  const assignmentWhere = buildAssignmentWhere(assignmentQueryFrom(query), userId);
  const counts = await workspaceLibraryDao.countByCategory({
    workspaceId: workspace.id,
    userId,
    isPrivate,
    folderId: query.folderId,
    assignmentWhere,
  });

  return {
    categories: [
      { ...CATEGORIES.video, count: counts.video },
      { ...CATEGORIES.presentation, count: counts.presentation },
      { ...CATEGORIES.image, count: counts.image },
    ],
  };
}

async function listLibraryCategory({ userId, workspace, category, query = {} }) {
  const meta = assertCategory(category);
  const { folderId, take, skip } = query;
  const assignmentQuery = assignmentQueryFrom(query);

  if (meta.id === 'video') {
    const projects = await projectService.listProjects(workspace.id, folderId, 'VIDEO', {
      userId,
      assignmentQuery,
    });
    return {
      category: meta.id,
      items: projects.map((p) => withKind('video', p)),
    };
  }

  if (meta.id === 'presentation') {
    const presentations = await presentationService.listPresentations({
      workspaceId: workspace.id,
      folderId,
      userId,
      assignmentQuery,
    });
    return {
      category: meta.id,
      items: presentations.map((p) => withKind('presentation', p)),
    };
  }

  // Image Gen ignores assignment filters (different model).
  const threads = await imageGenService.listThreads({
    userId,
    workspace,
    query: { folderId, take, skip },
  });
  return {
    category: meta.id,
    items: threads.map((thread) => withKind('image', thread)),
  };
}

async function getLibrary({ userId, workspace, query = {} }) {
  if (query.category) {
    return listLibraryCategory({ userId, workspace, category: query.category, query });
  }
  return getLibrarySummary({ userId, workspace, query });
}

module.exports = {
  CATEGORIES,
  getLibrary,
  getLibrarySummary,
  listLibraryCategory,
};
