const AppError = require('../../shared/utils/AppError');
const projectService = require('../project/project.service');
const presentationService = require('../presentation/presentation.service');
const imageGenService = require('../imageGen/imageGen.service');
const workspaceLibraryDao = require('./workspaceLibrary.dao');

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

async function getLibrarySummary({ userId, workspace }) {
  const isPrivate = workspace.type === 'PRIVATE';
  const counts = await workspaceLibraryDao.countByCategory({
    workspaceId: workspace.id,
    userId,
    isPrivate,
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
  const { folderId, take, skip, mode } = query;

  if (meta.id === 'video') {
    const projects = await projectService.listProjects(workspace.id, folderId, 'VIDEO');
    return {
      category: meta.id,
      items: projects.map((p) => withKind('video', p)),
    };
  }

  if (meta.id === 'presentation') {
    const presentations = await presentationService.listPresentations({
      workspaceId: workspace.id,
      folderId,
    });
    return {
      category: meta.id,
      items: presentations.map((p) => withKind('presentation', p)),
    };
  }

  const generations = await imageGenService.listGenerations({
    userId,
    workspace,
    query: { take, skip, mode },
  });
  return {
    category: meta.id,
    items: generations.map((g) => withKind('image', g)),
  };
}

async function getLibrary({ userId, workspace, query = {} }) {
  if (query.category) {
    return listLibraryCategory({ userId, workspace, category: query.category, query });
  }
  return getLibrarySummary({ userId, workspace });
}

module.exports = {
  CATEGORIES,
  getLibrary,
  getLibrarySummary,
  listLibraryCategory,
};
