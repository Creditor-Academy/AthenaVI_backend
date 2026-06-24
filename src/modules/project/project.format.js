const { attachUsers } = require('../../shared/utils/attachUsers');
const { toJsonNumber } = require('../../shared/utils/byteSize');

const USER_FIELD_MAP = [
  { sourceField: 'createdBy', targetField: 'owner' },
  { sourceField: 'updatedBy', targetField: 'lastModifiedBy' },
];

function baseProjectFields(project) {
  return {
    id: project.id,
    name: project.name,
    workspaceId: project.workspaceId,
    folderId: project.folderId,
    createdBy: project.createdBy,
    updatedBy: project.updatedBy ?? null,
    thumbnail: project.thumbnail,
    duration: project.duration,
    status: project.status,
    storageBytes: toJsonNumber(project.storageBytes),
    createdAt: project.createdAt,
    lastModifiedAt: project.updatedAt,
    folder: project.folder,
  };
}

function formatProjectSummary(project) {
  return baseProjectFields(project);
}

function formatProjectDetail(project) {
  return {
    ...baseProjectFields(project),
    data: project.data,
  };
}

async function enrichProjects(projects, { includeData = false } = {}) {
  const formatted = projects.map((project) =>
    includeData ? formatProjectDetail(project) : formatProjectSummary(project)
  );
  return attachUsers(formatted, USER_FIELD_MAP);
}

async function enrichProject(project, { includeData = true } = {}) {
  const [enriched] = await enrichProjects([project], { includeData });
  return enriched;
}

module.exports = {
  formatProjectSummary,
  formatProjectDetail,
  enrichProjects,
  enrichProject,
};
