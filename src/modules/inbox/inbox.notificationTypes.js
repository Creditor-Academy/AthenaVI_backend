const CATEGORIES = {
  VIDEOS: 'videos',
  CREDITS: 'credits',
  STORAGE: 'storage',
  WORKSPACE: 'workspace',
  PLATFORM: 'platform',
  COLLABORATION: 'collaboration',
};

const TYPE_CATEGORY = {
  WORKSPACE_INVITATION: CATEGORIES.WORKSPACE,
  WORKSPACE_MEMBER_JOINED: CATEGORIES.WORKSPACE,
  WORKSPACE_MEMBER_REMOVED: CATEGORIES.WORKSPACE,
  WORKSPACE_ROLE_CHANGED: CATEGORIES.WORKSPACE,
  VIDEO_EXPORT_COMPLETED: CATEGORIES.VIDEOS,
  VIDEO_EXPORT_FAILED: CATEGORIES.VIDEOS,
  CREDITS_PLATFORM_GRANT: CATEGORIES.CREDITS,
  CREDITS_PLATFORM_REVOKE: CATEGORIES.CREDITS,
  CREDITS_WORKSPACE_GRANT: CATEGORIES.CREDITS,
  CREDITS_ALLOCATED: CATEGORIES.CREDITS,
  CREDITS_DEALLOCATED: CATEGORIES.CREDITS,
  CREDITS_LOW_PERSONAL: CATEGORIES.CREDITS,
  CREDITS_LOW_WORKSPACE: CATEGORIES.CREDITS,
  STORAGE_PLATFORM_GRANT: CATEGORIES.STORAGE,
  STORAGE_PLATFORM_REVOKE: CATEGORIES.STORAGE,
  STORAGE_THRESHOLD_WARNING: CATEGORIES.STORAGE,
  STORAGE_UPLOAD_BLOCKED: CATEGORIES.STORAGE,
  STORAGE_UPGRADE_REJECTED: CATEGORIES.STORAGE,
  PLATFORM_HEYGEN_WALLET_LOW: CATEGORIES.PLATFORM,
  PLATFORM_STORAGE_UPGRADE_REQUEST: CATEGORIES.PLATFORM,
  PLATFORM_EARLY_ACCESS_REQUEST: CATEGORIES.PLATFORM,
  CREDITS_WORKSPACE_REVOKE: CATEGORIES.CREDITS,
  PROJECT_COMMENT_ADDED: CATEGORIES.COLLABORATION,
  PROJECT_COMMENT_MENTION: CATEGORIES.COLLABORATION,
};

const TYPE_PREFERENCE_KEY = {
  WORKSPACE_INVITATION: 'workspaceTeamAlerts',
  WORKSPACE_MEMBER_JOINED: 'workspaceTeamAlerts',
  WORKSPACE_MEMBER_REMOVED: 'workspaceTeamAlerts',
  WORKSPACE_ROLE_CHANGED: 'workspaceTeamAlerts',
  VIDEO_EXPORT_COMPLETED: 'videoExportAlerts',
  VIDEO_EXPORT_FAILED: 'videoExportAlerts',
  CREDITS_PLATFORM_GRANT: 'creditsAlerts',
  CREDITS_PLATFORM_REVOKE: 'creditsAlerts',
  CREDITS_WORKSPACE_GRANT: 'creditsAlerts',
  CREDITS_ALLOCATED: 'creditsAlerts',
  CREDITS_DEALLOCATED: 'creditsAlerts',
  CREDITS_LOW_PERSONAL: 'creditsAlerts',
  CREDITS_LOW_WORKSPACE: 'creditsAlerts',
  STORAGE_PLATFORM_GRANT: 'storageAlerts',
  STORAGE_PLATFORM_REVOKE: 'storageAlerts',
  STORAGE_THRESHOLD_WARNING: 'storageAlerts',
  STORAGE_UPLOAD_BLOCKED: 'storageAlerts',
  STORAGE_UPGRADE_REJECTED: 'storageAlerts',
  PLATFORM_HEYGEN_WALLET_LOW: 'platformAdminAlerts',
  PLATFORM_STORAGE_UPGRADE_REQUEST: 'platformAdminAlerts',
  PLATFORM_EARLY_ACCESS_REQUEST: 'platformAdminAlerts',
  CREDITS_WORKSPACE_REVOKE: 'creditsAlerts',
  PROJECT_COMMENT_ADDED: 'commentsAndMentions',
  PROJECT_COMMENT_MENTION: 'commentsAndMentions',
};

const WORKSPACE_ADMIN_VIDEO_TYPES = new Set([
  'VIDEO_EXPORT_COMPLETED',
  'VIDEO_EXPORT_FAILED',
]);

function getCategoryForType(type) {
  return TYPE_CATEGORY[type] || null;
}

function getPreferenceKeyForType(type, metadata = {}) {
  if (
    WORKSPACE_ADMIN_VIDEO_TYPES.has(type) &&
    metadata.audience === 'workspace_admin'
  ) {
    return 'workspaceVideoExportAlerts';
  }
  return TYPE_PREFERENCE_KEY[type] || 'pushNotifications';
}

function getTypesForCategory(category) {
  return Object.entries(TYPE_CATEGORY)
    .filter(([, cat]) => cat === category)
    .map(([type]) => type);
}

function buildActionUrl(metadata = {}) {
  if (metadata.actionUrl) {
    return metadata.actionUrl;
  }
  const base = process.env.FRONTEND_URL || '';
  if (metadata.workspaceId && metadata.projectId && metadata.renderId) {
    return `${base}/workspaces/${metadata.workspaceId}/projects/${metadata.projectId}/renders/${metadata.renderId}`;
  }
  if (metadata.workspaceId && metadata.projectId) {
    return `${base}/workspaces/${metadata.workspaceId}/projects/${metadata.projectId}`;
  }
  if (metadata.workspaceId) {
    return `${base}/workspaces/${metadata.workspaceId}`;
  }
  return null;
}

function serializeNotification(row) {
  const category = getCategoryForType(row.type);
  return {
    id: row.id,
    type: row.type,
    category,
    title: row.title,
    message: row.message,
    readAt: row.readAt,
    metadata: row.metadata,
    workspaceId: row.workspaceId,
    invitationId: row.invitationId,
    referenceId: row.referenceId,
    createdAt: row.createdAt,
  };
}

module.exports = {
  CATEGORIES,
  TYPE_CATEGORY,
  TYPE_PREFERENCE_KEY,
  getCategoryForType,
  getPreferenceKeyForType,
  getTypesForCategory,
  buildActionUrl,
  serializeNotification,
};
