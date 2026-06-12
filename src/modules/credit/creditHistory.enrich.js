const prisma = require('../../shared/config/prismaClient');
const { FEATURE } = require('../../shared/config/creditPricing');

const FEATURE_LABELS = Object.freeze({
  [FEATURE.HEYGEN_VIDEO]: 'Scene avatar video',
  [FEATURE.REMOTION_EXPORT]: 'Final video export',
  [FEATURE.VOICE_CLONE]: 'Voice clone',
  [FEATURE.VOICE_DESIGN]: 'Voice design',
  [FEATURE.AVATAR_CREATE]: 'Avatar creation',
  [FEATURE.VOICE_PREVIEW]: 'Speech preview',
});

function truncateText(value, max = 120) {
  if (value == null) return null;
  const text = String(value).trim();
  if (!text) return null;
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function uniqueIds(values) {
  return [...new Set(values.filter(Boolean))];
}

function buildNonUsageDetail(tx) {
  const meta = asObject(tx.metadata);
  switch (tx.type) {
    case 'platform_grant':
      return {
        label: tx.scope === 'workspace' ? 'Workspace credits granted' : 'Credits granted',
        reason: meta.reason || tx.reference || null,
      };
    case 'platform_revoke':
      return {
        label: 'Credits revoked',
        reason: meta.reason || tx.reference || null,
      };
    case 'allocation':
      return {
        label: meta.direction === 'out' ? 'Allocated to workspace' : 'Received from personal pool',
        workspaceId: meta.workspaceId || tx.workspaceId || tx.reference || null,
      };
    case 'deallocation':
      return {
        label: meta.direction === 'out' ? 'Returned from workspace' : 'Returned to personal pool',
        workspaceId: meta.workspaceId || tx.workspaceId || tx.reference || null,
      };
    case 'refund':
      return { label: 'Refund', reason: meta.reason || tx.reference || null };
    default:
      return null;
  }
}

function buildUsageDetail(tx, ctx) {
  const meta = asObject(tx.metadata);
  const feature = meta.feature;
  if (!feature) {
    return {
      label: 'Usage',
      kind: 'usage',
      credits: Math.abs(tx.amount),
    };
  }

  const base = {
    feature,
    label: FEATURE_LABELS[feature] || 'Usage',
    kind: feature,
    credits: Math.abs(tx.amount),
    durationSeconds: meta.durationSeconds ?? null,
    workspaceId: tx.workspaceId || null,
    workspaceName: tx.workspaceId ? ctx.workspaceById.get(tx.workspaceId)?.name || null : null,
  };

  switch (feature) {
    case FEATURE.HEYGEN_VIDEO: {
      const heygenVideoId = meta.heygenVideoId || tx.reference;
      const heygen = heygenVideoId ? ctx.heygenById.get(heygenVideoId) : null;
      const billingContext = asObject(heygen?.billingContext);
      const projectId = meta.projectId || heygen?.projectId || null;
      return {
        ...base,
        heygenVideoId,
        projectId,
        projectName: meta.projectName || ctx.projectById.get(projectId)?.name || null,
        sceneId: meta.sceneId || heygen?.sceneId || null,
        videoTitle: meta.videoTitle || billingContext.title || null,
        scriptPreview:
          meta.scriptPreview || truncateText(billingContext.script || billingContext.scriptText),
        avatarEngine: meta.avatarEngine || billingContext.avatarEngine || null,
      };
    }
    case FEATURE.REMOTION_EXPORT: {
      const renderId = meta.renderId || tx.reference;
      const render = renderId ? ctx.renderById.get(renderId) : null;
      const projectId = meta.projectId || render?.projectId || null;
      return {
        ...base,
        renderId,
        projectId,
        projectName: meta.projectName || ctx.projectById.get(projectId)?.name || null,
        durationInFrames: meta.durationInFrames ?? null,
        fps: meta.fps ?? null,
      };
    }
    case FEATURE.VOICE_CLONE:
      return {
        ...base,
        voiceId: meta.voiceId || tx.reference || null,
        voiceName: meta.voiceName || null,
      };
    case FEATURE.VOICE_DESIGN:
      return {
        ...base,
        voiceId: meta.voiceId || tx.reference || null,
        promptPreview: meta.promptPreview || null,
      };
    case FEATURE.AVATAR_CREATE:
      return {
        ...base,
        avatarGroupId: meta.avatarGroupId || tx.reference || null,
        avatarName: meta.avatarName || null,
        avatarType: meta.avatarType || null,
      };
    case FEATURE.VOICE_PREVIEW:
      return {
        ...base,
        voiceId: meta.voiceId || tx.reference || null,
        previewText: meta.previewText || null,
      };
    default:
      return base;
  }
}

function buildDetail(tx, ctx) {
  if (tx.type === 'usage') {
    return buildUsageDetail(tx, ctx);
  }
  return buildNonUsageDetail(tx);
}

async function loadEnrichmentContext(transactions) {
  const heygenVideoIds = [];
  const renderIds = [];
  const projectIds = [];
  const workspaceIds = [];

  for (const tx of transactions) {
    if (tx.workspaceId) workspaceIds.push(tx.workspaceId);
    if (tx.type !== 'usage') continue;

    const meta = asObject(tx.metadata);
    if (meta.feature === FEATURE.HEYGEN_VIDEO) {
      heygenVideoIds.push(meta.heygenVideoId || tx.reference);
      if (meta.projectId) projectIds.push(meta.projectId);
    } else if (meta.feature === FEATURE.REMOTION_EXPORT) {
      renderIds.push(meta.renderId || tx.reference);
      if (meta.projectId) projectIds.push(meta.projectId);
    }
  }

  const [heygenRows, renderRows] = await Promise.all([
    heygenVideoIds.length
      ? prisma.heygenResponse.findMany({
          where: { id: { in: uniqueIds(heygenVideoIds) } },
          select: {
            id: true,
            projectId: true,
            sceneId: true,
            billingContext: true,
          },
        })
      : [],
    renderIds.length
      ? prisma.projectRender.findMany({
          where: { id: { in: uniqueIds(renderIds) } },
          select: { id: true, projectId: true },
        })
      : [],
  ]);

  for (const row of heygenRows) {
    if (row.projectId) projectIds.push(row.projectId);
  }
  for (const row of renderRows) {
    if (row.projectId) projectIds.push(row.projectId);
  }

  const [projects, workspaces] = await Promise.all([
    projectIds.length
      ? prisma.project.findMany({
          where: { id: { in: uniqueIds(projectIds) } },
          select: { id: true, name: true },
        })
      : [],
    workspaceIds.length
      ? prisma.workspace.findMany({
          where: { id: { in: uniqueIds(workspaceIds) } },
          select: { id: true, name: true, type: true },
        })
      : [],
  ]);

  return {
    heygenById: new Map(heygenRows.map((row) => [row.id, row])),
    renderById: new Map(renderRows.map((row) => [row.id, row])),
    projectById: new Map(projects.map((row) => [row.id, row])),
    workspaceById: new Map(workspaces.map((row) => [row.id, row])),
  };
}

function enrichTransaction(tx, ctx) {
  return {
    ...tx,
    usageDetail: buildDetail(tx, ctx),
  };
}

async function enrichCreditHistoryResult(result) {
  if (!result?.transactions?.length) {
    return result;
  }

  const ctx = await loadEnrichmentContext(result.transactions);
  return {
    ...result,
    transactions: result.transactions.map((tx) => enrichTransaction(tx, ctx)),
  };
}

module.exports = {
  enrichCreditHistoryResult,
  enrichTransaction,
  truncateText,
  FEATURE_LABELS,
};
