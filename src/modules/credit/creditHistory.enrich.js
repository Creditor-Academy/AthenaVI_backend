const prisma = require('../../shared/config/prismaClient');
const { FEATURE } = require('../../shared/config/creditPricing');
const { IMAGE_GEN_FEATURE } = require('../../shared/config/imageGenCreditPricing');
const { BRAND_KIT_FEATURE } = require('../../shared/config/brandKitCreditPricing');

const FEATURE_LABELS = Object.freeze({
  [FEATURE.HEYGEN_VIDEO]: 'Scene avatar video',
  [FEATURE.SPEECH_GENERATION]: 'Scene speech',
  [FEATURE.REMOTION_EXPORT]: 'Final video export',
  [FEATURE.VOICE_CLONE]: 'Voice clone',
  [FEATURE.VOICE_DESIGN]: 'Voice design',
  [FEATURE.AVATAR_CREATE]: 'Avatar creation',
  [FEATURE.VOICE_PREVIEW]: 'Speech preview',
  ppt_outline: 'Presentation outline',
  ppt_slide_content: 'Presentation slide content',
  ppt_image_path_a: 'Presentation image',
  ppt_image_path_b: 'Presentation diagram',
  ppt_export: 'Presentation export',
  ppt_image_cache_hit: 'Presentation image (cached)',
  [IMAGE_GEN_FEATURE.GPT_IMAGE]: 'AI image generation',
  [IMAGE_GEN_FEATURE.GPT_IMAGE_HD]: 'AI image generation (HD)',
  [IMAGE_GEN_FEATURE.DALL_E_3]: 'AI image generation (DALL·E 3)',
  [IMAGE_GEN_FEATURE.TWEAK]: 'AI image tweak',
  [IMAGE_GEN_FEATURE.INFOGRAPHIC]: 'AI infographic',
  [BRAND_KIT_FEATURE.SUGGEST_COLORS]: 'Brand kit color suggestion',
  [BRAND_KIT_FEATURE.SUGGEST_FONTS]: 'Brand kit font suggestion',
  [BRAND_KIT_FEATURE.SUGGEST_VOICE]: 'Brand kit voice suggestion',
  [BRAND_KIT_FEATURE.SUGGEST_IMAGE_STYLE]: 'Brand kit image style suggestion',
  [BRAND_KIT_FEATURE.LOGO_VARIANTS]: 'Brand kit logo variants',
  [BRAND_KIT_FEATURE.LOGO_MOCKUP]: 'Brand kit logo mockup',
  [BRAND_KIT_FEATURE.GUIDELINE_GENERATE]: 'Brand guideline deck',
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

/** Editor scene display name from `project.data.scenes` (falls back to null). */
function resolveSceneNameFromProjectData(projectData, sceneId) {
  if (!projectData || sceneId == null || String(sceneId).trim() === '') {
    return null;
  }
  const scenes = Array.isArray(projectData?.scenes) ? projectData.scenes : [];
  const normalizedId = String(sceneId).trim();
  const scene = scenes.find((row) => {
    const candidate = row?.sceneId ?? row?.id;
    return candidate != null && String(candidate).trim() === normalizedId;
  });
  if (!scene) return null;
  const name = scene.name != null ? String(scene.name).trim() : '';
  return name || null;
}

const CONSUMPTION_TYPES = Object.freeze({
  [FEATURE.HEYGEN_VIDEO]: 'Avatar video',
  [FEATURE.SPEECH_GENERATION]: 'Speech generation',
  [FEATURE.REMOTION_EXPORT]: 'Video export',
  [FEATURE.VOICE_CLONE]: 'Voice clone',
  [FEATURE.VOICE_DESIGN]: 'Voice design',
  [FEATURE.AVATAR_CREATE]: 'Avatar creation',
  [FEATURE.VOICE_PREVIEW]: 'Speech preview',
});

function buildHeygenVideoDisplayName({ sceneName, sceneId, projectName, workspaceName }) {
  const sceneLabel = sceneName || sceneId;
  const parts = [CONSUMPTION_TYPES[FEATURE.HEYGEN_VIDEO]];
  if (sceneLabel) {
    parts.push(`scene “${sceneLabel}”`);
  }
  if (projectName) {
    parts.push(`in “${projectName}”`);
  } else if (workspaceName) {
    parts.push(`in workspace “${workspaceName}”`);
  }
  if (parts.length === 1) return FEATURE_LABELS[FEATURE.HEYGEN_VIDEO];
  return parts.join(' ');
}

function buildSpeechGenerationDisplayName({ sceneName, sceneId, projectName, workspaceName }) {
  const sceneLabel = sceneName || sceneId;
  const parts = [CONSUMPTION_TYPES[FEATURE.SPEECH_GENERATION]];
  if (sceneLabel) {
    parts.push(`scene “${sceneLabel}”`);
  }
  if (projectName) {
    parts.push(`in “${projectName}”`);
  } else if (workspaceName) {
    parts.push(`in workspace “${workspaceName}”`);
  }
  if (parts.length === 1) return FEATURE_LABELS[FEATURE.SPEECH_GENERATION];
  return parts.join(' ');
}

function buildRemotionExportDisplayName(projectName, workspaceName) {
  if (projectName) {
    return `${CONSUMPTION_TYPES[FEATURE.REMOTION_EXPORT]} — “${projectName}”`;
  }
  if (workspaceName) {
    return `${CONSUMPTION_TYPES[FEATURE.REMOTION_EXPORT]} in workspace “${workspaceName}”`;
  }
  return FEATURE_LABELS[FEATURE.REMOTION_EXPORT];
}

function buildWhereSummary({ sceneName, sceneId, projectName, workspaceName }) {
  const items = [];
  if (sceneName || sceneId) {
    items.push(sceneName ? `Scene: ${sceneName}` : `Scene ID: ${sceneId}`);
  }
  if (projectName) items.push(`Project: ${projectName}`);
  if (workspaceName) items.push(`Workspace: ${workspaceName}`);
  return items.length ? items.join(' · ') : null;
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
      const project = projectId ? ctx.projectById.get(projectId) : null;
      const sceneId = meta.sceneId || heygen?.sceneId || null;
      const projectName = meta.projectName || project?.name || null;
      const sceneName =
        meta.sceneName ||
        billingContext.sceneName ||
        resolveSceneNameFromProjectData(project?.data, sceneId);
      const videoTitle = meta.videoTitle || billingContext.title || null;
      const workspaceName = base.workspaceName;
      const displayName = buildHeygenVideoDisplayName({
        sceneName,
        sceneId,
        projectName,
        workspaceName,
      });
      return {
        ...base,
        consumptionType: CONSUMPTION_TYPES[FEATURE.HEYGEN_VIDEO],
        label: displayName,
        displayName,
        where: buildWhereSummary({ sceneName, sceneId, projectName, workspaceName }),
        heygenVideoId,
        projectId,
        projectName,
        sceneId,
        sceneName,
        videoTitle,
        scriptPreview:
          meta.scriptPreview || truncateText(billingContext.script || billingContext.scriptText),
        avatarEngine: meta.avatarEngine || billingContext.avatarEngine || null,
        avatarType: meta.avatarType || billingContext.avatarType || null,
        resolution: meta.resolution || billingContext.resolution || null,
      };
    }
    case FEATURE.SPEECH_GENERATION: {
      const speechGenerationId = meta.speechGenerationId || tx.reference;
      const speech = speechGenerationId ? ctx.speechById.get(speechGenerationId) : null;
      const billingContext = asObject(speech?.billingContext);
      const projectId = meta.projectId || speech?.projectId || null;
      const project = projectId ? ctx.projectById.get(projectId) : null;
      const sceneId = meta.sceneId || speech?.sceneId || null;
      const projectName = meta.projectName || project?.name || null;
      const sceneName =
        meta.sceneName ||
        billingContext.sceneName ||
        resolveSceneNameFromProjectData(project?.data, sceneId);
      const workspaceName = base.workspaceName;
      const displayName = buildSpeechGenerationDisplayName({
        sceneName,
        sceneId,
        projectName,
        workspaceName,
      });
      return {
        ...base,
        consumptionType: CONSUMPTION_TYPES[FEATURE.SPEECH_GENERATION],
        label: displayName,
        displayName,
        where: buildWhereSummary({ sceneName, sceneId, projectName, workspaceName }),
        speechGenerationId,
        projectId,
        projectName,
        sceneId,
        sceneName,
        voiceId: meta.voiceId || speech?.voiceId || null,
        scriptPreview:
          meta.scriptPreview || truncateText(speech?.script || billingContext.script),
      };
    }
    case FEATURE.REMOTION_EXPORT: {
      const renderId = meta.renderId || tx.reference;
      const render = renderId ? ctx.renderById.get(renderId) : null;
      const projectId = meta.projectId || render?.projectId || null;
      const projectName =
        meta.projectName ||
        meta.videoName ||
        ctx.projectById.get(projectId)?.name ||
        null;
      const workspaceName = base.workspaceName;
      const displayName = buildRemotionExportDisplayName(projectName, workspaceName);
      return {
        ...base,
        consumptionType: CONSUMPTION_TYPES[FEATURE.REMOTION_EXPORT],
        label: displayName,
        displayName,
        videoName: projectName,
        where: buildWhereSummary({ projectName, workspaceName }),
        renderId,
        projectId,
        projectName,
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
  const speechGenerationIds = [];
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
    } else if (meta.feature === FEATURE.SPEECH_GENERATION) {
      speechGenerationIds.push(meta.speechGenerationId || tx.reference);
      if (meta.projectId) projectIds.push(meta.projectId);
    } else if (meta.feature === FEATURE.REMOTION_EXPORT) {
      renderIds.push(meta.renderId || tx.reference);
      if (meta.projectId) projectIds.push(meta.projectId);
    }
  }

  const [heygenRows, speechRows, renderRows] = await Promise.all([
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
    speechGenerationIds.length
      ? prisma.speechGeneration.findMany({
          where: { id: { in: uniqueIds(speechGenerationIds) } },
          select: {
            id: true,
            projectId: true,
            sceneId: true,
            voiceId: true,
            script: true,
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
  for (const row of speechRows) {
    if (row.projectId) projectIds.push(row.projectId);
  }
  for (const row of renderRows) {
    if (row.projectId) projectIds.push(row.projectId);
  }

  const needsProjectData = heygenVideoIds.length > 0 || speechGenerationIds.length > 0;

  const [projects, workspaces] = await Promise.all([
    projectIds.length
      ? prisma.project.findMany({
          where: { id: { in: uniqueIds(projectIds) } },
          select: {
            id: true,
            name: true,
            ...(needsProjectData ? { data: true } : {}),
          },
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
    speechById: new Map(speechRows.map((row) => [row.id, row])),
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
  resolveSceneNameFromProjectData,
  FEATURE_LABELS,
};
