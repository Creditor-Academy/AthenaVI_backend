function extractAssetId(source) {
  if (!source || typeof source !== 'object') {
    return null;
  }

  if (typeof source.assetId === 'string' && source.assetId.trim()) {
    return source.assetId;
  }

  if (
    source.value &&
    typeof source.value === 'object' &&
    typeof source.value.assetId === 'string' &&
    source.value.assetId.trim()
  ) {
    return source.value.assetId;
  }

  return null;
}

function collectElementAssetIds(elements, assetIds) {
  for (const element of elements || []) {
    const content = element.content;
    const assetId = extractAssetId(content);
    if (assetId) {
      assetIds.add(assetId);
    }

    const fill = content && typeof content === 'object' ? content.fill : null;
    const fillAssetId = extractAssetId(fill);
    if (fillAssetId) {
      assetIds.add(fillAssetId);
    }
  }
}

function collectAssetIds(projectData) {
  const assetIds = new Set();

  for (const scene of projectData?.scenes || []) {
    const backgroundAssetId = extractAssetId(scene.background);
    if (backgroundAssetId) {
      assetIds.add(backgroundAssetId);
    }

    collectElementAssetIds(scene.elements, assetIds);
  }

  // Design-canvas documents (Project.type === 'CANVAS'): pages under `canvases[]`
  // instead of video `scenes[]`, each with its own flat `elements[]`.
  for (const page of projectData?.canvases || []) {
    const backgroundAssetId = extractAssetId(page.background);
    if (backgroundAssetId) {
      assetIds.add(backgroundAssetId);
    }

    collectElementAssetIds(page.elements, assetIds);
  }

  return [...assetIds];
}

module.exports = {
  extractAssetId,
  collectAssetIds,
};
