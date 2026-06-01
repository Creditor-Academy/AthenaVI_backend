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

function collectAssetIds(projectData) {
  const assetIds = new Set();

  for (const scene of projectData?.scenes || []) {
    const backgroundAssetId = extractAssetId(scene.background);
    if (backgroundAssetId) {
      assetIds.add(backgroundAssetId);
    }

    for (const element of scene.elements || []) {
      const assetId = extractAssetId(element.content);
      if (assetId) {
        assetIds.add(assetId);
      }
    }
  }

  return [...assetIds];
}

module.exports = {
  extractAssetId,
  collectAssetIds,
};
