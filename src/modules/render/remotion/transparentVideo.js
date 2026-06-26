function isWebmSource(value) {
  if (value == null || String(value).trim() === '') {
    return false;
  }
  return /\.webm(?:$|[?#])/i.test(String(value));
}

function isTransparentVideoSource(content = {}) {
  if (content.hasAlpha === true || content.outputFormat === 'webm') {
    return true;
  }

  if (String(content.mimeType || '').toLowerCase() === 'video/webm') {
    return true;
  }

  return (
    isWebmSource(content.assetKey) ||
    isWebmSource(content.src) ||
    isWebmSource(content.s3Key)
  );
}

function resolveCanvasBackgroundColor(videoSettings = {}, sceneBackground) {
  if (
    sceneBackground?.type === 'color' &&
    sceneBackground.value &&
    sceneBackground.value !== 'transparent'
  ) {
    return sceneBackground.value;
  }

  const fromSettings = videoSettings.backgroundColor;
  if (fromSettings && fromSettings !== 'transparent') {
    return fromSettings;
  }

  return '#000000';
}

module.exports = {
  isTransparentVideoSource,
  resolveCanvasBackgroundColor,
};
