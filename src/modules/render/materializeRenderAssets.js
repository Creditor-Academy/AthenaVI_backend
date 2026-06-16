const fs = require('fs/promises');
const os = require('os');
const path = require('path');

const { downloadObjectToFile } = require('../s3/s3.service');

const downloadCache = new Map();

function extensionFromKey(key, fallback = '.bin') {
  const ext = path.extname(String(key || ''));
  return ext || fallback;
}

async function downloadKeyOnce(key, tempDir, basename) {
  const cacheKey = `${tempDir}::${key}`;
  if (downloadCache.has(cacheKey)) {
    return downloadCache.get(cacheKey);
  }

  const destPath = path.join(tempDir, `${basename}${extensionFromKey(key)}`);
  const task = downloadObjectToFile(key, destPath).then(() => destPath);
  downloadCache.set(cacheKey, task);
  return task;
}

function clearDownloadCache() {
  downloadCache.clear();
}

async function materializeBackground(background, tempDir, sceneId) {
  if (!background || background.type === 'color') {
    return background;
  }

  const key = background.assetKey;
  if (key) {
    const localSrc = await downloadKeyOnce(key, tempDir, `scene-${sceneId}-background`);
    return { ...background, src: localSrc };
  }

  return background;
}

async function materializeContent(content, tempDir, sceneId, elementId) {
  if (!content || typeof content !== 'object') {
    return content;
  }

  const next = { ...content };

  if (content.assetKey) {
    next.src = await downloadKeyOnce(
      content.assetKey,
      tempDir,
      `scene-${sceneId}-element-${elementId}`
    );
  }

  if (content.fill && typeof content.fill === 'object' && content.fill.assetKey) {
    next.fill = {
      ...content.fill,
      src: await downloadKeyOnce(
        content.fill.assetKey,
        tempDir,
        `scene-${sceneId}-element-${elementId}-fill`
      ),
    };
  }

  return next;
}

async function materializeScene(scene, tempDir) {
  const sceneId = scene.sceneId || 'unknown';
  const elements = [];

  for (const element of scene.elements || []) {
    elements.push({
      ...element,
      content: await materializeContent(element.content, tempDir, sceneId, element.id || 'media'),
    });
  }

  return {
    ...scene,
    background: await materializeBackground(scene.background, tempDir, sceneId),
    elements,
  };
}

async function materializeSceneCompositionInput({ scene, videoSettings }, tempDir) {
  return {
    videoSettings,
    scene: await materializeScene(scene, tempDir),
  };
}

async function materializeProjectSceneClip(scene, tempDir) {
  if (!scene.s3Key) {
    return scene;
  }

  const localSrc = await downloadKeyOnce(
    scene.s3Key,
    tempDir,
    `clip-${scene.sceneId || 'scene'}-${scene.sceneHash || 'cache'}`
  );

  return {
    ...scene,
    src: localSrc,
  };
}

async function materializeProjectCompositionInput({ scenes, videoSettings }, tempDir) {
  const materializedScenes = [];
  for (const scene of scenes || []) {
    materializedScenes.push(await materializeProjectSceneClip(scene, tempDir));
  }

  return {
    videoSettings,
    scenes: materializedScenes,
  };
}

async function ensureTempAssetsDirectory(renderId, suffix = 'assets') {
  const directory = path.join(os.tmpdir(), 'athena-video-renders', renderId, suffix);
  await fs.mkdir(directory, { recursive: true });
  return directory;
}

module.exports = {
  clearDownloadCache,
  materializeSceneCompositionInput,
  materializeProjectCompositionInput,
  ensureTempAssetsDirectory,
};
