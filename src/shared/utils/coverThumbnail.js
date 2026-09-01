const s3Service = require('../../modules/s3/s3.service');

const PRESIGN_TTL_SECONDS = 3600;

function isUsableUrl(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  if (
    text.startsWith('http://') ||
    text.startsWith('https://') ||
    text.startsWith('data:') ||
    text.startsWith('/')
  ) {
    return text;
  }
  return null;
}

function isPresignedUrl(url) {
  return /[?&]X-Amz-/i.test(String(url || ''));
}

function firstUsableUrl(...candidates) {
  for (const candidate of candidates) {
    if (candidate == null || candidate === '') continue;
    if (typeof candidate === 'object') {
      const nested = firstUsableUrl(
        candidate.url,
        candidate.presignedUrl,
        candidate.src,
        candidate.thumbnail,
        candidate.thumbnailUrl,
        candidate.previewImage,
        candidate.poster,
        candidate.avatar
      );
      if (nested) return nested;
      continue;
    }
    const url = isUsableUrl(candidate);
    if (url) return url;
  }
  return null;
}

function slideElements(slide) {
  if (Array.isArray(slide?.elements?.elements)) return slide.elements.elements;
  if (Array.isArray(slide?.elements)) return slide.elements;
  return [];
}

function extractSlideCover(slide) {
  if (!slide || typeof slide !== 'object') {
    return { url: null, s3Key: null };
  }

  const imageRef = slide.imageRef;
  const refKey =
    imageRef && typeof imageRef === 'object' ? imageRef.s3Key || null : null;
  const elements = slideElements(slide);
  const imageEl = elements.find(
    (el) =>
      (el?.type === 'image' || el?.type === 'icon' || el?.type === 'background') &&
      (el?.content?.url || el?.content?.src || el?.content?.s3Key)
  );
  const content = slide.content && typeof slide.content === 'object' ? slide.content : {};
  const url = firstUsableUrl(
    imageEl?.content,
    typeof imageRef === 'string' ? imageRef : imageRef,
    content.imageUrl,
    content.image,
    content.heroImage,
    content.backgroundImage
  );
  const s3Key =
    imageEl?.content?.s3Key ||
    refKey ||
    s3Service.extractS3KeyFromUrl(url) ||
    null;

  return { url, s3Key };
}

function extractVideoCover(data) {
  const scenes = Array.isArray(data?.scenes) ? data.scenes : [];
  const scene = scenes[0] || data?.coverScene || null;
  if (!scene || typeof scene !== 'object') {
    return { url: null, s3Key: null };
  }

  const clips = Array.isArray(scene.clips) ? scene.clips : [];
  const avatarClip = clips.find(
    (clip) =>
      String(clip?.type || '').toLowerCase() === 'avatar' ||
      String(clip?.kind || '').toLowerCase() === 'avatar'
  );
  const imageClip = clips.find((clip) => String(clip?.type || '').toLowerCase() === 'image');
  const videoClip = clips.find((clip) => String(clip?.type || '').toLowerCase() === 'video');
  const bg = scene.background && typeof scene.background === 'object' ? scene.background.value : scene.background;

  const url = firstUsableUrl(
    scene.thumbnail,
    scene.thumbnailUrl,
    scene.previewImage,
    scene.avatar,
    scene.cover,
    scene.backgroundImage,
    bg,
    avatarClip,
    imageClip,
    videoClip?.poster,
    videoClip?.thumbnail,
    videoClip
  );

  return {
    url,
    s3Key: s3Service.extractS3KeyFromUrl(url),
  };
}

async function toCoverUrls({ url, s3Key } = {}) {
  const key = s3Key || s3Service.extractS3KeyFromUrl(url);
  if (key) {
    let displayUrl = null;
    try {
      displayUrl = await s3Service.getPresignedGetUrl(key, PRESIGN_TTL_SECONDS);
    } catch {
      displayUrl = null;
    }
    const persistUrl = s3Service.buildPublicUrl(key);
    return {
      displayUrl: displayUrl || url || persistUrl,
      persistUrl,
    };
  }
  if (!url) return { displayUrl: null, persistUrl: null };
  return {
    displayUrl: url,
    persistUrl: isPresignedUrl(url) ? null : url,
  };
}

async function persistCoverIfEmpty(prisma, projectId, persistUrl) {
  if (!prisma || !projectId || !persistUrl || isPresignedUrl(persistUrl)) return;
  if (String(persistUrl).startsWith('data:')) return;
  try {
    await prisma.project.updateMany({
      where: {
        id: projectId,
        OR: [{ thumbnail: null }, { thumbnail: '' }],
      },
      data: { thumbnail: persistUrl },
    });
  } catch {
    // cover persist is best-effort
  }
}

module.exports = {
  firstUsableUrl,
  extractSlideCover,
  extractVideoCover,
  toCoverUrls,
  persistCoverIfEmpty,
};
