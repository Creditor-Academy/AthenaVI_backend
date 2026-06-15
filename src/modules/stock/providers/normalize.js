function buildPexelsPhotoAttribution(photographer) {
  const name = photographer && String(photographer).trim() ? String(photographer).trim() : 'Unknown';
  return `Photo by ${name} on Pexels`;
}

function buildPexelsVideoAttribution(photographer) {
  const name = photographer && String(photographer).trim() ? String(photographer).trim() : 'Unknown';
  return `Video by ${name} on Pexels`;
}

function normalizePexelsPhoto(photo) {
  const photographer = photo.photographer || 'Unknown';
  return {
    provider: 'pexels',
    externalId: String(photo.id),
    mediaType: 'photo',
    previewUrl: photo.src?.medium || photo.src?.large || photo.src?.original || '',
    width: photo.width,
    height: photo.height,
    photographer,
    attribution: buildPexelsPhotoAttribution(photographer),
    pageUrl: photo.url || `https://www.pexels.com/photo/${photo.id}/`,
  };
}

function pickPreviewVideoFile(videoFiles) {
  const files = Array.isArray(videoFiles) ? videoFiles : [];
  const mp4Files = files.filter((f) => f.file_type === 'video/mp4' && f.link);
  if (!mp4Files.length) {
    return files.find((f) => f.link && String(f.file_type || '').startsWith('video/')) || null;
  }

  return mp4Files.sort((a, b) => (a.width || 0) - (b.width || 0))[0];
}

function normalizePexelsVideo(video) {
  const photographer = video.user?.name || 'Unknown';
  const previewPicture = Array.isArray(video.video_pictures) ? video.video_pictures[0] : null;
  const previewFile = pickPreviewVideoFile(video.video_files);
  return {
    provider: 'pexels',
    externalId: String(video.id),
    mediaType: 'video',
    previewUrl: previewPicture?.picture || video.image || '',
    previewVideoUrl: previewFile?.link || '',
    width: video.width,
    height: video.height,
    durationSec: video.duration,
    photographer,
    attribution: buildPexelsVideoAttribution(photographer),
    pageUrl: video.url || `https://www.pexels.com/video/${video.id}/`,
  };
}

function buildUnsplashPhotoAttribution(photographer) {
  const name = photographer && String(photographer).trim() ? String(photographer).trim() : 'Unknown';
  return `Photo by ${name} on Unsplash`;
}

function normalizeUnsplashPhoto(photo) {
  const photographer = photo.user?.name || 'Unknown';
  return {
    provider: 'unsplash',
    externalId: String(photo.id),
    mediaType: 'photo',
    previewUrl: photo.urls?.regular || photo.urls?.small || photo.urls?.thumb || '',
    width: photo.width,
    height: photo.height,
    photographer,
    attribution: buildUnsplashPhotoAttribution(photographer),
    pageUrl: photo.links?.html || `https://unsplash.com/photos/${photo.id}`,
  };
}

function buildPixabayPhotoAttribution(photographer) {
  const name = photographer && String(photographer).trim() ? String(photographer).trim() : 'Unknown';
  return `Image by ${name} on Pixabay`;
}

function buildPixabayVideoAttribution(photographer) {
  const name = photographer && String(photographer).trim() ? String(photographer).trim() : 'Unknown';
  return `Video by ${name} on Pixabay`;
}

function pickPixabayPreviewVideo(videos) {
  if (!videos || typeof videos !== 'object') return null;
  return videos.small || videos.medium || videos.tiny || videos.large || null;
}

function pickPixabayImportVideo(videos) {
  if (!videos || typeof videos !== 'object') return null;
  return videos.large || videos.medium || videos.small || videos.tiny || null;
}

function normalizePixabayPhoto(hit) {
  const photographer = hit.user || 'Unknown';
  return {
    provider: 'pixabay',
    externalId: String(hit.id),
    mediaType: 'photo',
    previewUrl: hit.previewURL || hit.webformatURL || '',
    width: hit.imageWidth,
    height: hit.imageHeight,
    photographer,
    attribution: buildPixabayPhotoAttribution(photographer),
    pageUrl: hit.pageURL || `https://pixabay.com/photos/${hit.id}/`,
  };
}

function normalizePixabayVideo(hit) {
  const photographer = hit.user || 'Unknown';
  const previewVideo = pickPixabayPreviewVideo(hit.videos);
  const thumbnail =
    previewVideo?.thumbnail ||
    hit.videos?.medium?.thumbnail ||
    hit.videos?.small?.thumbnail ||
    hit.picture_id ||
    '';
  return {
    provider: 'pixabay',
    externalId: String(hit.id),
    mediaType: 'video',
    previewUrl: thumbnail,
    previewVideoUrl: previewVideo?.url || '',
    width: hit.videos?.large?.width || hit.videos?.medium?.width,
    height: hit.videos?.large?.height || hit.videos?.medium?.height,
    durationSec: hit.duration,
    photographer,
    attribution: buildPixabayVideoAttribution(photographer),
    pageUrl: hit.pageURL || `https://pixabay.com/videos/${hit.id}/`,
  };
}

module.exports = {
  buildPexelsPhotoAttribution,
  buildPexelsVideoAttribution,
  buildUnsplashPhotoAttribution,
  buildPixabayPhotoAttribution,
  buildPixabayVideoAttribution,
  pickPixabayPreviewVideo,
  pickPixabayImportVideo,
  normalizePexelsPhoto,
  normalizePexelsVideo,
  normalizeUnsplashPhoto,
  normalizePixabayPhoto,
  normalizePixabayVideo,
};
