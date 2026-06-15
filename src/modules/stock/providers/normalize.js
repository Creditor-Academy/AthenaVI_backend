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

module.exports = {
  buildPexelsPhotoAttribution,
  buildPexelsVideoAttribution,
  normalizePexelsPhoto,
  normalizePexelsVideo,
};
