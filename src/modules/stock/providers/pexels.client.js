const path = require('path');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const {
  buildPexelsPhotoAttribution,
  buildPexelsVideoAttribution,
  normalizePexelsPhoto,
  normalizePexelsVideo,
} = require('./normalize');

const PEXELS_BASE = 'https://api.pexels.com';

function isConfigured() {
  const key = process.env.PEXELS_API_KEY;
  return Boolean(key && String(key).trim());
}

function getApiKey() {
  const key = process.env.PEXELS_API_KEY;
  if (!key || !String(key).trim()) {
    throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
  }
  return String(key).trim();
}

function buildQueryString(query) {
  if (!query || typeof query !== 'object') return '';
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue;
    params.set(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : '';
}

async function pexelsFetch(pathname, searchParams) {
  const url = `${PEXELS_BASE}${pathname}${buildQueryString(searchParams)}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: getApiKey(),
    },
  });

  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  if (!res.ok) {
    const msg = body?.error || res.statusText || messages.STOCK_PROVIDER_REQUEST_FAILED;
    const status = res.status === 429 ? 429 : res.status >= 400 && res.status < 600 ? res.status : 502;
    throw new AppError(msg, status);
  }

  return body;
}

async function searchPhotos({ q, page = 1, perPage = 20 }) {
  const data = await pexelsFetch('/v1/search', {
    query: q,
    page,
    per_page: perPage,
  });

  const photos = Array.isArray(data.photos) ? data.photos : [];
  return {
    items: photos.map(normalizePexelsPhoto),
    page: data.page || page,
    perPage: data.per_page || perPage,
    totalResults: data.total_results ?? photos.length,
    nextPage: data.next_page || null,
  };
}

async function searchVideos({ q, page = 1, perPage = 20 }) {
  const data = await pexelsFetch('/videos/search', {
    query: q,
    page,
    per_page: perPage,
  });

  const videos = Array.isArray(data.videos) ? data.videos : [];
  return {
    items: videos.map(normalizePexelsVideo),
    page: data.page || page,
    perPage: data.per_page || perPage,
    totalResults: data.total_results ?? videos.length,
    nextPage: data.next_page || null,
  };
}

async function getPhotoById(externalId) {
  const data = await pexelsFetch(`/v1/photos/${encodeURIComponent(externalId)}`);
  if (!data || !data.id) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }
  return data;
}

async function getVideoById(externalId) {
  const data = await pexelsFetch(`/videos/videos/${encodeURIComponent(externalId)}`);
  if (!data || !data.id) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }
  return data;
}

function pickBestVideoFile(videoFiles) {
  const files = Array.isArray(videoFiles) ? videoFiles : [];
  const mp4Files = files.filter((f) => f.file_type === 'video/mp4' && f.link);
  if (!mp4Files.length) {
    return files.find((f) => f.link) || null;
  }

  const qualityRank = { hd: 3, sd: 2, hls: 1 };
  return mp4Files.sort((a, b) => {
    const qa = qualityRank[a.quality] || 0;
    const qb = qualityRank[b.quality] || 0;
    if (qb !== qa) return qb - qa;
    return (b.width || 0) - (a.width || 0);
  })[0];
}

function extensionFromContentType(contentType, fallback = '.bin') {
  const map = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp',
    'video/mp4': '.mp4',
  };
  return map[contentType] || fallback;
}

function resolvePhotoImport(photo) {
  const downloadUrl = photo.src?.original || photo.src?.large2x || photo.src?.large;
  if (!downloadUrl) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }

  const photographer = photo.photographer || 'Unknown';
  const urlPath = new URL(downloadUrl).pathname;
  const ext = path.extname(urlPath) || '.jpg';

  return {
    downloadUrl,
    contentType: 'image/jpeg',
    fileName: `pexels-photo-${photo.id}${ext}`,
    stockMetadata: {
      provider: 'pexels',
      externalId: String(photo.id),
      mediaType: 'photo',
      photographer,
      attribution: buildPexelsPhotoAttribution(photographer),
      pageUrl: photo.url || `https://www.pexels.com/photo/${photo.id}/`,
      width: photo.width,
      height: photo.height,
    },
  };
}

function resolveVideoImport(video) {
  const file = pickBestVideoFile(video.video_files);
  if (!file?.link) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }

  const photographer = video.user?.name || 'Unknown';
  const contentType = file.file_type || 'video/mp4';

  return {
    downloadUrl: file.link,
    contentType,
    fileName: `pexels-video-${video.id}${extensionFromContentType(contentType, '.mp4')}`,
    stockMetadata: {
      provider: 'pexels',
      externalId: String(video.id),
      mediaType: 'video',
      photographer,
      attribution: buildPexelsVideoAttribution(photographer),
      pageUrl: video.url || `https://www.pexels.com/video/${video.id}/`,
      width: video.width,
      height: video.height,
      durationSec: video.duration,
    },
  };
}

async function resolveImportSource({ externalId, mediaType }) {
  if (mediaType === 'video') {
    const video = await getVideoById(externalId);
    return resolveVideoImport(video);
  }

  const photo = await getPhotoById(externalId);
  return resolvePhotoImport(photo);
}

module.exports = {
  isConfigured,
  searchPhotos,
  searchVideos,
  resolveImportSource,
};
