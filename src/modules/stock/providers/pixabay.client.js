const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const {
  buildPixabayPhotoAttribution,
  buildPixabayVideoAttribution,
  pickPixabayImportVideo,
  normalizePixabayPhoto,
  normalizePixabayVideo,
} = require('./normalize');

const PIXABAY_IMAGE_BASE = 'https://pixabay.com/api/';
const PIXABAY_VIDEO_BASE = 'https://pixabay.com/api/videos/';

function isConfigured() {
  const key = process.env.PIXABAY_API_KEY;
  return Boolean(key && String(key).trim());
}

function getApiKey() {
  const key = process.env.PIXABAY_API_KEY;
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

async function pixabayFetch(baseUrl, searchParams) {
  const params = { key: getApiKey(), ...searchParams };
  const url = `${baseUrl}${buildQueryString(params)}`;
  const res = await fetch(url, { method: 'GET' });

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
  const data = await pixabayFetch(PIXABAY_IMAGE_BASE, {
    q,
    image_type: 'photo',
    page,
    per_page: perPage,
  });

  const hits = Array.isArray(data.hits) ? data.hits : [];
  return {
    items: hits.map(normalizePixabayPhoto),
    page,
    perPage,
    totalResults: data.totalHits ?? hits.length,
    totalPages: null,
  };
}

async function searchVideos({ q, page = 1, perPage = 20 }) {
  const data = await pixabayFetch(PIXABAY_VIDEO_BASE, {
    q,
    page,
    per_page: perPage,
  });

  const hits = Array.isArray(data.hits) ? data.hits : [];
  return {
    items: hits.map(normalizePixabayVideo),
    page,
    perPage,
    totalResults: data.totalHits ?? hits.length,
    totalPages: null,
  };
}

async function getPhotoHitById(externalId) {
  const data = await pixabayFetch(PIXABAY_IMAGE_BASE, { id: externalId });
  const hit = Array.isArray(data.hits) ? data.hits[0] : null;
  if (!hit?.id) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }
  return hit;
}

async function getVideoHitById(externalId) {
  const data = await pixabayFetch(PIXABAY_VIDEO_BASE, { id: externalId });
  const hit = Array.isArray(data.hits) ? data.hits[0] : null;
  if (!hit?.id) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }
  return hit;
}

function resolvePhotoImport(hit) {
  const downloadUrl = hit.largeImageURL || hit.webformatURL;
  if (!downloadUrl) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }

  const photographer = hit.user || 'Unknown';
  return {
    downloadUrl,
    contentType: 'image/jpeg',
    fileName: `pixabay-photo-${hit.id}.jpg`,
    stockMetadata: {
      provider: 'pixabay',
      externalId: String(hit.id),
      mediaType: 'photo',
      photographer,
      attribution: buildPixabayPhotoAttribution(photographer),
      pageUrl: hit.pageURL || `https://pixabay.com/photos/${hit.id}/`,
      width: hit.imageWidth,
      height: hit.imageHeight,
    },
  };
}

function resolveVideoImport(hit) {
  const file = pickPixabayImportVideo(hit.videos);
  if (!file?.url) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }

  const photographer = hit.user || 'Unknown';
  return {
    downloadUrl: file.url,
    contentType: 'video/mp4',
    fileName: `pixabay-video-${hit.id}.mp4`,
    stockMetadata: {
      provider: 'pixabay',
      externalId: String(hit.id),
      mediaType: 'video',
      photographer,
      attribution: buildPixabayVideoAttribution(photographer),
      pageUrl: hit.pageURL || `https://pixabay.com/videos/${hit.id}/`,
      width: file.width,
      height: file.height,
      durationSec: hit.duration,
    },
  };
}

async function resolveImportSource({ externalId, mediaType }) {
  if (mediaType === 'video') {
    const hit = await getVideoHitById(externalId);
    return resolveVideoImport(hit);
  }

  const hit = await getPhotoHitById(externalId);
  return resolvePhotoImport(hit);
}

module.exports = {
  isConfigured,
  searchPhotos,
  searchVideos,
  resolveImportSource,
};
