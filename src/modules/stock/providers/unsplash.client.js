const path = require('path');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const {
  buildUnsplashPhotoAttribution,
  normalizeUnsplashPhoto,
} = require('./normalize');

const UNSPLASH_BASE = 'https://api.unsplash.com';

function isConfigured() {
  const key = process.env.UNSPLASH_ACCESS_KEY;
  return Boolean(key && String(key).trim());
}

function getAccessKey() {
  const key = process.env.UNSPLASH_ACCESS_KEY;
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

async function unsplashFetch(pathname, searchParams) {
  const url = `${UNSPLASH_BASE}${pathname}${buildQueryString(searchParams)}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Client-ID ${getAccessKey()}`,
      'Accept-Version': 'v1',
    },
  });

  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  if (!res.ok) {
    const msg =
      body?.errors?.[0] ||
      body?.error ||
      res.statusText ||
      messages.STOCK_PROVIDER_REQUEST_FAILED;
    const status = res.status === 429 ? 429 : res.status >= 400 && res.status < 600 ? res.status : 502;
    throw new AppError(msg, status);
  }

  return body;
}

async function searchPhotos({ q, page = 1, perPage = 20 }) {
  const data = await unsplashFetch('/search/photos', {
    query: q,
    page,
    per_page: perPage,
  });

  const photos = Array.isArray(data.results) ? data.results : [];
  return {
    items: photos.map(normalizeUnsplashPhoto),
    page: data.page || page,
    perPage: data.per_page || perPage,
    totalResults: data.total ?? photos.length,
    totalPages: data.total_pages ?? null,
  };
}

async function getPhotoById(externalId) {
  const data = await unsplashFetch(`/photos/${encodeURIComponent(externalId)}`);
  if (!data || !data.id) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }
  return data;
}

function contentTypeFromUrl(downloadUrl) {
  try {
    const ext = path.extname(new URL(downloadUrl).pathname).toLowerCase();
    const map = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.webp': 'image/webp',
    };
    return map[ext] || 'image/jpeg';
  } catch {
    return 'image/jpeg';
  }
}

function extensionFromContentType(contentType) {
  const map = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp',
  };
  return map[contentType] || '.jpg';
}

async function trackPhotoDownload(externalId) {
  const data = await unsplashFetch(`/photos/${encodeURIComponent(externalId)}/download`);
  const downloadUrl = data?.url && String(data.url).trim() ? String(data.url).trim() : null;
  if (!downloadUrl) {
    throw new AppError(messages.STOCK_ITEM_NOT_FOUND, 404);
  }
  return downloadUrl;
}

function resolvePhotoImport(photo, downloadUrl) {
  const photographer = photo.user?.name || 'Unknown';
  const contentType = contentTypeFromUrl(downloadUrl);
  const photographerProfileUrl = photo.user?.links?.html || null;

  return {
    downloadUrl,
    contentType,
    fileName: `unsplash-photo-${photo.id}${extensionFromContentType(contentType)}`,
    stockMetadata: {
      provider: 'unsplash',
      externalId: String(photo.id),
      mediaType: 'photo',
      photographer,
      photographerProfileUrl,
      attribution: buildUnsplashPhotoAttribution(photographer),
      pageUrl: photo.links?.html || `https://unsplash.com/photos/${photo.id}`,
      width: photo.width,
      height: photo.height,
    },
  };
}

async function resolveImportSource({ externalId }) {
  const photo = await getPhotoById(externalId);
  const downloadUrl = await trackPhotoDownload(externalId);
  return resolvePhotoImport(photo, downloadUrl);
}

module.exports = {
  isConfigured,
  searchPhotos,
  resolveImportSource,
};
