const messages = require('../../shared/utils/messages');
const assetDao = require('../asset/asset.dao');
const pexelsClient = require('./providers/pexels.client');
const unsplashClient = require('./providers/unsplash.client');
const pixabayClient = require('./providers/pixabay.client');
const { downloadRemote } = require('../../shared/utils/downloadRemote');
const { getStockMaxBytesForMediaType } = require('../../shared/config/stockLimits');
const AppError = require('../../shared/utils/AppError');
const { persistWorkspaceAsset } = require('../asset/asset.service');

const SUPPORTED_PROVIDERS = new Set(['pexels', 'unsplash', 'pixabay']);

const IMPORT_RESOLVERS = {
  pexels: pexelsClient.resolveImportSource,
  unsplash: unsplashClient.resolveImportSource,
  pixabay: pixabayClient.resolveImportSource,
};

function interleaveMany(lists, limit) {
  const merged = [];
  const maxLen = Math.max(0, ...lists.map((list) => list.length));
  for (let i = 0; i < maxLen && merged.length < limit; i += 1) {
    for (const list of lists) {
      if (i < list.length && merged.length < limit) {
        merged.push(list[i]);
      }
    }
  }
  return merged;
}

function assertAtLeastOneProviderConfigured() {
  if (
    !pexelsClient.isConfigured() &&
    !unsplashClient.isConfigured() &&
    !pixabayClient.isConfigured()
  ) {
    throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
  }
}

async function runConfiguredSearches(searchFns) {
  const tasks = [];
  const results = searchFns.map(() => ({ items: [], totalResults: 0 }));

  searchFns.forEach((fn, index) => {
    if (fn) {
      tasks.push(
        fn().then((result) => {
          results[index] = result;
        })
      );
    }
  });

  await Promise.all(tasks);
  return results;
}

async function searchAllPhotos({ q, page, perPage }) {
  assertAtLeastOneProviderConfigured();

  const results = await runConfiguredSearches([
    pexelsClient.isConfigured() ? () => pexelsClient.searchPhotos({ q, page, perPage }) : null,
    unsplashClient.isConfigured() ? () => unsplashClient.searchPhotos({ q, page, perPage }) : null,
    pixabayClient.isConfigured() ? () => pixabayClient.searchPhotos({ q, page, perPage }) : null,
  ]);

  return {
    items: interleaveMany(
      results.map((r) => r.items),
      perPage
    ),
    page,
    perPage,
    totalResults: results.reduce((sum, r) => sum + (r.totalResults || 0), 0),
    nextPage: null,
  };
}

async function searchAllVideos({ q, page, perPage }) {
  assertAtLeastOneProviderConfigured();

  const results = await runConfiguredSearches([
    pexelsClient.isConfigured() ? () => pexelsClient.searchVideos({ q, page, perPage }) : null,
    pixabayClient.isConfigured() ? () => pixabayClient.searchVideos({ q, page, perPage }) : null,
  ]);

  if (!pexelsClient.isConfigured() && !pixabayClient.isConfigured()) {
    throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
  }

  return {
    items: interleaveMany(
      results.map((r) => r.items),
      perPage
    ),
    page,
    perPage,
    totalResults: results.reduce((sum, r) => sum + (r.totalResults || 0), 0),
    nextPage: null,
  };
}

async function searchStock({ q, type, page, perPage, provider = 'all' }) {
  if (type === 'video') {
    if (provider === 'unsplash') {
      throw new AppError(messages.STOCK_VIDEO_NOT_SUPPORTED_FOR_PROVIDER, 400);
    }
    if (provider === 'pexels') {
      if (!pexelsClient.isConfigured()) {
        throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
      }
      return pexelsClient.searchVideos({ q, page, perPage });
    }
    if (provider === 'pixabay') {
      if (!pixabayClient.isConfigured()) {
        throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
      }
      return pixabayClient.searchVideos({ q, page, perPage });
    }
    return searchAllVideos({ q, page, perPage });
  }

  if (provider === 'pexels') {
    if (!pexelsClient.isConfigured()) {
      throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
    }
    return pexelsClient.searchPhotos({ q, page, perPage });
  }

  if (provider === 'unsplash') {
    if (!unsplashClient.isConfigured()) {
      throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
    }
    return unsplashClient.searchPhotos({ q, page, perPage });
  }

  if (provider === 'pixabay') {
    if (!pixabayClient.isConfigured()) {
      throw new AppError(messages.STOCK_NOT_CONFIGURED, 503);
    }
    return pixabayClient.searchPhotos({ q, page, perPage });
  }

  return searchAllPhotos({ q, page, perPage });
}

async function importStockAsset({ userId, workspace, provider, externalId, mediaType, name }) {
  if (!SUPPORTED_PROVIDERS.has(provider)) {
    throw new AppError(messages.STOCK_PROVIDER_NOT_SUPPORTED, 400);
  }

  if (provider === 'unsplash' && mediaType === 'video') {
    throw new AppError(messages.STOCK_VIDEO_NOT_SUPPORTED_FOR_PROVIDER, 400);
  }

  const existing = await assetDao.findStockAssetByExternalId(
    workspace.id,
    provider,
    String(externalId)
  );
  if (existing) {
    return existing;
  }

  const resolveImport = IMPORT_RESOLVERS[provider];
  const importSource = await resolveImport({ externalId, mediaType });
  const maxBytes = getStockMaxBytesForMediaType(mediaType);
  const buffer = await downloadRemote(importSource.downloadUrl, { maxBytes });

  const displayName =
    name?.trim() ||
    importSource.fileName ||
    `${provider}-${mediaType}-${externalId}`;

  try {
    return await persistWorkspaceAsset({
      userId,
      workspace,
      buffer,
      contentType: importSource.contentType,
      originalName: importSource.fileName,
      name: displayName,
      source: 'stock',
      stockProvider: provider,
      stockExternalId: String(externalId),
      stockMetadata: importSource.stockMetadata,
    });
  } catch (error) {
    if (error?.code === 'P2002') {
      const raced = await assetDao.findStockAssetByExternalId(
        workspace.id,
        provider,
        String(externalId)
      );
      if (raced) return raced;
    }
    throw error;
  }
}

module.exports = {
  searchStock,
  importStockAsset,
};
