const messages = require('../../shared/utils/messages');
const assetDao = require('../asset/asset.dao');
const pexelsClient = require('./providers/pexels.client');
const { downloadRemote } = require('../../shared/utils/downloadRemote');
const { getStockMaxBytesForMediaType } = require('../../shared/config/stockLimits');
const AppError = require('../../shared/utils/AppError');
const { persistWorkspaceAsset } = require('../asset/asset.service');

const SUPPORTED_PROVIDERS = new Set(['pexels']);

async function searchStock({ q, type, page, perPage }) {
  if (type === 'video') {
    return pexelsClient.searchVideos({ q, page, perPage });
  }
  return pexelsClient.searchPhotos({ q, page, perPage });
}

async function importStockAsset({ userId, workspace, provider, externalId, mediaType, name }) {
  if (!SUPPORTED_PROVIDERS.has(provider)) {
    throw new AppError(messages.STOCK_PROVIDER_NOT_SUPPORTED, 400);
  }

  const existing = await assetDao.findStockAssetByExternalId(
    workspace.id,
    provider,
    String(externalId)
  );
  if (existing) {
    return existing;
  }

  const importSource = await pexelsClient.resolveImportSource({ externalId, mediaType });
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
