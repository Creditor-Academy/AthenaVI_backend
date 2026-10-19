const crypto = require('crypto');
const presentationDao = require('./presentation.dao');

/**
 * Stable brief hash for image cache lookup.
 * @param {{ searchQuery: string, imageStyle?: string, colorTreatment?: string, tier?: string }} brief
 */
function hashBrief({ searchQuery, imageStyle, colorTreatment, tier }) {
  const payload = [
    String(searchQuery || '').trim().toLowerCase(),
    String(imageStyle || '').trim().toLowerCase(),
    String(colorTreatment || '').trim().toLowerCase(),
    String(tier || 'standard').trim().toLowerCase(),
  ].join('|');

  return crypto.createHash('sha256').update(payload).digest('hex');
}

async function getOrNull(briefHash) {
  if (!briefHash) return null;
  return presentationDao.findImageCacheByHash(String(briefHash));
}

async function put({ briefHash, s3Key, url, source, metadata }) {
  return presentationDao.createImageCache({
    briefHash,
    s3Key,
    url: url ?? null,
    source,
    metadata: metadata ?? null,
  });
}

module.exports = {
  hashBrief,
  getOrNull,
  put,
};
