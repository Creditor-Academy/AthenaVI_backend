const DEFAULT_PHOTO_MAX_BYTES = 15 * 1024 * 1024;
const DEFAULT_VIDEO_MAX_BYTES = 100 * 1024 * 1024;

function parsePositiveInt(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

function getStockPhotoMaxBytes() {
  return parsePositiveInt(process.env.STOCK_PHOTO_MAX_BYTES, DEFAULT_PHOTO_MAX_BYTES);
}

function getStockVideoMaxBytes() {
  return parsePositiveInt(process.env.STOCK_VIDEO_MAX_BYTES, DEFAULT_VIDEO_MAX_BYTES);
}

function getStockMaxBytesForMediaType(mediaType) {
  return mediaType === 'video' ? getStockVideoMaxBytes() : getStockPhotoMaxBytes();
}

module.exports = {
  getStockPhotoMaxBytes,
  getStockVideoMaxBytes,
  getStockMaxBytesForMediaType,
};
