/**
 * Stock provider contract for search + import resolution.
 * Phase 1: Pexels only. Unsplash/Pixabay implement the same shape in phase 2.
 *
 * @typedef {'pexels'|'unsplash'|'pixabay'} StockProviderId
 * @typedef {'photo'|'video'} StockMediaType
 *
 * @typedef {object} StockSearchItem
 * @property {StockProviderId} provider
 * @property {string} externalId
 * @property {StockMediaType} mediaType
 * @property {string} previewUrl
 * @property {string} [previewVideoUrl]  video items only — small MP4 for hover preview
 * @property {number} [width]
 * @property {number} [height]
 * @property {number} [durationSec]
 * @property {string} photographer
 * @property {string} attribution
 * @property {string} pageUrl
 *
 * @typedef {object} StockImportSource
 * @property {string} downloadUrl
 * @property {string} contentType
 * @property {string} fileName
 * @property {object} stockMetadata
 */

module.exports = {};
