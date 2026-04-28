const multer = require('multer');
const AppError = require('../shared/utils/AppError');
const messages = require('../shared/utils/messages');

const storage = multer.memoryStorage();

const allowedMime = new Set([
  'image/png',
  'image/jpeg',
  'video/mp4',
  'video/webm',
  'audio/mpeg',
  'audio/mp3',
  'audio/wav',
  'audio/x-wav',
  'application/pdf',
]);

const uploadHeygenAsset = multer({
  storage,
  limits: { fileSize: 32 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (!allowedMime.has(file.mimetype)) {
      return cb(new AppError(messages.HEYGEN_INVALID_ASSET_TYPE, 400));
    }
    cb(null, true);
  },
});

module.exports = { uploadHeygenAsset };
