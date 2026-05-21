const multer = require('multer');
const AppError = require('../shared/utils/AppError');

const MAX_BYTES = 32 * 1024 * 1024;

const ALLOWED_MIME = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'video/mp4',
  'video/webm',
]);

const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: { fileSize: MAX_BYTES },
  fileFilter: (_req, file, cb) => {
    if (!ALLOWED_MIME.has(file.mimetype)) {
      return cb(
        new AppError(
          'Unsupported file type; use image/jpeg, image/png, image/webp, video/mp4, or video/webm',
          400
        )
      );
    }
    cb(null, true);
  },
});

/**
 * For multipart create-avatar requests, parses `file` into memory.
 * JSON requests (`application/json`) skip multer.
 */
function heygenCreateAvatarMultipart(req, res, next) {
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  if (!ct.includes('multipart/form-data')) {
    return next();
  }
  return upload.single('file')(req, res, next);
}

module.exports = {
  heygenCreateAvatarMultipart,
  HEYGEN_AVATAR_PHOTO_MIMES: new Set(['image/jpeg', 'image/png', 'image/webp']),
  HEYGEN_AVATAR_TWIN_MIMES: new Set([
    'image/jpeg',
    'image/png',
    'image/webp',
    'video/mp4',
    'video/webm',
  ]),
};
