const fs = require('fs');
const os = require('os');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const AppError = require('../shared/utils/AppError');

/** Same cap as POST /api/heygen/avatars/upload — digital twin training videos can be large. */
const MAX_BYTES = 900 * 1024 * 1024;

const HEYGEN_AVATAR_PHOTO_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const HEYGEN_AVATAR_TWIN_MIMES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'video/mp4',
  'video/webm',
]);

const ALLOWED_MIME = new Set([...HEYGEN_AVATAR_PHOTO_MIMES, ...HEYGEN_AVATAR_TWIN_MIMES]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, os.tmpdir());
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '';
    cb(null, `heygen-avatar-create-${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_BYTES, files: 1 },
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
 * For multipart create-avatar requests, streams `file` to a temp path.
 * JSON requests (`application/json`) skip multer.
 */
function heygenCreateAvatarMultipart(req, res, next) {
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  if (!ct.includes('multipart/form-data')) {
    return next();
  }
  return upload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return next(
          new AppError('File too large (max 900 MB for HeyGen avatar create upload)', 400)
        );
      }
      return next(err);
    }
    next();
  });
}

function cleanupHeygenAvatarCreateFile(file) {
  if (!file?.path) return;
  fs.unlink(file.path, () => {});
}

module.exports = {
  heygenCreateAvatarMultipart,
  cleanupHeygenAvatarCreateFile,
  HEYGEN_AVATAR_PHOTO_MIMES,
  HEYGEN_AVATAR_TWIN_MIMES,
  HEYGEN_AVATAR_CREATE_MAX_BYTES: MAX_BYTES,
};
