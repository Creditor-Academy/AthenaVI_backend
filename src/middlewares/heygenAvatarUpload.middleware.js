const fs = require('fs');
const os = require('os');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const AppError = require('../shared/utils/AppError');
const { HEYGEN_AVATAR_TWIN_MIMES } = require('./heygenAvatarCreate.middleware');

const MAX_BYTES = 900 * 1024 * 1024;

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, os.tmpdir());
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '';
    cb(null, `heygen-avatar-${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (!HEYGEN_AVATAR_TWIN_MIMES.has(file.mimetype)) {
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

function heygenAvatarFileUpload(req, res, next) {
  return upload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return next(new AppError('File too large (max 900 MB for HeyGen avatar file upload)', 400));
      }
      return next(err);
    }
    if (!req.file) {
      return next(new AppError('file is required', 400));
    }
    next();
  });
}

function cleanupHeygenAvatarUploadFile(file) {
  if (!file?.path) return;
  fs.unlink(file.path, () => {});
}

module.exports = {
  heygenAvatarFileUpload,
  cleanupHeygenAvatarUploadFile,
  HEYGEN_AVATAR_UPLOAD_MAX_BYTES: MAX_BYTES,
};
