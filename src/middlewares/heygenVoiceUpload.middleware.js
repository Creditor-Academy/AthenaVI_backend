const fs = require('fs');
const os = require('os');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const AppError = require('../shared/utils/AppError');

const MAX_BYTES = 100 * 1024 * 1024;

const HEYGEN_VOICE_CLONE_MIMES = new Set([
  'audio/mpeg',
  'audio/mp3',
  'audio/wav',
  'audio/x-wav',
  'audio/webm',
  'video/mp4',
  'video/webm',
]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, os.tmpdir());
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '';
    cb(null, `heygen-voice-${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    if (!HEYGEN_VOICE_CLONE_MIMES.has(file.mimetype)) {
      return cb(
        new AppError(
          'Unsupported file type; use audio/mpeg, audio/wav, audio/webm, video/mp4, or video/webm',
          400
        )
      );
    }
    cb(null, true);
  },
});

function heygenVoiceFileUpload(req, res, next) {
  return upload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return next(new AppError('File too large (max 100 MB for HeyGen voice clone upload)', 400));
      }
      return next(err);
    }
    if (!req.file) {
      return next(new AppError('file is required', 400));
    }
    next();
  });
}

/** Multipart POST /api/heygen/voices/clone — JSON requests skip multer. */
function heygenVoiceCloneMultipart(req, res, next) {
  const ct = String(req.headers['content-type'] || '').toLowerCase();
  if (!ct.includes('multipart/form-data')) {
    return next();
  }
  return upload.single('file')(req, res, (err) => {
    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return next(new AppError('File too large (max 100 MB for HeyGen voice clone upload)', 400));
      }
      return next(err);
    }
    if (!req.file) {
      return next(
        new AppError(
          'file is required for multipart voice clone (or use JSON with audio.type url from POST /api/heygen/voices/upload)',
          400
        )
      );
    }
    next();
  });
}

function cleanupHeygenVoiceUploadFile(file) {
  if (!file?.path) return;
  fs.unlink(file.path, () => {});
}

module.exports = {
  heygenVoiceFileUpload,
  heygenVoiceCloneMultipart,
  cleanupHeygenVoiceUploadFile,
  HEYGEN_VOICE_CLONE_MIMES,
  HEYGEN_VOICE_UPLOAD_MAX_BYTES: MAX_BYTES,
};
