const fs = require("fs");
const os = require("os");
const path = require("path");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const AppError = require("../shared/utils/AppError");
const messages = require("../shared/utils/messages");

const storage = multer.memoryStorage();

/** Workspace media library uploads (images, video, audio). */
const MAX_LIBRARY_UPLOAD_BYTES = 1024 * 1024 * 1024; // 1 GB

const ASSET_MIME_TYPES = [
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/svg+xml",
  "video/mp4",
  "audio/mp3",
  "audio/mpeg",
];

const uploadProfile = multer({
  storage,
  limits: {
    fileSize: 2 * 1024 * 1024, // 2MB
    files: 1 // allow only one file
  },
  fileFilter: (req, file, cb) => {

    const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new AppError(messages.INVALID_IMAGE_TYPE, 400));
    }

    cb(null, true);
  }
});

const uploadAssetS3 = multer({
  storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB
    files: 1 // allow only one file
  },
  fileFilter: (req, file, cb) => {
    if (!ASSET_MIME_TYPES.includes(file.mimetype)) {
      return cb(new AppError(messages.INVALID_FILE_TYPE, 400));
    }

    cb(null, true);
  }
});

/**
 * Library uploads up to 1 GB. Written to a temp file and streamed to S3 — holding files this
 * size in memory (memoryStorage) would exhaust the server. The temp file is always removed
 * once the response is done (see removeUploadedTempFile).
 */
const uploadLibraryAsset = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, os.tmpdir()),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || "") || "";
      cb(null, `asset-upload-${uuidv4()}${ext}`);
    },
  }),
  limits: {
    fileSize: MAX_LIBRARY_UPLOAD_BYTES,
    files: 1,
  },
  fileFilter: (req, file, cb) => {
    if (!ASSET_MIME_TYPES.includes(file.mimetype)) {
      return cb(new AppError(messages.INVALID_FILE_TYPE, 400));
    }
    cb(null, true);
  },
});

/** Delete a disk-stored upload when the request ends — success, validation error or failure. */
function removeUploadedTempFile(req, res, next) {
  const cleanup = () => {
    const filePath = req.file?.path;
    if (filePath) fs.promises.unlink(filePath).catch(() => {});
  };
  res.once("finish", cleanup);
  res.once("close", cleanup);
  next();
}


module.exports = {
  uploadProfile,
  uploadAssetS3,
  uploadLibraryAsset,
  removeUploadedTempFile,
  MAX_LIBRARY_UPLOAD_BYTES,
};