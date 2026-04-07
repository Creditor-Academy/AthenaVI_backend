const multer = require("multer");
const AppError = require("../shared/utils/AppError");
const messages = require("../shared/utils/messages");

const storage = multer.memoryStorage();

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
    const allowedTypes = ["image/jpeg", "image/png", "image/webp", "video/mp4", "audio/mp3"];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new AppError(messages.INVALID_FILE_TYPE, 400));
    }

    cb(null, true);
  }
});


module.exports = {
  uploadProfile,
  uploadAssetS3
};