const { PutObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { v4: uuidv4 } = require("uuid");
const path = require("path");

const s3 = require("../../shared/config/s3");

const BUCKET = process.env.AWS_S3_BUCKET;

async function uploadFile(fileBuffer, userId, folder, originalName, contentType) {

  // extract file extension
  const extension = path.extname(originalName);

  // generate unique key
  const key = `users/${folder}/${userId}/${uuidv4()}${extension}`;
  
  const command = new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: fileBuffer,
    ContentType: contentType,
  });

  await s3.send(command);

  return {
    key,
    url: `https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`
  };
}

async function deleteFile(key) {
  const command = new DeleteObjectCommand({
    Bucket: BUCKET,
    Key: key,
  });

  return s3.send(command);
}

module.exports = {
  uploadFile,
  deleteFile,
};