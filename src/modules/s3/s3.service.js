const { PutObjectCommand, DeleteObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const s3 = require('../../shared/config/s3');

const BUCKET = process.env.AWS_S3_BUCKET;

async function uploadFile(
  fileBuffer,
  entityType,   // 'users' | 'workspace'
  entityId,     // userId | workspaceId
  folder = '',  // profile | assets | thumbnails etc
  originalName,
  contentType
) {
  // extract file extension
  const extension = path.extname(originalName);

  // generate unique key
  const key = `${entityType}/${entityId}/${folder}/${uuidv4()}${extension}`;

  const command = new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: fileBuffer,
    ContentType: contentType,
  });

  await s3.send(command);

  return {
    key,
    url: `https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`,
  };
}

async function deleteFile(key) {
  const command = new DeleteObjectCommand({
    Bucket: BUCKET,
    Key: key,
  });

  return s3.send(command);
}

async function getPresignedGetUrl(key, expiresInSeconds = 300) {
  const command = new GetObjectCommand({
    Bucket: BUCKET,
    Key: key,
  });
  return getSignedUrl(s3, command, { expiresIn: expiresInSeconds });
}

module.exports = {
  uploadFile,
  deleteFile,
  getPresignedGetUrl,
};
