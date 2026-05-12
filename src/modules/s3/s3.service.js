const {
  PutObjectCommand,
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const s3 = require('../../shared/config/s3');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const BUCKET = process.env.AWS_S3_BUCKET;

function buildPublicUrl(key) {
  return `https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;
}

async function uploadBodyToKey(body, key, contentType) {
  const command = new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: body,
    ContentType: contentType,
  });

  await s3.send(command);

  return {
    key,
    url: buildPublicUrl(key),
  };
}

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
  return uploadBodyToKey(fileBuffer, key, contentType);
}

async function uploadFileToKey(fileBuffer, key, contentType) {
  return uploadBodyToKey(fileBuffer, key, contentType);
}

async function deleteFile(key) {
  const command = new DeleteObjectCommand({
    Bucket: BUCKET,
    Key: key,
  });

  return s3.send(command);
}

async function copyFile(sourceKey, destinationKey) {
  const command = new CopyObjectCommand({
    Bucket: BUCKET,
    CopySource: `${BUCKET}/${sourceKey}`,
    Key: destinationKey,
  });

  await s3.send(command);

  return {
    key: destinationKey,
    url: buildPublicUrl(destinationKey),
  };
}

async function moveFile(sourceKey, destinationKey) {
  if (sourceKey === destinationKey) {
    return {
      key: destinationKey,
      url: buildPublicUrl(destinationKey),
    };
  }

  const copied = await copyFile(sourceKey, destinationKey);
  await deleteFile(sourceKey);
  return copied;
}

async function getPresignedGetUrl(key, expiresInSeconds = 300) {
  const command = new GetObjectCommand({
    Bucket: BUCKET,
    Key: key,
  });
  return getSignedUrl(s3, command, { expiresIn: expiresInSeconds });
}

/**
 * Pipe S3 object to Express response. Supports Range for video seeking (206 Partial Content).
 */
async function streamObjectToResponse(req, res, key) {
  if (!BUCKET) {
    throw new AppError(messages.INTERNAL_SERVER_ERROR, 500);
  }

  const input = {
    Bucket: BUCKET,
    Key: key,
  };
  const range = req.headers.range;
  if (range && typeof range === 'string') {
    input.Range = range;
  }

  try {
    const out = await s3.send(new GetObjectCommand(input));
    const statusCode = range ? 206 : 200;

    res.status(statusCode);
    res.setHeader('Content-Type', out.ContentType || 'video/mp4');
    if (out.ContentLength != null) {
      res.setHeader('Content-Length', String(out.ContentLength));
    }
    if (out.ContentRange) {
      res.setHeader('Content-Range', out.ContentRange);
    }
    res.setHeader('Accept-Ranges', 'bytes');
    if (out.ETag) {
      res.setHeader('ETag', out.ETag);
    }
    res.setHeader('Cache-Control', 'private, no-cache');

    const body = out.Body;
    if (!body) {
      if (!res.headersSent) {
        res.status(500).end();
      }
      return;
    }

    if (typeof body.pipe === 'function') {
      body.on('error', () => {
        if (!res.headersSent) {
          res.status(500).end();
        } else {
          res.destroy();
        }
      });
      res.on('close', () => {
        if (typeof body.destroy === 'function') {
          body.destroy();
        }
      });
      body.pipe(res);
      return;
    }

    const buf = Buffer.from(await body.transformToByteArray());
    res.end(buf);
  } catch (err) {
    const code = err.$metadata?.httpStatusCode;
    const name = err.name || '';
    if (code === 404 || name === 'NoSuchKey' || name === 'NotFound') {
      throw new AppError(messages.NOT_FOUND, 404);
    }
    throw err;
  }
}

async function headObjectMeta(key) {
  if (!BUCKET) {
    throw new AppError(messages.INTERNAL_SERVER_ERROR, 500);
  }
  try {
    const out = await s3.send(
      new HeadObjectCommand({
        Bucket: BUCKET,
        Key: key,
      })
    );
    return {
      contentType: out.ContentType || 'video/mp4',
      contentLength: out.ContentLength,
      etag: out.ETag,
      acceptRanges: out.AcceptRanges || 'bytes',
    };
  } catch (err) {
    const code = err.$metadata?.httpStatusCode;
    const name = err.name || '';
    if (code === 404 || name === 'NotFound') {
      throw new AppError(messages.NOT_FOUND, 404);
    }
    throw err;
  }
}

module.exports = {
  uploadFile,
  uploadFileToKey,
  deleteFile,
  copyFile,
  moveFile,
  getPresignedGetUrl,
  streamObjectToResponse,
  headObjectMeta,
  buildPublicUrl,
};
