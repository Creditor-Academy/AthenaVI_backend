const fs = require('fs/promises');
const { createWriteStream } = require('fs');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');
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

async function getPresignedGetUrl(key, expiresInSeconds = 300, options = {}) {
  const input = {
    Bucket: BUCKET,
    Key: key,
  };
  if (options.responseContentDisposition) {
    input.ResponseContentDisposition = options.responseContentDisposition;
  }
  const command = new GetObjectCommand(input);
  return getSignedUrl(s3, command, { expiresIn: expiresInSeconds });
}

async function downloadObjectToFile(key, destPath) {
  if (!BUCKET) {
    throw new AppError(messages.INTERNAL_SERVER_ERROR, 500);
  }

  const out = await s3.send(
    new GetObjectCommand({
      Bucket: BUCKET,
      Key: key,
    })
  );

  const body = out.Body;
  if (!body) {
    throw new AppError(messages.NOT_FOUND, 404);
  }

  await fs.mkdir(path.dirname(destPath), { recursive: true });

  if (typeof body.pipe === 'function') {
    await pipeline(body, createWriteStream(destPath));
    return destPath;
  }

  const buf = Buffer.from(await body.transformToByteArray());
  await fs.writeFile(destPath, buf);
  return destPath;
}

/**
 * Pipe S3 object to Express response. Supports Range for video seeking (206 Partial Content).
 */
async function streamObjectToResponse(req, res, key, options = {}) {
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
    if (options.contentDisposition) {
      res.setHeader('Content-Disposition', options.contentDisposition);
    }

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

/**
 * Pipe a remote HTTP(S) video URL to Express (e.g. HeyGen CDN while S3 copy is pending).
 */
async function streamRemoteUrlToResponse(req, res, url) {
  const headers = {};
  const range = req.headers.range;
  if (range && typeof range === 'string') {
    headers.Range = range;
  }

  const remote = await fetch(url, { method: 'GET', headers });
  if (!remote.ok) {
    throw new AppError(messages.HEYGEN_PROXY_FETCH_FAILED, 502);
  }

  res.status(remote.status);
  const contentType = remote.headers.get('content-type');
  if (contentType) res.setHeader('Content-Type', contentType);
  const contentLength = remote.headers.get('content-length');
  if (contentLength) res.setHeader('Content-Length', contentLength);
  const contentRange = remote.headers.get('content-range');
  if (contentRange) res.setHeader('Content-Range', contentRange);
  res.setHeader('Accept-Ranges', remote.headers.get('accept-ranges') || 'bytes');
  res.setHeader('Cache-Control', 'private, no-cache');

  if (!remote.body) {
    res.end();
    return;
  }

  const nodeStream = Readable.fromWeb(remote.body);
  try {
    await pipeline(nodeStream, res);
  } catch (err) {
    if (!res.headersSent) {
      throw new AppError(messages.HEYGEN_PROXY_FETCH_FAILED, 502);
    }
    res.destroy();
  }
}

async function headRemoteUrlMeta(url) {
  const remote = await fetch(url, { method: 'HEAD' });
  if (!remote.ok) {
    throw new AppError(messages.HEYGEN_PROXY_FETCH_FAILED, 502);
  }
  const contentLength = remote.headers.get('content-length');
  return {
    contentType: remote.headers.get('content-type') || 'video/mp4',
    contentLength: contentLength != null ? Number(contentLength) : null,
    etag: remote.headers.get('etag'),
    acceptRanges: remote.headers.get('accept-ranges') || 'bytes',
  };
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
  downloadObjectToFile,
  streamObjectToResponse,
  streamRemoteUrlToResponse,
  headRemoteUrlMeta,
  headObjectMeta,
  buildPublicUrl,
};
