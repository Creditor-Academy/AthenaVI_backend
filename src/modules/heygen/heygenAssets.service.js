const fs = require('fs/promises');
const { createWriteStream } = require('fs');
const http = require('http');
const https = require('https');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');
const { Readable } = require('stream');
const { URL } = require('url');
const { v4: uuidv4 } = require('uuid');
const { GetObjectCommand } = require('@aws-sdk/client-s3');
const { postJson } = require('../../shared/services/heygenV3.client');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const s3 = require('../../shared/config/s3');
const { headObjectMeta, headRemoteUrlMeta } = require('../s3/s3.service');

const BUCKET = process.env.AWS_S3_BUCKET;

/** HeyGen caps `file.type: url` (and base64) inputs at 32 MB; larger files need direct upload → asset_id. */
const HEYGEN_URL_INPUT_MAX_BYTES = 32 * 1024 * 1024;

function pickDirectUploadInit(body) {
  const data = body?.data && typeof body.data === 'object' ? body.data : body;
  return {
    assetId: data?.asset_id ?? data?.assetId ?? null,
    uploadUrl: data?.upload_url ?? data?.uploadUrl ?? null,
    uploadHeaders: data?.upload_headers ?? data?.uploadHeaders ?? {},
  };
}

function parseOurS3PublicUrl(url) {
  if (!BUCKET || !url) return null;
  const region = process.env.AWS_REGION;
  const candidates = [
    `https://${BUCKET}.s3.${region}.amazonaws.com/`,
    `https://${BUCKET}.s3.amazonaws.com/`,
    `https://s3.${region}.amazonaws.com/${BUCKET}/`,
  ];
  const raw = String(url);
  for (const prefix of candidates) {
    if (raw.startsWith(prefix)) {
      return decodeURIComponent(raw.slice(prefix.length).split('?')[0]);
    }
  }
  return null;
}

async function initDirectUpload({ filename, contentType, sizeBytes }) {
  const raw = await postJson('/v3/assets/direct-uploads', {
    filename,
    content_type: contentType,
    size_bytes: sizeBytes,
  });
  const { assetId, uploadUrl, uploadHeaders } = pickDirectUploadInit(raw);
  if (!assetId || !uploadUrl) {
    throw new AppError(messages.HEYGEN_DIRECT_UPLOAD_FAILED, 502);
  }
  return { assetId, uploadUrl, uploadHeaders };
}

function normalizeUploadHeaders(uploadHeaders) {
  if (!uploadHeaders) return {};
  if (Array.isArray(uploadHeaders)) {
    const out = {};
    for (const entry of uploadHeaders) {
      if (!entry || typeof entry !== 'object') continue;
      const key = entry.name ?? entry.key ?? entry.header;
      const value = entry.value;
      if (key != null && value != null) out[String(key)] = String(value);
    }
    return out;
  }
  if (typeof uploadHeaders === 'object') {
    const out = {};
    for (const [key, value] of Object.entries(uploadHeaders)) {
      if (value != null) out[String(key)] = String(value);
    }
    return out;
  }
  return {};
}

/**
 * PUT bytes to HeyGen's presigned URL. Must send exact signed headers and Content-Length
 * (chunked transfer breaks S3 signature → SignatureDoesNotMatch).
 */
function putToPresignedUrl(uploadUrl, uploadHeaders, body, sizeBytes, contentType) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(uploadUrl);
    } catch {
      reject(new AppError(messages.HEYGEN_DIRECT_UPLOAD_FAILED, 502));
      return;
    }

    const headers = normalizeUploadHeaders(uploadHeaders);
    if (Object.keys(headers).length === 0) {
      if (contentType) headers['Content-Type'] = contentType;
      if (sizeBytes != null) headers['Content-Length'] = String(sizeBytes);
    } else {
      const hasContentLength = Object.keys(headers).some(
        (k) => k.toLowerCase() === 'content-length'
      );
      if (!hasContentLength && sizeBytes != null) {
        headers['Content-Length'] = String(sizeBytes);
      }
    }

    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.request(
      {
        method: 'PUT',
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || undefined,
        path: `${parsed.pathname}${parsed.search}`,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
            return;
          }
          reject(
            new AppError(
              `${messages.HEYGEN_DIRECT_UPLOAD_FAILED}${text ? ` (${text.slice(0, 220)})` : ''}`,
              502
            )
          );
        });
      }
    );

    req.on('error', (err) => {
      reject(new AppError(`${messages.HEYGEN_DIRECT_UPLOAD_FAILED}: ${err.message}`, 502));
    });

    if (body && typeof body.pipe === 'function') {
      body.pipe(req);
    } else if (body != null) {
      req.end(body);
    } else {
      req.end();
    }
  });
}

async function completeDirectUpload(assetId) {
  await postJson(`/v3/assets/${encodeURIComponent(assetId)}/complete`, {});
  return assetId;
}

async function directUploadLocalFile(localPath, originalName, contentType) {
  const st = await fs.stat(localPath);
  const mime = contentType || 'application/octet-stream';
  const { assetId, uploadUrl, uploadHeaders } = await initDirectUpload({
    filename: originalName || path.basename(localPath),
    contentType: mime,
    sizeBytes: st.size,
  });
  const buffer = await fs.readFile(localPath);
  await putToPresignedUrl(uploadUrl, uploadHeaders, buffer, buffer.length, mime);
  return completeDirectUpload(assetId);
}

async function directUploadFromS3Key(key, contentType) {
  const meta = await headObjectMeta(key);
  const sizeBytes = meta.contentLength;
  if (sizeBytes == null) {
    throw new AppError(messages.HEYGEN_DIRECT_UPLOAD_FAILED, 502);
  }
  const mime = contentType || meta.contentType || 'application/octet-stream';
  const { assetId, uploadUrl, uploadHeaders } = await initDirectUpload({
    filename: path.basename(key),
    contentType: mime,
    sizeBytes,
  });
  const out = await s3.send(
    new GetObjectCommand({
      Bucket: BUCKET,
      Key: key,
    })
  );
  if (!out.Body) {
    throw new AppError(messages.NOT_FOUND, 404);
  }
  const buffer = Buffer.from(await out.Body.transformToByteArray());
  await putToPresignedUrl(uploadUrl, uploadHeaders, buffer, buffer.length, mime);
  return completeDirectUpload(assetId);
}

async function directUploadFromRemoteUrl(url, contentType, sizeBytes) {
  const tmpPath = path.join(os.tmpdir(), `heygen-asset-${uuidv4()}${path.extname(url.split('?')[0]) || ''}`);
  try {
    const remote = await fetch(url, { method: 'GET' });
    if (!remote.ok || !remote.body) {
      throw new AppError(messages.HEYGEN_PROXY_FETCH_FAILED, 502);
    }
    await pipeline(Readable.fromWeb(remote.body), createWriteStream(tmpPath));
    return await directUploadLocalFile(tmpPath, path.basename(url.split('?')[0]), contentType);
  } finally {
    await fs.unlink(tmpPath).catch(() => {});
  }
}

async function resolveUrlAssetMeta(url) {
  const s3Key = parseOurS3PublicUrl(url);
  if (s3Key) {
    const meta = await headObjectMeta(s3Key);
    return {
      sizeBytes: meta.contentLength,
      contentType: meta.contentType,
      s3Key,
    };
  }
  const remote = await headRemoteUrlMeta(url);
  return {
    sizeBytes: remote.contentLength,
    contentType: remote.contentType,
    s3Key: null,
  };
}

/**
 * For HeyGen asset unions (`url` | `asset_id` | `base64`): if `url` points to a file
 * larger than 32 MB, stream it into HeyGen direct upload and return `asset_id`.
 */
async function ensureHeygenAssetRef(asset) {
  if (!asset || typeof asset !== 'object') return asset;
  if (asset.type === 'asset_id') return asset;
  if (asset.type !== 'url' || !asset.url) return asset;

  let meta;
  try {
    meta = await resolveUrlAssetMeta(asset.url);
  } catch {
    return asset;
  }

  const sizeBytes = meta.sizeBytes;
  if (sizeBytes == null || sizeBytes <= HEYGEN_URL_INPUT_MAX_BYTES) {
    return asset;
  }

  let assetId;
  if (meta.s3Key) {
    assetId = await directUploadFromS3Key(meta.s3Key, meta.contentType);
  } else {
    assetId = await directUploadFromRemoteUrl(asset.url, meta.contentType, sizeBytes);
  }
  return { type: 'asset_id', asset_id: assetId };
}

module.exports = {
  HEYGEN_URL_INPUT_MAX_BYTES,
  ensureHeygenAssetRef,
  directUploadLocalFile,
};
