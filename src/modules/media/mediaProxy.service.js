'use strict';

/**
 * Same-origin copy of one of our images, for in-browser exports (Canvas PNG / JPG / WebP / PDF).
 *
 * The browser can only draw an image into an exported file when the image host sends CORS
 * headers for the page's origin. Our bucket does, but a browser can still refuse: it reuses a
 * copy it cached from a plain <img> (no CORS headers), and dev / staging origins may not be on
 * the bucket's list. The export then fetches the image through this route instead.
 *
 * Safety:
 * - Only https URLs on our own image hosts (the S3 bucket, plus MEDIA_PROXY_HOSTS), so the
 *   route can't be used to reach anything else (no SSRF).
 * - The URL is fetched exactly as given, with no AWS credentials and without following
 *   redirects: it returns only what that URL already serves to anyone (a public object or a
 *   presigned link), never a private object.
 * - Images only, up to MAX_BYTES, with a time limit.
 */

const AppError = require('../../shared/utils/AppError');

const TIMEOUT_MS = 15_000;
const MAX_BYTES = 25 * 1024 * 1024;

/** Hosts the proxy may fetch from: the S3 bucket's addresses, plus MEDIA_PROXY_HOSTS. */
function allowedHosts(env = process.env) {
  const hosts = new Set();
  const bucket = String(env.AWS_S3_BUCKET || '').trim().toLowerCase();
  const region = String(env.AWS_REGION || '').trim().toLowerCase();
  if (bucket) {
    hosts.add(`${bucket}.s3.amazonaws.com`);
    if (region) {
      hosts.add(`${bucket}.s3.${region}.amazonaws.com`);
      hosts.add(`${bucket}.s3-${region}.amazonaws.com`);
    }
  }
  String(env.MEDIA_PROXY_HOSTS || '')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
    .forEach((h) => hosts.add(h));
  return hosts;
}

/** The URL to fetch, or an AppError(400) when it isn't one of our images. */
function checkProxyUrl(raw, env = process.env) {
  let url;
  try {
    url = new URL(String(raw || ''));
  } catch {
    throw new AppError('Not a valid image address.', 400);
  }
  if (url.protocol !== 'https:') throw new AppError('Only https image addresses can be loaded.', 400);
  if (url.username || url.password) throw new AppError('Not a valid image address.', 400);
  if (url.port && url.port !== '443') throw new AppError('Not a valid image address.', 400);
  if (!allowedHosts(env).has(url.hostname.toLowerCase())) {
    throw new AppError('This image host is not supported for export.', 400);
  }
  return url;
}

/**
 * Fetch one of our images. Resolves `{ body: Buffer, contentType }`; rejects with an AppError
 * (400 bad address, 404 not found / not allowed, 413 too large, 415 not an image,
 * 504 timed out, 502 other failure).
 */
async function fetchProxiedImage(raw, { fetchImpl = fetch, env = process.env, timeoutMs = TIMEOUT_MS } = {}) {
  const url = checkProxyUrl(raw, env);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let res;
    try {
      res = await fetchImpl(url.href, { redirect: 'manual', signal: controller.signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw new AppError('The image took too long to load.', 504);
      throw new AppError('The image could not be loaded.', 502);
    }
    if (res.status === 403 || res.status === 404) throw new AppError('Image not found.', 404);
    if (!res.ok) throw new AppError('The image could not be loaded.', 502);

    const contentType = String(res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (!contentType.startsWith('image/')) throw new AppError('This file is not an image.', 415);
    const declared = Number(res.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_BYTES) throw new AppError('The image is too large to export.', 413);

    const chunks = [];
    let size = 0;
    const reader = res.body?.getReader?.();
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_BYTES) {
          controller.abort();
          throw new AppError('The image is too large to export.', 413);
        }
        chunks.push(Buffer.from(value));
      }
    } else {
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_BYTES) throw new AppError('The image is too large to export.', 413);
      chunks.push(buf);
    }
    return { body: Buffer.concat(chunks), contentType };
  } catch (error) {
    if (error instanceof AppError) throw error;
    if (error?.name === 'AbortError') throw new AppError('The image took too long to load.', 504);
    throw new AppError('The image could not be loaded.', 502);
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { allowedHosts, checkProxyUrl, fetchProxiedImage, MAX_BYTES };
