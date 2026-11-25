const AppError = require('../utils/AppError');
const messages = require('../utils/messages');

const HEYGEN_BASE =
  (process.env.HEYGEN_BASE_URL && String(process.env.HEYGEN_BASE_URL).trim().replace(/\/$/, '')) ||
  'https://api.heygen.com';

function getApiKey() {
  const key = process.env.HEYGEN_API_KEY;
  if (!key || !String(key).trim()) {
    throw new AppError(messages.HEYGEN_NOT_CONFIGURED, 500);
  }
  return String(key).trim();
}

function buildQueryString(query) {
  if (!query || typeof query !== 'object') return '';
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue;
    params.set(k, String(v));
  }
  const s = params.toString();
  return s ? `?${s}` : '';
}

function buildHeyGenAppError(msg, statusCode, errorCode) {
  const err = new AppError(msg, statusCode);
  if (errorCode) {
    err.heygenErrorCode = String(errorCode);
  }
  return err;
}

function mapHeyGenStatus(res, body) {
  const errorCode = body?.error?.code || null;
  if (res.ok && body && body.error && !body.data) {
    const msg = body.error?.message || messages.HEYGEN_REQUEST_FAILED;
    const code = errorCode === 'authentication_failed' ? 401 : 400;
    throw buildHeyGenAppError(msg, code, errorCode);
  }
  if (!res.ok) {
    const msg =
      body?.error?.message ||
      body?.message ||
      res.statusText ||
      messages.HEYGEN_REQUEST_FAILED;
    let status = res.status;
    if (status < 400 || status > 599) status = 502;
    if (status === 401) throw buildHeyGenAppError(msg, 401, errorCode);
    if (status === 429) throw buildHeyGenAppError(msg, 429, errorCode);
    throw buildHeyGenAppError(msg, status >= 400 && status < 600 ? status : 502, errorCode);
  }
}

async function heygenFetchRaw(path, options = {}) {
  const { method = 'GET', searchParams, jsonBody } = options;
  const qs = searchParams ? buildQueryString(searchParams) : '';
  const url = `${HEYGEN_BASE}${path}${qs}`;

  const headers = {
    ...(options.headers || {}),
    'x-api-key': getApiKey(),
  };

  /** @type {RequestInit} */
  const init = { method, headers };

  if (jsonBody !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(jsonBody);
  }

  const res = await fetch(url, init);
  const text = await res.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = { raw: text };
  }
  return { res, body };
}

async function heygenFetch(path, options = {}) {
  const { res, body } = await heygenFetchRaw(path, options);
  mapHeyGenStatus(res, body);
  return body;
}

/** Like getJson but returns `{ ok, status, body }` instead of throwing on HTTP errors. */
async function getJsonSafe(path, searchParams) {
  const { res, body } = await heygenFetchRaw(path, { method: 'GET', searchParams });
  const logicalError =
    res.ok && body && body.error && !body.data
      ? body.error?.message || messages.HEYGEN_REQUEST_FAILED
      : null;
  if (logicalError) {
    return { ok: false, status: body.error?.code === 'authentication_failed' ? 401 : 400, body };
  }
  if (!res.ok) {
    const status = res.status >= 400 && res.status < 600 ? res.status : 502;
    return { ok: false, status, body };
  }
  return { ok: true, status: res.status, body };
}

async function getJson(path, searchParams) {
  return heygenFetch(path, { method: 'GET', searchParams });
}

async function postJson(path, jsonBody, options = {}) {
  return heygenFetch(path, { ...options, method: 'POST', jsonBody });
}

async function deleteJson(path) {
  return heygenFetch(path, { method: 'DELETE' });
}

/** DELETE that treats HTTP 404 as success (idempotent delete). */
async function deleteJsonSafe(path) {
  const { res, body } = await heygenFetchRaw(path, { method: 'DELETE' });
  if (res.status === 404) return body;
  mapHeyGenStatus(res, body);
  return body;
}

module.exports = {
  HEYGEN_BASE,
  getApiKey,
  getJson,
  getJsonSafe,
  postJson,
  deleteJson,
  deleteJsonSafe,
  buildQueryString,
};
