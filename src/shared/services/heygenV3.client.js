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

function mapHeyGenStatus(res, body) {
  if (res.ok && body && body.error && !body.data) {
    const msg = body.error?.message || messages.HEYGEN_REQUEST_FAILED;
    const code = body.error?.code === 'authentication_failed' ? 401 : 400;
    throw new AppError(msg, code);
  }
  if (!res.ok) {
    const msg =
      body?.error?.message ||
      body?.message ||
      res.statusText ||
      messages.HEYGEN_REQUEST_FAILED;
    let status = res.status;
    if (status < 400 || status > 599) status = 502;
    if (status === 401) throw new AppError(msg, 401);
    if (status === 429) throw new AppError(msg, 429);
    throw new AppError(msg, status >= 400 && status < 600 ? status : 502);
  }
}

async function heygenFetch(path, options = {}) {
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
  mapHeyGenStatus(res, body);
  return body;
}

async function getJson(path, searchParams) {
  return heygenFetch(path, { method: 'GET', searchParams });
}

async function postJson(path, jsonBody) {
  return heygenFetch(path, { method: 'POST', jsonBody });
}

module.exports = {
  HEYGEN_BASE,
  getApiKey,
  getJson,
  postJson,
  buildQueryString,
};
