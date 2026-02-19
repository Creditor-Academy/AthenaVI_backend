const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { redisClient } = require('../../shared/config/redis');

const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs';
const OAUTH_STATE_TTL = 300; // 5 minutes
const OAUTH_STATE_PREFIX = 'oauth:state:';

const jwks = jwksClient({
  jwksUri: GOOGLE_JWKS_URI,
  cache: true,
  cacheMaxAge: 600000,
});

/**
 * Store OAuth state in Redis (CSRF protection).
 * @returns {string} state
 */
const createState = async () => {
  const state = crypto.randomBytes(32).toString('hex');
  await redisClient.set(OAUTH_STATE_PREFIX + state, '1', { EX: OAUTH_STATE_TTL });
  return state;
};

/**
 * Consume state: verify it exists and delete (one-time use).
 * @returns {Promise<boolean>} true if valid
 */
const consumeState = async (state) => {
  if (!state) return false;
  const key = OAUTH_STATE_PREFIX + state;
  const value = await redisClient.get(key);
  if (!value) return false;
  await redisClient.del(key);
  return true;
};

/**
 * Build Google authorization URL.
 * @param {string} state
 * @returns {string} redirect URL
 */
const getAuthUrl = (state) => {
  const redirectUri = getRedirectUri();
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    access_type: 'offline',
    prompt: 'consent',
  });
  return `${GOOGLE_AUTH_URL}?${params.toString()}`;
};

function getRedirectUri() {
  const base = process.env.BACKEND_URL || process.env.API_URL || '';
  const path = '/api/auth/google/callback';
  if (base) return base.replace(/\/$/, '') + path;
  throw new Error('BACKEND_URL or API_URL must be set for Google OAuth');
}

/**
 * Exchange authorization code for tokens.
 * @param {string} code
 * @returns {Promise<{ access_token, refresh_token?, expires_in, id_token }>}
 */
const exchangeCodeForTokens = async (code) => {
  const redirectUri = getRedirectUri();
  const body = new URLSearchParams({
    code,
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });

  const res = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Google token exchange failed: ${res.status} ${err}`);
  }

  return res.json();
};

/**
 * Verify Google id_token (signature + aud, iss, exp).
 * @param {string} idToken
 * @returns {Promise<{ sub, email, email_verified, name?, picture? }>}
 */
const verifyIdToken = (idToken) => {
  return new Promise((resolve, reject) => {
    jwt.verify(
      idToken,
      (header, callback) => {
        jwks.getSigningKey(header.kid, (err, key) => {
          if (err) return callback(err);
          const publicKey = key?.publicKey || key?.rsaPublicKey || key?.getPublicKey?.();
          callback(null, publicKey);
        });
      },
      {
        algorithms: ['RS256'],
        issuer: ['https://accounts.google.com', 'accounts.google.com'],
        audience: process.env.GOOGLE_CLIENT_ID,
      },
      (err, payload) => {
        if (err) return reject(err);
        resolve(payload);
      }
    );
  });
};

module.exports = {
  createState,
  consumeState,
  getAuthUrl,
  exchangeCodeForTokens,
  verifyIdToken,
  getRedirectUri,
};
