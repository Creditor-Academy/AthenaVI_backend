const cors = require('cors');

function normalizeOrigin(origin) {
  return String(origin || '').trim().replace(/\/$/, '');
}

function getCorsAllowedOrigins() {
  const raw = process.env.CORS_ORIGINS || process.env.FRONTEND_URL || '';
  const origins = new Set();

  for (const part of raw.split(',')) {
    const o = normalizeOrigin(part);
    if (o) origins.add(o);
  }

  for (const o of [...origins]) {
    if (o.includes('://localhost')) {
      origins.add(o.replace('://localhost', '://127.0.0.1'));
    } else if (o.includes('://127.0.0.1')) {
      origins.add(o.replace('://127.0.0.1', '://localhost'));
    }
  }

  if (process.env.NODE_ENV !== 'production') {
    for (const o of [
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
    ]) {
      origins.add(o);
    }
  }

  return [...origins];
}

function createCorsMiddleware() {
  return cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      const allowed = getCorsAllowedOrigins();
      if (allowed.length === 0) {
        return callback(null, false);
      }

      if (allowed.includes(normalizeOrigin(origin))) {
        return callback(null, true);
      }

      return callback(null, false);
    },
    credentials: true,
  });
}

function logCorsConfig() {
  const allowed = getCorsAllowedOrigins();
  if (allowed.length > 0) {
    console.log(`CORS allowed origins: ${allowed.join(', ')}`);
  } else {
    console.warn(
      'CORS: set FRONTEND_URL or CORS_ORIGINS — credentialed browser requests (login, logout, refresh) will fail',
    );
  }
}

module.exports = {
  createCorsMiddleware,
  getCorsAllowedOrigins,
  logCorsConfig,
};
