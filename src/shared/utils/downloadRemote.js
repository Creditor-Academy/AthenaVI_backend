const AppError = require('./AppError');
const messages = require('./messages');

/**
 * Download a remote URL into a Buffer with an optional max-bytes guard.
 * Checks Content-Length when present; aborts if the body exceeds maxBytes while streaming.
 */
async function downloadRemote(url, { maxBytes } = {}) {
  const res = await fetch(url, { method: 'GET' });
  if (!res.ok) {
    throw new AppError(messages.STOCK_REMOTE_FETCH_FAILED, 502);
  }

  const contentLengthHeader = res.headers.get('content-length');
  if (maxBytes && contentLengthHeader) {
    const contentLength = Number(contentLengthHeader);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      throw new AppError(messages.STOCK_FILE_TOO_LARGE, 400);
    }
  }

  if (!res.body) {
    throw new AppError(messages.STOCK_REMOTE_FETCH_FAILED, 502);
  }

  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (maxBytes && total > maxBytes) {
      await reader.cancel();
      throw new AppError(messages.STOCK_FILE_TOO_LARGE, 400);
    }
    chunks.push(value);
  }

  return Buffer.concat(chunks);
}

module.exports = {
  downloadRemote,
};
