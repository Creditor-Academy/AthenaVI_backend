'use strict';

const assert = require('assert');
const { test } = require('node:test');
const { allowedHosts, checkProxyUrl, fetchProxiedImage, MAX_BYTES } = require('./mediaProxy.service');

const ENV = { AWS_S3_BUCKET: 'virtual-instructor', AWS_REGION: 'us-east-1', MEDIA_PROXY_HOSTS: 'cdn.example.com' };
const IMG = 'https://virtual-instructor.s3.us-east-1.amazonaws.com/workspace/w1/assets/a.png';

function response({ status = 200, type = 'image/png', body = Buffer.from([1, 2, 3]), length } = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: new Map([
      ['content-type', type],
      ['content-length', length != null ? String(length) : String(body.length)],
    ]),
    body: null,
    arrayBuffer: async () => body,
  };
}

test('only our bucket and the configured hosts are allowed', () => {
  const hosts = allowedHosts(ENV);
  assert.ok(hosts.has('virtual-instructor.s3.us-east-1.amazonaws.com'));
  assert.ok(hosts.has('virtual-instructor.s3.amazonaws.com'));
  assert.ok(hosts.has('cdn.example.com'));
  assert.equal(checkProxyUrl(IMG, ENV).hostname, 'virtual-instructor.s3.us-east-1.amazonaws.com');
  for (const bad of [
    'https://other-bucket.s3.us-east-1.amazonaws.com/a.png',
    'https://169.254.169.254/latest/meta-data',
    'http://virtual-instructor.s3.us-east-1.amazonaws.com/a.png',
    'https://user:pw@virtual-instructor.s3.us-east-1.amazonaws.com/a.png',
    'https://virtual-instructor.s3.us-east-1.amazonaws.com:8443/a.png',
    'not a url',
  ]) {
    assert.throws(() => checkProxyUrl(bad, ENV), (e) => e.statusCode === 400, bad);
  }
  // Nothing configured: nothing allowed.
  assert.throws(() => checkProxyUrl(IMG, {}), (e) => e.statusCode === 400);
});

test('fetches the URL as given, without credentials or following redirects', async () => {
  let seen = null;
  const out = await fetchProxiedImage(`${IMG}?X-Amz-Signature=abc`, {
    env: ENV,
    fetchImpl: async (url, opts) => {
      seen = { url, opts };
      return response();
    },
  });
  assert.equal(seen.url, `${IMG}?X-Amz-Signature=abc`);
  assert.equal(seen.opts.redirect, 'manual');
  assert.equal(seen.opts.headers, undefined);
  assert.equal(out.contentType, 'image/png');
  assert.deepEqual([...out.body], [1, 2, 3]);
});

test('refuses non-images, missing objects, redirects, oversized files and slow hosts', async () => {
  const run = (res) => fetchProxiedImage(IMG, { env: ENV, fetchImpl: async () => res });
  await assert.rejects(run(response({ type: 'text/html' })), (e) => e.statusCode === 415);
  await assert.rejects(run(response({ status: 403 })), (e) => e.statusCode === 404);
  await assert.rejects(run(response({ status: 404 })), (e) => e.statusCode === 404);
  await assert.rejects(run(response({ status: 302 })), (e) => e.statusCode === 502);
  await assert.rejects(run(response({ length: MAX_BYTES + 1 })), (e) => e.statusCode === 413);
  await assert.rejects(
    fetchProxiedImage(IMG, {
      env: ENV,
      timeoutMs: 20,
      fetchImpl: (url, { signal }) =>
        new Promise((resolve, reject) => {
          signal.addEventListener('abort', () => {
            const err = new Error('aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }),
    }),
    (e) => e.statusCode === 504
  );
});
