/**
 * Smoke test for slide progressStatus (editor + reviewer-only public).
 * Prefers HTTP against a running server; uses Prisma directly for DB asserts.
 * Usage: node scripts/verify-slide-progress.js
 */
const path = require('path');
const http = require('http');

const envFile =
  process.env.NODE_ENV === 'production' ? '.env.production' : '.env.development';
require('dotenv').config({ path: path.join(process.cwd(), envFile) });

const prisma = require('../src/shared/config/prismaClient');
const { createSession } = require('../src/modules/sessions/session.service');
const { signAccessToken } = require('../src/shared/utils/jwt');
const { connectRedis, redisClient } = require('../src/shared/config/redis');

const PORT = Number(process.env.PORT) || 9000;
const BASE = `http://127.0.0.1:${PORT}`;
const results = [];

function pass(name, detail) {
  results.push({ status: 'PASS', name, detail });
  console.log(`  ✓ ${name}${detail ? ` — ${detail}` : ''}`);
}
function fail(name, detail) {
  results.push({ status: 'FAIL', name, detail });
  console.error(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
}

async function httpJson(method, urlPath, { token, body } = {}) {
  const headers = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${BASE}${urlPath}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = JSON.parse(await res.text());
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

async function serverUp() {
  return new Promise((resolve) => {
    const req = http.get(`${BASE}/health`, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(2000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function main() {
  console.log('Slide progressStatus verification\n');

  if (!(await serverUp())) {
    console.error(`Server not running on ${BASE}. Start with npm run dev.`);
    process.exit(1);
  }

  // Session creation needs Redis; short connect for JWT session only.
  await connectRedis();
  await prisma.$connect();

  const project = await prisma.project.findFirst({
    where: {
      type: 'PRESENTATION',
      deck: { status: { not: 'GENERATING' }, slides: { some: { status: 'READY' } } },
    },
    select: {
      id: true,
      workspaceId: true,
      deck: {
        select: {
          slides: { where: { status: 'READY' }, take: 1, orderBy: { order: 'asc' } },
        },
      },
    },
    orderBy: { updatedAt: 'desc' },
  });
  if (!project?.deck?.slides?.[0]) {
    console.error('No READY presentation slide found');
    process.exit(1);
  }

  const member = await prisma.workspaceMember.findFirst({
    where: { workspaceId: project.workspaceId },
    select: { userId: true },
  });
  const slideId = project.deck.slides[0].id;
  const before = await prisma.slide.findUnique({
    where: { id: slideId },
    select: { manuallyEdited: true, progressStatus: true },
  });

  const sessionId = await createSession({
    userId: member.userId,
    userAgent: 'verify-slide-progress',
    ip: '127.0.0.1',
  });
  const accessToken = signAccessToken({ sub: member.userId, sessionId });
  const base = `/api/workspaces/${project.workspaceId}/presentations/${project.id}`;

  console.log(`Deck ${project.id}, slide ${slideId}`);

  const setTodo = await httpJson('PATCH', `${base}/slides/${slideId}`, {
    token: accessToken,
    body: { progressStatus: 'TODO' },
  });
  if (setTodo.status === 200 && setTodo.json?.data?.slide?.progressStatus === 'TODO') {
    pass('HTTP PATCH set TODO', '200');
  } else {
    fail('HTTP PATCH set TODO', `status=${setTodo.status}`);
  }

  const mid = await prisma.slide.findUnique({
    where: { id: slideId },
    select: { manuallyEdited: true },
  });
  if (mid.manuallyEdited === before.manuallyEdited) {
    pass('Progress-only keeps manuallyEdited', `still ${mid.manuallyEdited}`);
  } else {
    fail('Progress-only keeps manuallyEdited', `${before.manuallyEdited} → ${mid.manuallyEdited}`);
  }

  const clear = await httpJson('PATCH', `${base}/slides/${slideId}`, {
    token: accessToken,
    body: { progressStatus: null },
  });
  if (clear.status === 200 && clear.json?.data?.slide?.progressStatus === null) {
    pass('HTTP PATCH clear null', 'null');
  } else {
    fail('HTTP PATCH clear null', JSON.stringify(clear.json?.data?.slide?.progressStatus));
  }

  await httpJson('PATCH', `${base}/slides/${slideId}`, {
    token: accessToken,
    body: { progressStatus: 'COMPLETED' },
  });

  const bad = await httpJson('PATCH', `${base}/slides/${slideId}`, {
    token: accessToken,
    body: { progressStatus: 'DONE' },
  });
  if (bad.status === 400) pass('HTTP invalid enum', '400');
  else fail('HTTP invalid enum', `status=${bad.status}`);

  // Share links
  await httpJson('PUT', `${base}/share/viewer`, { token: accessToken });
  await httpJson('PUT', `${base}/share/reviewer`, { token: accessToken });
  const shareGet = await httpJson('GET', `${base}/share`, { token: accessToken });
  const viewerToken = shareGet.json?.data?.viewer?.token;
  const reviewerToken = shareGet.json?.data?.reviewer?.token;
  if (!viewerToken || !reviewerToken) {
    fail('Enable share links', JSON.stringify(shareGet.json?.data));
  } else {
    pass('Enable share links', 'viewer+reviewer');
  }

  if (viewerToken) {
    const deckV = await httpJson('GET', `/api/p/${viewerToken}`);
    const vs = deckV.json?.data?.slides?.find((s) => s.id === slideId);
    if (deckV.status === 200 && vs && !Object.prototype.hasOwnProperty.call(vs, 'progressStatus')) {
      pass('Viewer deck omits progressStatus', 'ok');
    } else {
      fail('Viewer deck omits progressStatus', JSON.stringify(vs && Object.keys(vs)));
    }
  }

  if (reviewerToken) {
    const deckR = await httpJson('GET', `/api/p/${reviewerToken}`);
    const rs = deckR.json?.data?.slides?.find((s) => s.id === slideId);
    if (deckR.status === 200 && rs?.progressStatus === 'COMPLETED') {
      pass('Reviewer deck includes progressStatus', 'COMPLETED');
    } else {
      fail('Reviewer deck includes progressStatus', JSON.stringify(rs?.progressStatus));
    }
  }

  // Duplicate copies progress
  const dup = await httpJson('POST', `${base}/slides/${slideId}/duplicate`, {
    token: accessToken,
  });
  if (dup.status === 200 || dup.status === 201) {
    const dupSlide = dup.json?.data?.slide;
    if (dupSlide?.progressStatus === 'COMPLETED') {
      pass('Duplicate copies progressStatus', 'COMPLETED');
    } else {
      fail('Duplicate copies progressStatus', JSON.stringify(dupSlide?.progressStatus));
    }
    if (dupSlide?.id) {
      await httpJson('DELETE', `${base}/slides/${dupSlide.id}`, { token: accessToken });
    }
  } else {
    fail('Duplicate slide', `status=${dup.status}`);
  }

  await prisma.slide.update({
    where: { id: slideId },
    data: { progressStatus: before.progressStatus },
  });

  await prisma.$disconnect();
  try {
    await redisClient.quit();
  } catch {
    // ignore
  }

  const passed = results.filter((r) => r.status === 'PASS').length;
  const failed = results.filter((r) => r.status === 'FAIL').length;
  console.log(`\n=== Summary: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
