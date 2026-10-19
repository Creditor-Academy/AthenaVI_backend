/**
 * Verification script for viewer/reviewer dual share links.
 * Usage: node scripts/verify-share-links.js
 */
const fs = require('fs');
const path = require('path');
const http = require('http');

const envFile =
  process.env.NODE_ENV === 'production' ? '.env.production' : '.env.development';
require('dotenv').config({ path: path.join(process.cwd(), envFile) });

const prisma = require('../src/shared/config/prismaClient');
const { connectRedis, redisClient } = require('../src/shared/config/redis');
const shareService = require('../src/modules/presentationShare/presentationShare.service');
const shareDao = require('../src/modules/presentationShare/presentationShare.dao');
const presence = require('../src/modules/presentationShare/presentationShare.presence');
const { createSession } = require('../src/modules/sessions/session.service');
const { signAccessToken } = require('../src/shared/utils/jwt');
const messages = require('../src/shared/utils/messages');

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

function skip(name, detail) {
  results.push({ status: 'SKIP', name, detail });
  console.log(`  - ${name} — ${detail}`);
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
  const text = await res.text();
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }

  return { status: res.status, json, headers: res.headers };
}

async function findTestContext() {
  const project = await prisma.project.findFirst({
    where: { type: 'PRESENTATION', deck: { status: { not: 'GENERATING' } } },
    select: {
      id: true,
      workspaceId: true,
      name: true,
      deck: { select: { status: true } },
    },
    orderBy: { updatedAt: 'desc' },
  });

  if (!project) return null;

  const member = await prisma.workspaceMember.findFirst({
    where: { workspaceId: project.workspaceId },
    select: { userId: true, role: true, user: { select: { email: true } } },
  });

  if (!member) return null;

  const slide = await prisma.slide.findFirst({
    where: { deck: { projectId: project.id }, status: 'READY' },
    select: { id: true },
  });

  const sessionId = await createSession({
    userId: member.userId,
    userAgent: 'verify-share-links',
    ip: '127.0.0.1',
  });
  const accessToken = signAccessToken({ sub: member.userId, sessionId });

  return {
    workspaceId: project.workspaceId,
    presentationId: project.id,
    deckStatus: project.deck?.status,
    slideId: slide?.id || null,
    userId: member.userId,
    userEmail: member.user.email,
    accessToken,
  };
}

async function findPristinePresentation(workspaceId) {
  const rows = await prisma.presentationShareLink.findMany({
    select: { projectId: true },
  });
  const used = new Set(rows.map((r) => r.projectId));

  const project = await prisma.project.findFirst({
    where: {
      type: 'PRESENTATION',
      workspaceId,
      deck: { status: { not: 'GENERATING' } },
      id: { notIn: [...used] },
    },
    select: { id: true },
    orderBy: { updatedAt: 'desc' },
  });

  return project?.id || null;
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

async function expectShareNotFound(fn) {
  try {
    await fn();
    return false;
  } catch (err) {
    return err.statusCode === 404;
  }
}

async function runServiceTests(ctx) {
  console.log('\n=== Service-layer checks ===');

  const sharesBefore = await shareDao.listSharesByProjectId(ctx.presentationId);
  const hadViewer = sharesBefore.some((s) => s.role === 'VIEWER');
  const hadReviewer = sharesBefore.some((s) => s.role === 'REVIEWER');

  const get0 = await shareService.getShare({
    workspaceId: ctx.workspaceId,
    presentationId: ctx.presentationId,
  });
  if (get0.viewer && get0.reviewer) {
    pass('GET share shape', 'viewer + reviewer keys present');
  } else {
    fail('GET share shape', JSON.stringify(Object.keys(get0)));
  }

  if (!get0.viewer.exists && !get0.reviewer.exists) {
    pass('GET with neither minted', 'both exists:false');
  } else {
    skip('GET with neither minted', 'links already exist on this deck');
  }

  let viewerToken;
  let reviewerToken;

  const enableViewer = await shareService.enableShareForRole({
    workspaceId: ctx.workspaceId,
    presentationId: ctx.presentationId,
    userId: ctx.userId,
    ip: '127.0.0.1',
    role: shareService.ROLE_VIEWER,
  });
  viewerToken = enableViewer.link?.token || enableViewer.token;
  if (enableViewer.link?.exists && enableViewer.link?.role === 'VIEWER') {
    pass('PUT viewer enable', viewerToken ? 'token minted/returned' : 're-enabled existing');
  } else {
    fail('PUT viewer enable', JSON.stringify(enableViewer));
  }

  const enableViewerAgain = await shareService.enableShareForRole({
    workspaceId: ctx.workspaceId,
    presentationId: ctx.presentationId,
    userId: ctx.userId,
    ip: '127.0.0.1',
    role: shareService.ROLE_VIEWER,
  });
  if (enableViewerAgain.link?.token === viewerToken) {
    pass('PUT viewer idempotent', 'same token on re-enable');
  } else {
    fail('PUT viewer idempotent', 'token changed unexpectedly');
  }

  if (await expectShareNotFound(() => shareService.getPublicSession({ token: 'totally-invalid-token-xyz', user: null }))) {
    pass('Invalid token public session', '404');
  } else {
    fail('Invalid token public session', 'should have thrown 404');
  }

  const viewerSession = await shareService.getPublicSession({ token: viewerToken, user: null });
  if (
    viewerSession.linkRole === 'viewer' &&
    viewerSession.canComment === false &&
    viewerSession.permission === 'view'
  ) {
    pass('Viewer session fields', `linkRole=${viewerSession.linkRole}, permission=${viewerSession.permission}`);
  } else {
    fail('Viewer session fields', JSON.stringify(viewerSession));
  }

  const memberSession = await shareService.getPublicSession({
    token: viewerToken,
    user: { id: ctx.userId },
  });
  if (memberSession.canOpenInEditor === true && memberSession.canComment === false) {
    pass('Member on viewer link', 'canOpenInEditor=true, canComment=false');
  } else {
    fail('Member on viewer link', JSON.stringify(memberSession));
  }

  const viewerComments = await shareService.resolveShareForComments({
    token: viewerToken,
    user: null,
  });
  if (viewerComments.canComment === false) {
    pass('resolveShareForComments viewer', 'canComment=false');
  } else {
    fail('resolveShareForComments viewer', JSON.stringify(viewerComments));
  }

  const pristineId = await findPristinePresentation(ctx.workspaceId);
  if (pristineId) {
    try {
      await shareService.updateShareForRole({
        workspaceId: ctx.workspaceId,
        presentationId: pristineId,
        userId: ctx.userId,
        ip: '127.0.0.1',
        role: shareService.ROLE_REVIEWER,
        enabled: false,
      });
      fail('PATCH never-minted reviewer', 'should 404');
    } catch (err) {
      if (err.statusCode === 404) pass('PATCH never-minted reviewer', '404');
      else fail('PATCH never-minted reviewer', err.message);
    }

    try {
      await shareService.rotateShareForRole({
        workspaceId: ctx.workspaceId,
        presentationId: pristineId,
        userId: ctx.userId,
        ip: '127.0.0.1',
        role: shareService.ROLE_REVIEWER,
      });
      fail('rotate never-minted reviewer', 'should 404');
    } catch (err) {
      if (err.statusCode === 404) pass('rotate never-minted reviewer', '404');
      else fail('rotate never-minted reviewer', err.message);
    }
  } else {
    skip('PATCH/rotate never-minted reviewer', 'no presentation without share rows');
  }

  const enableReviewer = await shareService.enableShareForRole({
    workspaceId: ctx.workspaceId,
    presentationId: ctx.presentationId,
    userId: ctx.userId,
    ip: '127.0.0.1',
    role: shareService.ROLE_REVIEWER,
  });
  reviewerToken = enableReviewer.link?.token || enableReviewer.token;
  if (enableReviewer.link?.role === 'REVIEWER') {
    pass('PUT reviewer enable', reviewerToken ? 'token minted' : 're-enabled');
  } else {
    fail('PUT reviewer enable', JSON.stringify(enableReviewer));
  }

  const reviewerSession = await shareService.getPublicSession({ token: reviewerToken, user: null });
  if (
    reviewerSession.linkRole === 'reviewer' &&
    reviewerSession.canComment === true &&
    reviewerSession.permission === 'review'
  ) {
    pass('Reviewer session fields', `permission=${reviewerSession.permission}`);
  } else {
    fail('Reviewer session fields', JSON.stringify(reviewerSession));
  }

  await presence.heartbeat({
    projectId: ctx.presentationId,
    viewerKey: 'user:test-viewer',
    identity: { displayName: 'Test Viewer', isAnonymous: false },
    slideIndex: 0,
  });
  const roomBefore = await presence.listViewers(ctx.presentationId);
  if (roomBefore.viewerCount >= 1) {
    pass('Presence keyed by projectId', `viewerCount=${roomBefore.viewerCount}`);
  } else {
    fail('Presence keyed by projectId', 'no viewers in room');
  }

  await shareService.updateShareForRole({
    workspaceId: ctx.workspaceId,
    presentationId: ctx.presentationId,
    userId: ctx.userId,
    ip: '127.0.0.1',
    role: shareService.ROLE_VIEWER,
    enabled: false,
  });

  if (await expectShareNotFound(() => shareService.getPublicSession({ token: viewerToken, user: null }))) {
    pass('Disabled viewer token', '404');
  } else {
    fail('Disabled viewer token', 'should 404');
  }

  if (await expectShareNotFound(() => shareService.getPublicSession({ token: reviewerToken, user: null }))) {
    fail('Reviewer OK while viewer disabled', 'reviewer unexpectedly disabled');
  } else {
    pass('Reviewer OK while viewer disabled', 'reviewer still resolves');
  }

  const roomAfterDisable = await presence.listViewers(ctx.presentationId);
  if (roomAfterDisable.viewerCount >= roomBefore.viewerCount) {
    pass('Presence preserved on viewer disable', `count=${roomAfterDisable.viewerCount}`);
  } else {
    fail('Presence preserved on viewer disable', `before=${roomBefore.viewerCount} after=${roomAfterDisable.viewerCount}`);
  }

  const oldReviewerToken = reviewerToken;
  const rotated = await shareService.rotateShareForRole({
    workspaceId: ctx.workspaceId,
    presentationId: ctx.presentationId,
    userId: ctx.userId,
    ip: '127.0.0.1',
    role: shareService.ROLE_REVIEWER,
  });
  reviewerToken = rotated.token || rotated.link?.token;

  if (await expectShareNotFound(() => shareService.getPublicSession({ token: oldReviewerToken, user: null }))) {
    pass('Old reviewer token after rotate', '404');
  } else {
    fail('Old reviewer token after rotate', 'should 404');
  }

  const roomAfterRotate = await presence.listViewers(ctx.presentationId);
  if (roomAfterRotate.viewerCount >= 1) {
    pass('Presence preserved on reviewer rotate', `count=${roomAfterRotate.viewerCount}`);
  } else {
    fail('Presence preserved on reviewer rotate', 'room cleared unexpectedly');
  }

  const migrated = await prisma.presentationShareLink.findMany({
    where: { projectId: ctx.presentationId },
    select: { role: true, token: true, enabled: true },
  });
  const roles = migrated.map((r) => r.role).sort();
  if (roles.every((r) => r === 'VIEWER' || r === 'REVIEWER')) {
    pass('DB roles enum', roles.join(', '));
  } else {
    fail('DB roles enum', roles.join(', '));
  }

  const cols = await prisma.$queryRaw`
    SELECT column_name FROM information_schema.columns
    WHERE table_name = 'presentation_share_links'
    AND column_name IN ('access', 'expires_at', 'role')
  `;
  const colNames = cols.map((c) => c.column_name);
  if (colNames.includes('role') && !colNames.includes('access') && !colNames.includes('expires_at')) {
    pass('Schema columns', 'role present; access/expires_at dropped');
  } else {
    fail('Schema columns', colNames.join(', '));
  }

  await shareService.updateShareForRole({
    workspaceId: ctx.workspaceId,
    presentationId: ctx.presentationId,
    userId: ctx.userId,
    ip: '127.0.0.1',
    role: shareService.ROLE_VIEWER,
    enabled: true,
  });

  if (!hadViewer && !hadReviewer) {
    // leave both enabled for dev; cleanup not required
  }

  return { viewerToken, reviewerToken };
}

async function runHttpTests(ctx, viewerToken, reviewerToken) {
  console.log('\n=== HTTP API checks ===');

  const shareGet = await httpJson(
    'GET',
    `/api/workspaces/${ctx.workspaceId}/presentations/${ctx.presentationId}/share`,
    { token: ctx.accessToken }
  );
  if (shareGet.status === 200 && shareGet.json?.data?.viewer && shareGet.json?.data?.reviewer) {
    pass('HTTP GET share', '200 with viewer+reviewer');
  } else {
    fail('HTTP GET share', `status=${shareGet.status} body=${JSON.stringify(shareGet.json)}`);
  }

  const oldRoutes = [
    ['PUT', `/api/workspaces/${ctx.workspaceId}/presentations/${ctx.presentationId}/share`],
    ['PATCH', `/api/workspaces/${ctx.workspaceId}/presentations/${ctx.presentationId}/share`],
    ['POST', `/api/workspaces/${ctx.workspaceId}/presentations/${ctx.presentationId}/share/rotate`],
  ];
  for (const [method, urlPath] of oldRoutes) {
    const res = await httpJson(method, urlPath, {
      token: ctx.accessToken,
      body: method === 'PATCH' ? { enabled: false } : undefined,
    });
    if (res.status === 404 || res.status === 405) {
      pass(`Old route removed ${method} /share`, `status=${res.status}`);
    } else {
      fail(`Old route removed ${method} /share`, `status=${res.status} (expected 404/405)`);
    }
  }

  const deckViewer = await httpJson('GET', `/api/p/${viewerToken}`);
  if (deckViewer.status === 200 && deckViewer.json?.data?.permission === 'view') {
    pass('HTTP GET deck (viewer)', '200 permission=view');
  } else {
    fail('HTTP GET deck (viewer)', `status=${deckViewer.status}`);
  }

  const sessionViewer = await httpJson('GET', `/api/p/${viewerToken}/session`);
  const sv = sessionViewer.json?.data;
  if (sessionViewer.status === 200 && sv?.linkRole === 'viewer' && sv?.canComment === false) {
    pass('HTTP GET session (viewer)', 'linkRole=viewer');
  } else {
    fail('HTTP GET session (viewer)', JSON.stringify(sessionViewer.json));
  }

  const commentsViewer = await httpJson('GET', `/api/p/${viewerToken}/comments`);
  const cv = commentsViewer.json?.data;
  if (
    commentsViewer.status === 200 &&
    Array.isArray(cv?.comments) &&
    cv.comments.length === 0 &&
    cv.nextCursor === null
  ) {
    pass('HTTP GET comments (viewer)', 'empty list 200');
  } else {
    fail('HTTP GET comments (viewer)', JSON.stringify(commentsViewer.json));
  }

  const writeViewer = await httpJson('POST', `/api/p/${viewerToken}/comments`, {
    body: {
      body: 'test',
      slideId: ctx.slideId || '00000000-0000-4000-8000-000000000099',
      viewerSessionId: '11111111-2222-4333-8444-555555555555',
      displayName: 'Guest',
    },
  });
  if (writeViewer.status === 403) {
    pass('HTTP POST comment (viewer)', `403 ${writeViewer.json?.message || ''}`);
  } else {
    fail('HTTP POST comment (viewer)', `status=${writeViewer.status}`);
  }

  const sessionReviewer = await httpJson('GET', `/api/p/${reviewerToken}/session`);
  const sr = sessionReviewer.json?.data;
  if (sessionReviewer.status === 200 && sr?.linkRole === 'reviewer' && sr?.canComment === true) {
    pass('HTTP GET session (reviewer)', 'linkRole=reviewer, canComment=true');
  } else {
    fail('HTTP GET session (reviewer)', JSON.stringify(sessionReviewer.json));
  }

  if (ctx.slideId) {
    const commentsReviewer = await httpJson('GET', `/api/p/${reviewerToken}/comments?slideId=${ctx.slideId}`);
    if (commentsReviewer.status === 200) {
      pass('HTTP GET comments (reviewer)', '200');
    } else {
      fail('HTTP GET comments (reviewer)', `status=${commentsReviewer.status}`);
    }
  } else {
    skip('HTTP GET comments (reviewer)', 'no READY slide on test deck');
  }

  const presenceViewer = await httpJson('PUT', `/api/p/${viewerToken}/presence`, {
    body: { viewerSessionId: '11111111-2222-4333-8444-555555555555', slideIndex: 1 },
  });
  const presenceReviewer = await httpJson('PUT', `/api/p/${reviewerToken}/presence`, {
    body: { viewerSessionId: '22222222-3333-4444-8555-666666666666', slideIndex: 2 },
  });
  if (presenceViewer.status === 200 && presenceReviewer.status === 200) {
    const count = presenceReviewer.json?.data?.viewerCount;
    pass('HTTP unified presence', `viewerCount=${count}`);
  } else {
    fail('HTTP unified presence', `viewer=${presenceViewer.status} reviewer=${presenceReviewer.status}`);
  }

  if (writeViewer.json?.message === messages.PRESENTATION_COMMENT_DISABLED) {
    pass('Comment disabled message', messages.PRESENTATION_COMMENT_DISABLED);
  } else {
    skip('Comment disabled message', writeViewer.json?.message || 'no message');
  }
}

async function main() {
  console.log('Viewer/Reviewer share link verification\n');

  await connectRedis();
  await prisma.$connect();

  const ctx = await findTestContext();
  if (!ctx) {
    console.error('No suitable PRESENTATION project found in DB (need workspace member + non-GENERATING deck).');
    process.exit(1);
  }

  console.log(`Test deck: ${ctx.presentationId} (${ctx.deckStatus})`);
  console.log(`Workspace: ${ctx.workspaceId}, user: ${ctx.userEmail}`);

  const { viewerToken, reviewerToken } = await runServiceTests(ctx);

  const up = await serverUp();
  if (up) {
    console.log(`\nServer detected at ${BASE}`);
    await runHttpTests(ctx, viewerToken, reviewerToken);
  } else {
    skip('HTTP API checks', `server not running on ${BASE} — start with npm run dev and re-run`);
  }

  await prisma.$disconnect();
  try {
    await redisClient.quit();
  } catch {
    // ignore
  }

  const passed = results.filter((r) => r.status === 'PASS').length;
  const failed = results.filter((r) => r.status === 'FAIL').length;
  const skipped = results.filter((r) => r.status === 'SKIP').length;

  console.log(`\n=== Summary: ${passed} passed, ${failed} failed, ${skipped} skipped ===`);
  if (failed > 0) {
    console.log('\nFailures:');
    results.filter((r) => r.status === 'FAIL').forEach((r) => console.log(`  - ${r.name}: ${r.detail}`));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
