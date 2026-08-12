require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.development') });
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');
const prisma = require('../src/shared/config/prismaClient');
const { signAccessToken } = require('../src/shared/utils/jwt');
const sessionService = require('../src/modules/sessions/session.service');
const { connectRedis } = require('../src/shared/config/redis');

const base = process.env.SMOKE_BASE_URL || 'http://localhost:9000';

(async () => {
  const results = [];
  const ok = (name, pass, detail) => {
    results.push({ name, pass, detail });
    console.log(`${pass ? 'PASS' : 'FAIL'} | ${name}${detail ? ` — ${detail}` : ''}`);
  };

  let sessionId = null;
  try {
    await connectRedis();

    const health = await axios.get(`${base}/health`);
    ok('GET /health', health.status === 200, JSON.stringify(health.data));

    try {
      await axios.get(`${base}/api/image-gen/models`);
      ok('GET /models without auth → 401', false, 'expected 401');
    } catch (e) {
      ok('GET /models without auth → 401', e.response?.status === 401, `status=${e.response?.status}`);
    }

    // Prefer a PRIVATE workspace whose owner has personal credits (billing pool = owner).
    const creditedOwner = await prisma.user.findFirst({
      where: {
        credits: { gte: 20 },
        ownedWorkspaces: { some: { type: 'PRIVATE' } },
      },
      include: {
        ownedWorkspaces: {
          where: { type: 'PRIVATE' },
          take: 1,
        },
      },
      orderBy: { credits: 'desc' },
    });

    const user =
      creditedOwner ||
      (await prisma.user.findFirst({
        where: {
          OR: [{ ownedWorkspaces: { some: {} } }, { workspaceMemberships: { some: {} } }],
        },
        include: {
          ownedWorkspaces: { take: 1 },
          workspaceMemberships: { take: 1, include: { workspace: true } },
        },
        orderBy: { createdAt: 'asc' },
      }));
    if (!user) throw new Error('No user with workspace found');
    const workspace =
      user.ownedWorkspaces?.[0] || user.workspaceMemberships?.[0]?.workspace;
    if (!workspace) throw new Error('No workspace found');
    sessionId = await sessionService.createSession({
      userId: user.id,
      userAgent: 'smoke-image-gen-context',
      ip: '127.0.0.1',
    });
    const token = signAccessToken({ sub: user.id, sessionId });
    const headers = { Authorization: `Bearer ${token}` };
    ok('Auth fixture', true, `user=${user.email} workspace=${workspace.id}`);

    const models = await axios.get(`${base}/api/image-gen/models`, { headers });
    ok(
      'GET /models',
      models.status === 200 && Array.isArray(models.data?.data?.models),
      `count=${models.data?.data?.models?.length || 0}`
    );

    try {
      const fd = new FormData();
      fd.append('payload', JSON.stringify({}));
      await axios.post(`${base}/api/image-gen/workspaces/${workspace.id}/context`, fd, {
        headers: { ...headers, ...fd.getHeaders() },
      });
      ok('POST /context empty → 400', false, 'expected 400');
    } catch (e) {
      ok(
        'POST /context empty → 400',
        e.response?.status === 400,
        `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.response?.data)}`
      );
    }

    const tmp = path.join(__dirname, 'tmp-context-brief.md');
    fs.writeFileSync(tmp, '# Brief\n\nUse a clean blue SaaS look with teal accents.\n');
    const fd2 = new FormData();
    fd2.append('payload', JSON.stringify({ inlineText: 'Make it look premium and minimal.' }));
    fd2.append('files', fs.createReadStream(tmp), {
      filename: 'brief.md',
      contentType: 'text/markdown',
    });
    const created = await axios.post(
      `${base}/api/image-gen/workspaces/${workspace.id}/context`,
      fd2,
      {
        headers: { ...headers, ...fd2.getHeaders() },
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        timeout: 120000,
      }
    );
    const ctx = created.data?.data?.context;
    ok(
      'POST /context create',
      created.status === 201 && !!ctx?.id,
      `id=${ctx?.id} docs=${ctx?.previews?.documents?.length || 0}`
    );
    fs.unlinkSync(tmp);

    const got = await axios.get(
      `${base}/api/image-gen/workspaces/${workspace.id}/context/${ctx.id}`,
      { headers }
    );
    ok(
      'GET /context/:id',
      got.status === 200 && got.data?.data?.context?.id === ctx.id,
      `status=${got.status}`
    );

    try {
      await axios.post(
        `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
        {
          mode: 'image',
          modelId: 'gpt-image-1',
          formatId: 'square',
          prompt: 'test',
          contextId: '00000000-0000-4000-8000-000000000000',
        },
        { headers, timeout: 30000 }
      );
      ok('POST /generate bad contextId → error', false, 'expected error');
    } catch (e) {
      ok(
        'POST /generate bad contextId → error',
        [400, 404].includes(e.response?.status),
        `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.response?.data)}`
      );
    }

    let generationId = null;
    try {
      const gen = await axios.post(
        `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
        {
          mode: 'image',
          modelId: 'gpt-image-1',
          formatId: 'square',
          prompt: 'A minimal product hero image for a SaaS dashboard',
          contextId: ctx.id,
        },
        { headers, timeout: 180000 }
      );
      const g = gen.data?.data?.generation;
      generationId = g?.id || null;
      ok(
        'POST /generate with contextId',
        gen.status === 201 && !!g?.id,
        `genId=${g?.id} contextId=${g?.contextId} preview=${JSON.stringify(g?.contextPreview)}`
      );
    } catch (e) {
      ok(
        'POST /generate with contextId',
        false,
        `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
      );
    }

    if (generationId) {
      try {
        await axios.delete(
          `${base}/api/image-gen/workspaces/${workspace.id}/context/${ctx.id}`,
          { headers }
        );
        ok('DELETE pinned context → 409', false, 'expected 409');
      } catch (e) {
        ok(
          'DELETE pinned context → 409',
          e.response?.status === 409,
          `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.response?.data)}`
        );
      }
    } else {
      const del = await axios.delete(
        `${base}/api/image-gen/workspaces/${workspace.id}/context/${ctx.id}`,
        { headers }
      );
      ok('DELETE unpinned context', del.status === 200, `status=${del.status}`);
    }
  } catch (err) {
    console.error('SMOKE FATAL', err.response?.data || err.message || err);
  } finally {
    if (sessionId) {
      try {
        await sessionService.deleteSession({ sessionId });
      } catch {
        // ignore
      }
    }
    const failed = results.filter((r) => !r.pass).length;
    console.log(`\nSUMMARY: ${results.length - failed}/${results.length} passed`);
    await prisma.$disconnect();
    process.exit(failed ? 1 : 0);
  }
})();
