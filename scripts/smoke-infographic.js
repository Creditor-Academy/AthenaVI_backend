/**
 * Smoke test: Image Gen infographic mode (catalogs, estimate, generate, chat routing).
 * Usage: node scripts/smoke-infographic.js
 * Requires: Redis, Postgres, OPENAI_API_KEY, server on SMOKE_BASE_URL (default :9000)
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.development') });
const axios = require('axios');
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

    const health = await axios.get(`${base}/health`, { timeout: 10000 });
    ok('GET /health', health.status === 200, JSON.stringify(health.data));

    const creditedOwner = await prisma.user.findFirst({
      where: {
        credits: { gte: 30 },
        ownedWorkspaces: { some: { type: 'PRIVATE' } },
      },
      include: {
        ownedWorkspaces: {
          where: { type: 'PRIVATE' },
          take: 1,
          include: { folders: { take: 1, orderBy: { createdAt: 'asc' } } },
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
          ownedWorkspaces: {
            take: 1,
            include: { folders: { take: 1, orderBy: { createdAt: 'asc' } } },
          },
          workspaceMemberships: {
            take: 1,
            include: {
              workspace: { include: { folders: { take: 1, orderBy: { createdAt: 'asc' } } } },
            },
          },
        },
        orderBy: { createdAt: 'asc' },
      }));

    if (!user) throw new Error('No user with workspace found');
    const workspace =
      user.ownedWorkspaces?.[0] || user.workspaceMemberships?.[0]?.workspace;
    if (!workspace) throw new Error('No workspace found');

    let folder = workspace.folders?.[0];
    if (!folder) {
      folder = await prisma.folder.create({
        data: {
          name: 'Infographic Smoke',
          workspaceId: workspace.id,
          createdBy: user.id,
        },
      });
    }

    sessionId = await sessionService.createSession({
      userId: user.id,
      userAgent: 'smoke-infographic',
      ip: '127.0.0.1',
    });
    const token = signAccessToken({ sub: user.id, sessionId });
    const headers = { Authorization: `Bearer ${token}` };
    ok(
      'Auth fixture',
      true,
      `user=${user.email} credits=${user.credits} workspace=${workspace.id} folder=${folder.id}`
    );

    const archetypes = await axios.get(`${base}/api/image-gen/archetypes`, { headers });
    const archList = archetypes.data?.data?.archetypes || [];
    ok(
      'GET /archetypes',
      archetypes.status === 200 && archList.length === 7,
      `ids=${archList.map((a) => a.id).join(',')}`
    );

    const models = await axios.get(`${base}/api/image-gen/models`, { headers });
    const modelList = models.data?.data?.models || [];
    const supportsInfographic = modelList.every((m) => (m.modes || []).includes('infographic'));
    ok(
      'GET /models includes infographic mode',
      models.status === 200 && supportsInfographic,
      `count=${modelList.length}`
    );

    const estimate = await axios.get(
      `${base}/api/image-gen/workspaces/${workspace.id}/estimate`,
      {
        headers,
        params: { mode: 'infographic', modelId: 'gpt-image-1-hd' },
      }
    );
    ok(
      'GET /estimate mode=infographic',
      estimate.status === 200 && Number(estimate.data?.data?.athenaCredits) > 0,
      JSON.stringify(estimate.data?.data)
    );

    try {
      await axios.post(
        `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
        {
          mode: 'infographic',
          folderId: folder.id,
          prompt: 'test',
          headline: 'should-fail',
        },
        { headers, timeout: 15000 }
      );
      ok('POST /generate forbidden headline → 400', false, 'expected 400');
    } catch (e) {
      ok(
        'POST /generate forbidden headline → 400',
        e.response?.status === 400,
        `status=${e.response?.status}`
      );
    }

    try {
      await axios.post(
        `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
        {
          mode: 'social',
          folderId: folder.id,
          prompt: 'test',
        },
        { headers, timeout: 15000 }
      );
      ok('POST /generate mode=social → 400', false, 'expected 400');
    } catch (e) {
      ok(
        'POST /generate mode=social → 400',
        e.response?.status === 400,
        `status=${e.response?.status}`
      );
    }

    console.log('\n… generating infographic (spec + HD image, may take 60–120s) …\n');
    const started = Date.now();
    let generation = null;
    let thread = null;
    try {
      const gen = await axios.post(
        `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
        {
          mode: 'infographic',
          folderId: folder.id,
          modelId: 'gpt-image-1-hd',
          formatId: 'landscape',
          archetypeHint: 'process',
          styleHint: 'minimal, clean corporate',
          prompt:
            'Explain a 4-step customer onboarding funnel: 1) Sign up 2) Verify email 3) Complete profile 4) First project. Title: Customer Onboarding.',
        },
        { headers, timeout: 180000 }
      );
      const data = gen.data?.data;
      generation = data?.generation || null;
      thread = data?.thread || null;
      const latencyMs = Date.now() - started;
      ok(
        'POST /generate infographic',
        gen.status === 201 &&
          generation?.mode === 'infographic' &&
          !!generation?.infographicSpec?.title &&
          !!generation?.url &&
          !!thread?.id,
        `latencyMs=${latencyMs} genId=${generation?.id} archetype=${generation?.archetype} title=${generation?.infographicSpec?.title} sections=${generation?.infographicSpec?.sections?.length || 0} credits=${data?.creditsCharged}`
      );
      ok(
        'Thread exposes mode=infographic',
        thread?.mode === 'infographic',
        `thread.mode=${thread?.mode} archetype=${thread?.archetype}`
      );
    } catch (e) {
      ok(
        'POST /generate infographic',
        false,
        `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)} errors=${JSON.stringify(e.response?.data?.errors || [])}`
      );
    }

    if (generation?.id) {
      const listed = await axios.get(
        `${base}/api/image-gen/workspaces/${workspace.id}/generations`,
        { headers, params: { take: 20 } }
      );
      const gens = listed.data?.data?.generations || [];
      ok(
        'GET /generations includes infographic (no mode filter)',
        gens.some((g) => g.id === generation.id && g.mode === 'infographic'),
        `found=${gens.some((g) => g.id === generation.id)}`
      );

      const got = await axios.get(
        `${base}/api/image-gen/workspaces/${workspace.id}/generations/${generation.id}`,
        { headers }
      );
      ok(
        'GET /generations/:id',
        got.status === 200 && got.data?.data?.generation?.infographicSpec?.title,
        `title=${got.data?.data?.generation?.infographicSpec?.title}`
      );

      const dl = await axios.get(
        `${base}/api/image-gen/workspaces/${workspace.id}/generations/${generation.id}/download`,
        { headers, params: { format: 'png' }, responseType: 'arraybuffer', timeout: 60000 }
      );
      ok(
        'GET /download png',
        dl.status === 200 && Number(dl.headers['content-length'] || dl.data?.length || 0) > 1000,
        `bytes≈${dl.data?.length || dl.headers['content-length']}`
      );
    }

    if (thread?.id && generation?.id) {
      console.log('\n… chat: spec-path edit (swap steps) …\n');
      try {
        const msg = await axios.post(
          `${base}/api/image-gen/workspaces/${workspace.id}/threads/${thread.id}/messages`,
          {
            content: 'Swap step 2 and step 3',
            editMode: 'spec',
          },
          { headers, timeout: 180000 }
        );
        const hop = msg.data?.data?.generation;
        ok(
          'POST /messages spec edit',
          msg.status === 201 &&
            hop?.mode === 'infographic' &&
            hop?.id !== generation.id &&
            !hop?.request?.pixelEdited,
          `newGenId=${hop?.id} pixelEdited=${hop?.request?.pixelEdited} sections=${hop?.infographicSpec?.sections?.map((s) => s.label).join(' | ')}`
        );
      } catch (e) {
        ok(
          'POST /messages spec edit',
          false,
          `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
        );
      }

      console.log('\n… chat: pixel-path edit …\n');
      try {
        const msg2 = await axios.post(
          `${base}/api/image-gen/workspaces/${workspace.id}/threads/${thread.id}/messages`,
          {
            content: 'Make the background slightly darker',
            editMode: 'pixel',
          },
          { headers, timeout: 180000 }
        );
        const hop2 = msg2.data?.data?.generation;
        ok(
          'POST /messages pixel edit sets pixelEdited',
          msg2.status === 201 && hop2?.request?.pixelEdited === true,
          `newGenId=${hop2?.id} pixelEdited=${hop2?.request?.pixelEdited}`
        );
      } catch (e) {
        ok(
          'POST /messages pixel edit sets pixelEdited',
          false,
          `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
        );
      }

      const thr = await axios.get(
        `${base}/api/image-gen/workspaces/${workspace.id}/threads/${thread.id}`,
        { headers }
      );
      ok(
        'GET /threads/:id still mode=infographic',
        thr.data?.data?.thread?.mode === 'infographic',
        `mode=${thr.data?.data?.thread?.mode} messages=${thr.data?.data?.thread?.messages?.length}`
      );
    }
  } catch (err) {
    console.error('SMOKE FATAL', err.response?.data || err.message || err);
    ok('SMOKE FATAL', false, err.message || String(err));
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
