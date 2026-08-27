/**
 * Smoke test: Gemini image models across image + infographic modes.
 * Usage: node scripts/smoke-gemini-image.js
 * Requires: Redis, Postgres, OPENAI_API_KEY, GEMINI_API_KEY, server on SMOKE_BASE_URL (default :9000)
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env.development') });
const axios = require('axios');
const prisma = require('../src/shared/config/prismaClient');
const { signAccessToken } = require('../src/shared/utils/jwt');
const sessionService = require('../src/modules/sessions/session.service');
const { connectRedis } = require('../src/shared/config/redis');

const base = process.env.SMOKE_BASE_URL || 'http://localhost:9000';

const GEMINI_MODELS = [
  { id: 'gemini-3-pro-image', ac: 12, maxImageSize: '4K' },
  { id: 'gemini-3.1-flash-image', ac: 8, maxImageSize: '4K' },
  { id: 'gemini-3.1-flash-lite-image', ac: 4, maxImageSize: '1K' },
];

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

    const user = await prisma.user.findFirst({
      where: {
        credits: { gte: 60 },
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
    if (!user) throw new Error('No credited user with a PRIVATE workspace found');

    const workspace = user.ownedWorkspaces[0];
    let folder = workspace.folders?.[0];
    if (!folder) {
      folder = await prisma.folder.create({
        data: { name: 'Gemini Smoke', workspaceId: workspace.id, createdBy: user.id },
      });
    }

    sessionId = await sessionService.createSession({
      userId: user.id,
      userAgent: 'smoke-gemini-image',
      ip: '127.0.0.1',
    });
    const token = signAccessToken({ sub: user.id, sessionId });
    const headers = { Authorization: `Bearer ${token}` };
    ok(
      'Auth fixture',
      true,
      `user=${user.email} credits=${user.credits} workspace=${workspace.id} folder=${folder.id}`
    );

    const models = await axios.get(`${base}/api/image-gen/models`, { headers });
    const list = models.data?.data?.models || [];
    for (const expected of GEMINI_MODELS) {
      const entry = list.find((m) => m.id === expected.id);
      ok(
        `GET /models lists ${expected.id}`,
        Boolean(entry) &&
          entry.provider === 'gemini' &&
          entry.maxImageSize === expected.maxImageSize &&
          entry.supportsEdit === true &&
          ['image', 'infographic'].every((mode) => (entry.modes || []).includes(mode)) &&
          entry.creditEstimate === expected.ac,
        `provider=${entry?.provider} maxImageSize=${entry?.maxImageSize} ac=${entry?.creditEstimate} modes=${(entry?.modes || []).join('|')}`
      );
    }

    for (const expected of GEMINI_MODELS) {
      // eslint-disable-next-line no-await-in-loop
      const estimate = await axios.get(
        `${base}/api/image-gen/workspaces/${workspace.id}/estimate`,
        { headers, params: { mode: 'infographic', modelId: expected.id } }
      );
      ok(
        `GET /estimate ${expected.id}`,
        estimate.data?.data?.athenaCredits === expected.ac,
        JSON.stringify(estimate.data?.data)
      );
    }

    const hasKey = Boolean(
      (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim()) ||
        (process.env.GOOGLE_API_KEY && process.env.GOOGLE_API_KEY.trim())
    );

    if (!hasKey) {
      console.log('\nGEMINI_API_KEY not set — verifying the 503 contract instead of generating.\n');
      try {
        await axios.post(
          `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
          {
            mode: 'image',
            folderId: folder.id,
            modelId: 'gemini-3-pro-image',
            prompt: 'A calm modern workspace at golden hour.',
          },
          { headers, timeout: 60000 }
        );
        ok('POST /generate without GEMINI_API_KEY → 503', false, 'expected 503');
      } catch (e) {
        ok(
          'POST /generate without GEMINI_API_KEY → 503',
          e.response?.status === 503,
          `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
        );
      }

      const failedEarly = results.filter((r) => !r.pass).length;
      console.log(
        `\nSUMMARY: ${results.length - failedEarly}/${results.length} passed (catalog + 503 contract only; set GEMINI_API_KEY for live renders)`
      );
      if (sessionId) {
        try {
          await sessionService.deleteSession({ sessionId });
        } catch {
          // ignore
        }
        sessionId = null;
      }
      await prisma.$disconnect();
      process.exit(failedEarly ? 1 : 0);
    }

    const generated = [];
    for (const expected of GEMINI_MODELS) {
      console.log(`\n… generating image mode with ${expected.id} …\n`);
      const started = Date.now();
      try {
        // eslint-disable-next-line no-await-in-loop
        const gen = await axios.post(
          `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
          {
            mode: 'image',
            folderId: folder.id,
            modelId: expected.id,
            formatId: 'landscape',
            prompt: 'A calm modern workspace at golden hour, wide shot, soft natural light.',
          },
          { headers, timeout: 240000 }
        );
        const data = gen.data?.data;
        generated.push({ modelId: expected.id, generation: data?.generation });
        ok(
          `POST /generate image ${expected.id}`,
          gen.status === 201 &&
            data?.generation?.mode === 'image' &&
            data?.generation?.modelId === expected.id &&
            Boolean(data?.generation?.url),
          `latencyMs=${Date.now() - started} genId=${data?.generation?.id} credits=${data?.creditsCharged}`
        );
      } catch (e) {
        ok(
          `POST /generate image ${expected.id}`,
          false,
          `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
        );
      }
    }

    console.log('\n… generating infographic with gemini-3-pro-image (spec + render) …\n');
    let infographic = null;
    let thread = null;
    const infoStarted = Date.now();
    try {
      const gen = await axios.post(
        `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
        {
          mode: 'infographic',
          folderId: folder.id,
          modelId: 'gemini-3-pro-image',
          formatId: 'landscape',
          archetypeHint: 'comparison',
          styleHint: 'minimal, clean corporate',
          prompt:
            'Compare solar and wind energy on cost, build time, land use, and output reliability.',
        },
        { headers, timeout: 300000 }
      );
      const data = gen.data?.data;
      infographic = data?.generation || null;
      thread = data?.thread || null;
      ok(
        'POST /generate infographic gemini-3-pro-image',
        gen.status === 201 &&
          infographic?.mode === 'infographic' &&
          infographic?.modelId === 'gemini-3-pro-image' &&
          Boolean(infographic?.infographicSpec?.title) &&
          Boolean(infographic?.url),
        `latencyMs=${Date.now() - infoStarted} genId=${infographic?.id} archetype=${infographic?.archetype} credits=${data?.creditsCharged}`
      );
    } catch (e) {
      ok(
        'POST /generate infographic gemini-3-pro-image',
        false,
        `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
      );
    }

    if (infographic?.id) {
      const dl = await axios.get(
        `${base}/api/image-gen/workspaces/${workspace.id}/generations/${infographic.id}/download`,
        { headers, params: { format: 'png' }, responseType: 'arraybuffer', timeout: 60000 }
      );
      ok(
        'GET /download png',
        dl.status === 200 && dl.data?.byteLength > 10000,
        `bytes≈${dl.data?.byteLength}`
      );
    }

    const editParent = generated.find((g) => g.modelId === 'gemini-3-pro-image')?.generation;
    if (editParent?.id) {
      console.log('\n… pixel edit on a Gemini parent (must stay on Gemini) …\n');
      try {
        const tweak = await axios.post(
          `${base}/api/image-gen/workspaces/${workspace.id}/generations/${editParent.id}/tweak`,
          { instruction: 'Make the overall tone cooler and slightly darker.', editMode: 'pixel' },
          { headers, timeout: 300000 }
        );
        const hop = tweak.data?.data?.generation;
        ok(
          'POST /tweak pixel stays on Gemini',
          tweak.status === 201 && hop?.modelId === 'gemini-3-pro-image' && Boolean(hop?.url),
          `newGenId=${hop?.id} modelId=${hop?.modelId} credits=${tweak.data?.data?.creditsCharged}`
        );
      } catch (e) {
        ok(
          'POST /tweak pixel stays on Gemini',
          false,
          `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
        );
      }
    }

    if (thread?.id) {
      const thr = await axios.get(
        `${base}/api/image-gen/workspaces/${workspace.id}/threads/${thread.id}`,
        { headers }
      );
      ok(
        'GET /threads/:id keeps mode + model',
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
