/**
 * Focused Gemini Pro live smoke (image + pixel tweak + infographic).
 * Usage: node scripts/smoke-gemini-pro.js
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
    results.push({ name, pass });
    console.log(`${pass ? 'PASS' : 'FAIL'} | ${name}${detail ? ` — ${detail}` : ''}`);
  };

  let sessionId = null;
  try {
    await connectRedis();
    const user = await prisma.user.findFirst({
      where: { credits: { gte: 40 }, ownedWorkspaces: { some: { type: 'PRIVATE' } } },
      include: {
        ownedWorkspaces: {
          where: { type: 'PRIVATE' },
          take: 1,
          include: { folders: { take: 1, orderBy: { createdAt: 'asc' } } },
        },
      },
      orderBy: { credits: 'desc' },
    });
    if (!user) throw new Error('No credited user found');
    const workspace = user.ownedWorkspaces[0];
    const folder = workspace.folders[0];
    sessionId = await sessionService.createSession({
      userId: user.id,
      userAgent: 'smoke-gemini-pro',
      ip: '127.0.0.1',
    });
    const headers = {
      Authorization: `Bearer ${signAccessToken({ sub: user.id, sessionId })}`,
    };

    console.log('\n… Pro image generate …\n');
    let t0 = Date.now();
    const img = await axios.post(
      `${base}/api/image-gen/workspaces/${workspace.id}/generate`,
      {
        mode: 'image',
        folderId: folder.id,
        modelId: 'gemini-3-pro-image',
        formatId: 'landscape',
        prompt: 'A calm modern workspace at golden hour, wide shot, soft natural light.',
      },
      { headers, timeout: 420000 }
    );
    const gen = img.data?.data?.generation;
    ok(
      'Pro image generate',
      img.status === 201 && gen?.modelId === 'gemini-3-pro-image' && Boolean(gen?.url),
      `latencyMs=${Date.now() - t0} genId=${gen?.id} credits=${img.data?.data?.creditsCharged}`
    );

    console.log('\n… Pro pixel tweak …\n');
    t0 = Date.now();
    const tw = await axios.post(
      `${base}/api/image-gen/workspaces/${workspace.id}/generations/${gen.id}/tweak`,
      {
        instruction: 'Make the overall tone cooler and slightly darker.',
        editMode: 'pixel',
      },
      { headers, timeout: 420000 }
    );
    const hop = tw.data?.data?.generation;
    ok(
      'Pro pixel tweak',
      tw.status === 201 && hop?.modelId === 'gemini-3-pro-image' && Boolean(hop?.url),
      `latencyMs=${Date.now() - t0} newGenId=${hop?.id}`
    );

    console.log('\n… Pro infographic generate …\n');
    t0 = Date.now();
    const info = await axios.post(
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
      { headers, timeout: 480000 }
    );
    const igen = info.data?.data?.generation;
    ok(
      'Pro infographic generate',
      info.status === 201 &&
        igen?.mode === 'infographic' &&
        igen?.modelId === 'gemini-3-pro-image' &&
        Boolean(igen?.infographicSpec?.title) &&
        Boolean(igen?.url),
      `latencyMs=${Date.now() - t0} genId=${igen?.id} archetype=${igen?.archetype} credits=${info.data?.data?.creditsCharged}`
    );
  } catch (e) {
    ok(
      'FATAL',
      false,
      `status=${e.response?.status} msg=${JSON.stringify(e.response?.data?.message || e.message)}`
    );
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
