/**
 * Live HTTP smoke tests for VIDEO_SCENE template APIs (+ isolation checks).
 * Requires server on BASE_URL and smoke user from ensure-smoke-user.js
 */
const BASE = process.env.SMOKE_BASE_URL || 'http://127.0.0.1:9000/api';

const CTX = {
  email: 'api.smoke.videotemplates@example.com',
  password: 'SmokeTest123!',
  workspaceId: 'e1600524-7f96-4784-8375-a8769dcc707d',
  folderId: 'ff6edb39-32fd-4447-a838-ba0d539b4db7',
  videoTemplateId: 'cms2tt42e0002xsurpxe378vp',
};

const results = [];

async function req(method, path, { token, body, expectStatus } = {}) {
  const headers = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  const ok =
    expectStatus != null ? res.status === expectStatus : res.status >= 200 && res.status < 300;
  return { ok, status: res.status, json, expectStatus };
}

function record(name, outcome) {
  results.push({
    name,
    pass: outcome.ok,
    status: outcome.status,
    expect: outcome.expectStatus,
    message: outcome.json?.message || null,
    detail: outcome.detail || null,
  });
  const mark = outcome.ok ? 'PASS' : 'FAIL';
  console.log(
    `${mark} ${name} [${outcome.status}${outcome.expectStatus ? ` expected ${outcome.expectStatus}` : ''}] ${outcome.json?.message || outcome.detail || ''}`
  );
}

async function main() {
  console.log('BASE', BASE);

  // health
  {
    const res = await fetch(BASE.replace(/\/api$/, '') + '/health');
    const json = await res.json().catch(() => ({}));
    record('GET /health', { ok: res.status === 200, status: res.status, json });
  }

  // login
  const login = await req('POST', '/auth/login', {
    body: { email: CTX.email, password: CTX.password },
    expectStatus: 200,
  });
  record('POST /auth/login', login);
  const token = login.json?.data?.accessToken;
  if (!token) {
    console.error('No access token; aborting');
    process.exit(1);
  }

  // list video templates (both types + gallery fields)
  const list = await req('GET', `/workspaces/${CTX.workspaceId}/video-templates`, {
    token,
    expectStatus: 200,
  });
  const listTemplates = list.json?.data?.templates || [];
  record('GET .../video-templates', {
    ...list,
    ok:
      list.ok &&
      Array.isArray(listTemplates) &&
      listTemplates.length >= 1 &&
      listTemplates.every((t) => t.type === 'VIDEO_SCENE' || t.type === 'VIDEO_PACK') &&
      listTemplates.every(
        (t) =>
          Array.isArray(t.media) &&
          Object.prototype.hasOwnProperty.call(t, 'previewImageUrl') &&
          t.preview &&
          typeof t.preview === 'object'
      ),
    detail: `count=${listTemplates.length} galleryFields=ok`,
  });

  // filter VIDEO_SCENE only
  const listScenes = await req(
    'GET',
    `/workspaces/${CTX.workspaceId}/video-templates?type=VIDEO_SCENE`,
    { token, expectStatus: 200 }
  );
  const sceneOnly = listScenes.json?.data?.templates || [];
  record('GET .../video-templates?type=VIDEO_SCENE', {
    ...listScenes,
    ok:
      listScenes.ok &&
      sceneOnly.length >= 1 &&
      sceneOnly.every((t) => t.type === 'VIDEO_SCENE'),
    detail: `count=${sceneOnly.length}`,
  });

  // ensure no DECK_LAYOUT leaked
  const leaked = listTemplates.filter(
    (t) => t.type !== 'VIDEO_SCENE' && t.type !== 'VIDEO_PACK'
  );
  record('isolation: video-templates only VIDEO_*', {
    ok: leaked.length === 0,
    status: 200,
    json: { message: leaked.length ? `leaked ${leaked.length}` : 'clean' },
  });

  // get one
  const one = await req(
    'GET',
    `/workspaces/${CTX.workspaceId}/video-templates/${CTX.videoTemplateId}`,
    { token, expectStatus: 200 }
  );
  record('GET .../video-templates/:id', {
    ...one,
    ok: one.ok && one.json?.data?.template?.type === 'VIDEO_SCENE',
  });

  // deck layout id should 404 on video path
  const prisma = require('../src/shared/config/prismaClient');
  const deck = await prisma.template.findFirst({
    where: { type: 'DECK_LAYOUT', isActive: true },
    select: { id: true },
  });
  const deckOnVideo = await req(
    'GET',
    `/workspaces/${CTX.workspaceId}/video-templates/${deck.id}`,
    { token, expectStatus: 404 }
  );
  record('GET video-templates with DECK_LAYOUT id → 404', deckOnVideo);

  // create project from template
  const created = await req('POST', `/workspaces/${CTX.workspaceId}/projects`, {
    token,
    body: {
      title: `Smoke Video ${Date.now()}`,
      folderId: CTX.folderId,
      aspectRatio: '16:9',
      templateId: CTX.videoTemplateId,
    },
    expectStatus: 201,
  });
  const project = created.json?.data?.project;
  const scenes = project?.data?.scenes || [];
  record('POST .../projects with templateId', {
    ...created,
    ok:
      created.ok &&
      project?.type === 'VIDEO' &&
      scenes.length === 1 &&
      scenes[0].templateId === CTX.videoTemplateId,
    detail: `type=${project?.type} scenes=${scenes.length} stamp=${scenes[0]?.templateId}`,
  });

  // conflict: templateId + scenes
  const conflict = await req('POST', `/workspaces/${CTX.workspaceId}/projects`, {
    token,
    body: {
      title: `Conflict ${Date.now()}`,
      folderId: CTX.folderId,
      templateId: CTX.videoTemplateId,
      data: {
        scenes: [
          {
            sceneId: 'x',
            durationInFrames: 30,
            background: { type: 'solid', value: '#000' },
            elements: [],
          },
        ],
      },
    },
    expectStatus: 400,
  });
  record('POST projects templateId + scenes → 400', conflict);

  // append scene
  const projectId = project?.id;
  const appended = await req(
    'POST',
    `/workspaces/${CTX.workspaceId}/projects/${projectId}/scenes/from-template`,
    {
      token,
      body: { templateId: CTX.videoTemplateId },
      expectStatus: 200,
    }
  );
  const afterScenes = appended.json?.data?.project?.data?.scenes || [];
  record('POST .../scenes/from-template', {
    ...appended,
    ok: appended.ok && afterScenes.length === 2,
    detail: `scenes=${afterScenes.length}`,
  });

  // create presentation then reject video template apply
  const pres = await req('POST', `/workspaces/${CTX.workspaceId}/presentations`, {
    token,
    body: { title: `Smoke PPT ${Date.now()}`, folderId: CTX.folderId },
    expectStatus: 201,
  });
  record('POST .../presentations (create)', {
    ...pres,
    ok: pres.ok && pres.json?.data?.project?.type === 'PRESENTATION',
  });
  const presentationId = pres.json?.data?.project?.id;
  const rejectApply = await req(
    'POST',
    `/workspaces/${CTX.workspaceId}/projects/${presentationId}/scenes/from-template`,
    {
      token,
      body: { templateId: CTX.videoTemplateId },
      expectStatus: 400,
    }
  );
  record('POST scenes/from-template on PRESENTATION → 400', rejectApply);

  // superadmin list templates
  const adminList = await req('GET', '/superadmin/templates?type=VIDEO_SCENE', {
    token,
    expectStatus: 200,
  });
  record('GET /superadmin/templates?type=VIDEO_SCENE', {
    ...adminList,
    ok:
      adminList.ok &&
      Array.isArray(adminList.json?.data?.templates) &&
      adminList.json.data.templates.every((t) => t.type === 'VIDEO_SCENE'),
    detail: `count=${adminList.json?.data?.templates?.length}`,
  });

  // superadmin create VIDEO_SCENE
  const createdTpl = await req('POST', '/superadmin/templates', {
    token,
    body: {
      type: 'VIDEO_SCENE',
      name: `Smoke Template ${Date.now()}`,
      contentType: 'title',
      variant: 'smoke',
      schema: {
        version: 1,
        videoSettings: { width: 1920, height: 1080, fps: 30 },
        scene: {
          name: 'Smoke',
          durationInFrames: 60,
          background: { type: 'solid', value: '#111' },
          elements: [
            {
              id: 't1',
              type: 'text',
              layer: 1,
              startFrame: 0,
              durationInFrames: 60,
              placement: { x: 0, y: 0, width: 100, height: 40 },
              content: { text: 'Hi' },
            },
          ],
        },
      },
    },
    expectStatus: 201,
  });
  record('POST /superadmin/templates VIDEO_SCENE', {
    ...createdTpl,
    ok: createdTpl.ok && createdTpl.json?.data?.template?.type === 'VIDEO_SCENE',
  });

  // reject deck shape as VIDEO_SCENE
  const badSchema = await req('POST', '/superadmin/templates', {
    token,
    body: {
      type: 'VIDEO_SCENE',
      name: 'Bad deck shape',
      schema: {
        layout_id: 'x',
        content_type: 'title',
        grid: '12-col',
        slots: [],
      },
    },
    expectStatus: 400,
  });
  record('POST VIDEO_SCENE with deck schema → 400', badSchema);

  await prisma.$disconnect().catch(() => {});

  const failed = results.filter((r) => !r.pass);
  console.log('\n=== SUMMARY ===');
  console.log(`passed=${results.length - failed.length} failed=${failed.length} total=${results.length}`);
  if (failed.length) {
    for (const f of failed) {
      console.log('FAIL', f.name, f.status, f.message || f.detail);
    }
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
