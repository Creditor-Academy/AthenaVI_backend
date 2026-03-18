/**
 * Video render worker – processes jobs from the render queue.
 *
 * Flow: load video + scenes from DB → build inputProps → render (external service or stub) → update job.
 *
 * - Set RENDER_SERVICE_URL to POST inputProps to an external render service that returns { outputUrl }.
 * - Otherwise runs a stub that marks the job COMPLETED with outputUrl null (for frontend polling until Remotion is integrated).
 */

require('dotenv').config({ path: process.env.ENV_PATH || '.env.development' });

const prisma = require('../shared/config/prismaClient');
const { renderQueue } = require('../shared/config/renderQueue');
const renderDao = require('../modules/render/render.dao');
const heygenService = require('../modules/heygen/heygen.service');

function buildInputProps(video, scenes) {
  const metadata = video.metadata && typeof video.metadata === 'object' ? video.metadata : {};
  const aspectRatio = metadata.aspectRatio || '16:9';
  return {
    scenes: scenes.map((s) => ({
      id: s.id,
      order: s.order,
      startTime: s.startTime,
      duration: s.duration,
      payload: s.payload && typeof s.payload === 'object' ? s.payload : {},
    })),
    aspectRatio,
  };
}

/** Parse aspect ratio string to HeyGen dimension { width, height }. */
function aspectRatioToDimension(aspectRatio) {
  const normalized = (aspectRatio || '16:9').toString().trim();
  if (normalized === '9:16') return { width: 1080, height: 1920 };
  if (normalized === '1:1') return { width: 1080, height: 1080 };
  return { width: 1920, height: 1080 };
}

/** Build HeyGen background object from scene payload.background (defaults to color #FFFFFF). */
function sceneBackgroundToHeyGen(background) {
  const bg = background && typeof background === 'object' ? background : {};
  const bgType = bg.type === 'image' || bg.type === 'video' ? bg.type : 'color';
  const bgValue = bg.value && /^#[0-9a-fA-F]{6}$/.test(bg.value) ? bg.value : '#FFFFFF';
  return bgType === 'color'
    ? { type: 'color', value: bgValue }
    : { type: bgType, url: bg.url || '' };
}

/**
 * Build HeyGen createVideo payload: one video_inputs entry per scene.
 * Avatar and voice are the same for the whole video (from first scene).
 * Each scene has its own script (input_text) and background.
 */
function buildHeyGenPayload(video, scenes) {
  if (!scenes.length) {
    throw new Error('HeyGen requires at least one scene');
  }

  const firstPayload = (scenes[0].payload && typeof scenes[0].payload === 'object')
    ? scenes[0].payload
    : {};
  const avatarId = firstPayload.avatar != null ? String(firstPayload.avatar) : null;
  const voiceId = firstPayload.avatarSettings?.voice != null
    ? String(firstPayload.avatarSettings.voice)
    : null;

  if (!avatarId || !voiceId) {
    throw new Error('HeyGen requires avatar and voice (set in first scene payload.avatar and payload.avatarSettings.voice)');
  }

  const metadata = video.metadata && typeof video.metadata === 'object' ? video.metadata : {};
  const dimension = aspectRatioToDimension(metadata.aspectRatio);

  const video_inputs = scenes.map((scene) => {
    const p = scene.payload && typeof scene.payload === 'object' ? scene.payload : {};
    const scriptText = p.scriptText != null ? String(p.scriptText).trim() : '';
    const background = sceneBackgroundToHeyGen(p.background);
    return {
      character: { type: 'avatar', avatar_id: avatarId },
      voice: { type: 'text', voice_id: voiceId, input_text: scriptText || ' ' },
      background,
    };
  });

  return {
    video_inputs,
    title: video.name || 'Generated Video',
    dimension,
  };
}

const HEYGEN_POLL_INTERVAL_MS = 5000;
const HEYGEN_POLL_TIMEOUT_MS = 600000; // 10 min

async function renderWithHeyGen(video, scenes) {
  const payload = buildHeyGenPayload(video, scenes);
  const { video_id } = await heygenService.createVideo(payload);
  const deadline = Date.now() + HEYGEN_POLL_TIMEOUT_MS;

  while (Date.now() < deadline) {
    const { status, video_url, error } = await heygenService.getVideoStatus(video_id);
    if (status === 'completed') return video_url || null;
    if (status === 'failed') {
      const msg = error?.message || error?.detail || (typeof error === 'string' ? error : 'HeyGen render failed');
      throw new Error(msg);
    }
    await new Promise((r) => setTimeout(r, HEYGEN_POLL_INTERVAL_MS));
  }

  throw new Error('HeyGen render timed out');
}

/**
 * Call external render service (e.g. Remotion Lambda or custom service).
 * Expects POST with JSON { inputProps } and response { outputUrl }.
 */
async function callRenderService(inputProps) {
  const url = process.env.RENDER_SERVICE_URL;
  if (!url) return null;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ inputProps }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Render service error ${res.status}: ${text}`);
  }

  const data = await res.json();
  return data.outputUrl || null;
}

/**
 * Process one render job.
 */
async function processRenderJob(job) {
  const { jobId, videoId, workspaceId } = job.data;

  const dbJob = await renderDao.findRenderJobById(jobId);
  if (!dbJob || dbJob.status !== 'PENDING') return;

  await renderDao.updateRenderJob(jobId, { status: 'RENDERING' });

  try {
    const video = await prisma.video.findUnique({
      where: { id: videoId },
      include: { scenes: { orderBy: [{ order: 'asc' }, { startTime: 'asc' }] } },
    });

    if (!video || video.workspaceId !== workspaceId) {
      await renderDao.updateRenderJob(jobId, {
        status: 'FAILED',
        error: 'Video not found or access denied',
      });
      return;
    }

    let outputUrl = null;
    if (process.env.HEYGEN_API_KEY) {
      outputUrl = await renderWithHeyGen(video, video.scenes);
    } else {
      const inputProps = buildInputProps(video, video.scenes);
      outputUrl = await callRenderService(inputProps);
    }

    await renderDao.updateRenderJob(jobId, {
      status: 'COMPLETED',
      outputUrl: outputUrl || null,
      error: null,
    });
  } catch (err) {
    await renderDao.updateRenderJob(jobId, {
      status: 'FAILED',
      error: err.message || String(err),
    });
  }
}

renderQueue.process(async (job) => {
  await processRenderJob(job);
});

renderQueue.on('error', (err) => {
  console.error('Render queue error:', err);
});

renderQueue.on('failed', (job, err) => {
  console.error('Render job failed:', job?.id, err);
  if (job?.data?.jobId) {
    renderDao.updateRenderJob(job.data.jobId, {
      status: 'FAILED',
      error: err.message || String(err),
    }).catch(console.error);
  }
});

console.log('Render worker started. Waiting for jobs...');
