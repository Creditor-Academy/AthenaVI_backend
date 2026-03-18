/**
 * HeyGen API v2 service.
 * - Create: POST /v2/video/generate (video_inputs, title, dimension)
 * - Status: GET /v1/video_status.get?video_id=...
 * Uses HEYGEN_API_KEY env var.
 */

const HEYGEN_BASE = 'https://api.heygen.com';

function getHeaders() {
  const apiKey = process.env.HEYGEN_API_KEY;
  if (!apiKey) throw new Error('HEYGEN_API_KEY is not set');
  return {
    'Content-Type': 'application/json',
    'x-api-key': apiKey,
  };
}

/**
 * Create an avatar video (one call per video).
 * @param {object} payload - { video_inputs, title?, dimension? }
 *   video_inputs: array of { character: { type, avatar_id }, voice: { type: 'text', voice_id, input_text }, background?: { type, value? } }
 * @returns {Promise<{ video_id: string }>}
 */
async function createVideo(payload) {
  const res = await fetch(`${HEYGEN_BASE}/v2/video/generate`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify(payload),
  });

  const data = await res.json();

  if (!res.ok) {
    const msg = data?.error?.message || data?.error || res.statusText;
    throw new Error(`HeyGen createVideo failed: ${msg}`);
  }

  if (data.error) {
    throw new Error(`HeyGen createVideo error: ${data.error}`);
  }

  const videoId = data?.data?.video_id;
  if (!videoId) throw new Error('HeyGen createVideo: no video_id in response');
  return { video_id: videoId };
}

/**
 * Get video generation status and details.
 * @param {string} videoId - HeyGen video_id
 * @returns {Promise<{ status: string, video_url?: string, error?: object }>}
 */
async function getVideoStatus(videoId) {
  const url = new URL(`${HEYGEN_BASE}/v1/video_status.get`);
  url.searchParams.set('video_id', videoId);

  const res = await fetch(url.toString(), {
    method: 'GET',
    headers: getHeaders(),
  });

  const body = await res.json();

  if (!res.ok) {
    const msg = body?.message || body?.error || res.statusText;
    throw new Error(`HeyGen getVideoStatus failed: ${msg}`);
  }

  const d = body?.data;
  if (!d) throw new Error('HeyGen getVideoStatus: no data in response');

  return {
    status: d.status || 'unknown',
    video_url: d.video_url || null,
    error: d.error || null,
  };
}

/**
 * Get output URL when video is completed. Calls getVideoStatus and returns video_url if status is 'completed'.
 * @param {string} videoId - HeyGen video_id
 * @returns {Promise<string|null>} - video_url or null if not completed
 */
async function getVideoUrl(videoId) {
  const { status, video_url } = await getVideoStatus(videoId);
  return status === 'completed' ? video_url || null : null;
}

module.exports = {
  createVideo,
  getVideoStatus,
  getVideoUrl,
};
