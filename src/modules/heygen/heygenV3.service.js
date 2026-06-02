const { getJson, postJson } = require('../../shared/services/heygenV3.client');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const heygenDao = require('./heygen.dao');

function pickArray(data, keys) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { key: null, list: [] };
  }
  /** Prefer a non-empty array so we do not latch onto an empty stub field before the real list (e.g. `data`). */
  let emptyFallback = null;
  for (const k of keys) {
    const v = data[k];
    if (!Array.isArray(v)) continue;
    if (v.length > 0) return { key: k, list: v };
    if (!emptyFallback) emptyFallback = { key: k, list: v };
  }
  return emptyFallback || { key: null, list: [] };
}

function itemAvatarGroupId(item) {
  if (!item || typeof item !== 'object') return null;
  function groupFields(o) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
    const v =
      o.avatar_group_id ??
      o.group_id ??
      o.avatarGroupId ??
      o.groupId ??
      o.id ??
      null;
    return v != null && String(v).trim() !== '' ? String(v).trim() : null;
  }
  const nested = groupFields(item.avatar_group);
  const direct =
    item.avatar_group_id ??
    item.group_id ??
    item.avatarGroupId ??
    item.groupId;
  if (direct != null && String(direct).trim() !== '') return String(direct).trim();
  if (nested) return nested;
  if (item.id != null && String(item.id).trim() !== '') return String(item.id).trim();
  return null;
}

function itemVoiceId(item) {
  if (!item || typeof item !== 'object') return null;
  const v =
    item.voice_id ??
    item.voiceId ??
    item.voice_clone_id ??
    item.voiceCloneId ??
    item.id ??
    null;
  return v != null && String(v).trim() !== '' ? String(v).trim() : null;
}

/** Unwrap HeyGen-style `{ data: { data: … } }` envelopes (shared by avatar create + voice responses). */
function buildHeyGenDataChain(body, maxDepth = 6) {
  const chain = [];
  if (!body || typeof body !== 'object') return chain;
  let cur = body.data !== undefined && body.data !== null ? body.data : body;
  if (Array.isArray(cur)) return chain;
  for (let i = 0; i < maxDepth && cur && typeof cur === 'object' && !Array.isArray(cur); i++) {
    chain.push(cur);
    const next = cur.data;
    if (next != null && typeof next === 'object' && !Array.isArray(next)) cur = next;
    else break;
  }
  return chain;
}

function filterPrivateListBody(body, allowedSet, getIdFromItem, arrayKeys) {
  if (!body || typeof body !== 'object') return body;
  const hasEnvelope = 'data' in body && body.data != null && typeof body.data === 'object';
  const target = hasEnvelope ? body.data : body;

  let arrayKey;
  let list;
  if (Array.isArray(target)) {
    arrayKey = null;
    list = target;
  } else {
    const picked = pickArray(target, arrayKeys);
    arrayKey = picked.key;
    list = picked.list;
  }

  if (!Array.isArray(list)) return body;

  const filtered = list.filter((item) => {
    const id = getIdFromItem(item);
    return id != null && id !== '' && allowedSet.has(String(id));
  });

  if (Array.isArray(target)) {
    if (hasEnvelope) return { ...body, data: filtered };
    return filtered;
  }

  if (!arrayKey) return body;

  const nextTarget = { ...target, [arrayKey]: filtered };
  if (typeof nextTarget.total === 'number') nextTarget.total = filtered.length;
  if (typeof nextTarget.count === 'number') nextTarget.count = filtered.length;
  if (typeof nextTarget.total_count === 'number') nextTarget.total_count = filtered.length;
  if (hasEnvelope) return { ...body, data: nextTarget };
  return nextTarget;
}

/** Voice ids currently present in list payload (same shape as filterPrivateListBody). */
function extractVoiceIdsFromListBody(body) {
  const ids = new Set();
  if (!body || typeof body !== 'object') return ids;
  const hasEnvelope = 'data' in body && body.data != null && typeof body.data === 'object';
  const target = hasEnvelope ? body.data : body;
  if (Array.isArray(target)) {
    for (const item of target) {
      const id = itemVoiceId(item);
      if (id) ids.add(id);
    }
    return ids;
  }
  const picked = pickArray(target, VOICE_LIST_ARRAY_KEYS);
  if (!Array.isArray(picked.list)) return ids;
  for (const item of picked.list) {
    const id = itemVoiceId(item);
    if (id) ids.add(id);
  }
  return ids;
}

/** Append list rows (e.g. from DB) and fix common pagination fields. */
function appendItemsToVoiceListBody(body, newItems) {
  if (!newItems.length) return body;
  if (!body || typeof body !== 'object') {
    return {
      data: {
        voices: newItems,
        total: newItems.length,
        count: newItems.length,
      },
    };
  }
  const hasEnvelope = 'data' in body && body.data != null && typeof body.data === 'object';
  const target = hasEnvelope ? body.data : body;

  if (Array.isArray(target)) {
    const merged = [...target, ...newItems];
    if (hasEnvelope) return { ...body, data: merged };
    return merged;
  }

  const picked = pickArray(target, VOICE_LIST_ARRAY_KEYS);
  const arrayKey = picked.key || 'voices';
  const existing = Array.isArray(picked.list) ? picked.list : [];
  const merged = [...existing, ...newItems];
  const nextTarget = { ...target, [arrayKey]: merged };
  if (typeof nextTarget.total === 'number') nextTarget.total = merged.length;
  if (typeof nextTarget.count === 'number') nextTarget.count = merged.length;
  if (typeof nextTarget.total_count === 'number') nextTarget.total_count = merged.length;
  if (hasEnvelope) return { ...body, data: nextTarget };
  return nextTarget;
}

function dbRowToVoiceListItem(row) {
  const raw = row.raw;
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    const inner = raw.data !== undefined && raw.data !== null ? raw.data : raw;
    if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
      const id = itemVoiceId(inner) || row.voiceId;
      return { ...inner, voice_id: id, voiceId: id };
    }
  }
  const id = row.voiceId;
  return {
    voice_id: id,
    voiceId: id,
    ...(row.name != null ? { name: row.name } : {}),
    ...(row.language != null ? { language: row.language } : {}),
  };
}

async function augmentPrivateVoiceListFromDb(body, userId, allowedSet) {
  if (!allowedSet || allowedSet.size === 0) return body;
  const present = extractVoiceIdsFromListBody(body);
  const missing = [...allowedSet].filter((id) => !present.has(id));
  if (missing.length === 0) return body;
  const rows = await heygenDao.listHeygenVoicesForUser(userId, missing);
  const missingSet = new Set(missing);
  const items = rows.filter((r) => missingSet.has(r.voiceId)).map(dbRowToVoiceListItem);
  return appendItemsToVoiceListBody(body, items);
}

/**
 * HeyGen create-avatar responses vary: group id may live under nested `data`, `avatar_group`,
 * or camelCase aliases. We unwrap a short `data` chain and prefer explicit group keys before `id`.
 */
function extractAvatarGroupIdFromCreateResponse(body) {
  if (!body || typeof body !== 'object') return null;

  function explicitGroupId(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
    const ag = obj.avatar_group;
    const nested =
      ag && typeof ag === 'object' && !Array.isArray(ag)
        ? ag.avatar_group_id ?? ag.group_id ?? ag.avatarGroupId ?? ag.groupId ?? ag.id
        : null;
    const v =
      obj.avatar_group_id ??
      obj.group_id ??
      obj.avatarGroupId ??
      obj.groupId ??
      nested;
    return v != null && String(v).trim() !== '' ? String(v).trim() : null;
  }

  let chain = buildHeyGenDataChain(body);
  if (chain.length === 0) {
    const fb = body.data !== undefined && body.data !== null ? body.data : body;
    if (fb && typeof fb === 'object' && !Array.isArray(fb)) chain = [fb];
  }

  for (const node of chain) {
    const hit = explicitGroupId(node);
    if (hit) return hit;
  }
  for (const node of chain) {
    if (node.id != null && String(node.id).trim() !== '') return String(node.id).trim();
  }
  return null;
}

/** Same candidate keys as private voice listing so POST clone/design records ids HeyGen nests under `data`, etc. */
const VOICE_LIST_ARRAY_KEYS = [
  'voices',
  'suggestions',
  'voice_list',
  'list',
  'items',
  'results',
  'data',
];

function extractVoiceIdsFromVoiceResponse(body) {
  if (!body || typeof body !== 'object') return [];
  const ids = new Set();

  function addFromItem(item) {
    const id = itemVoiceId(item);
    if (id) ids.add(id);
  }

  function scanNode(node) {
    if (node == null) return;
    if (Array.isArray(node)) {
      node.forEach(addFromItem);
      return;
    }
    if (typeof node !== 'object') return;

    const direct =
      node.voice_id ??
      node.voiceId ??
      node.voice_clone_id ??
      node.voiceCloneId;
    if (direct != null && String(direct).trim() !== '') ids.add(String(direct).trim());

    const vObj = node.voice;
    if (vObj && typeof vObj === 'object' && !Array.isArray(vObj)) addFromItem(vObj);

    const picked = pickArray(node, VOICE_LIST_ARRAY_KEYS);
    if (picked.list && Array.isArray(picked.list)) picked.list.forEach(addFromItem);
  }

  const root = body.data !== undefined && body.data !== null ? body.data : body;
  if (Array.isArray(root)) {
    scanNode(root);
    return [...ids];
  }

  const chain = buildHeyGenDataChain(body);
  const nodes = chain.length > 0 ? chain : root && typeof root === 'object' ? [root] : [];
  for (const node of nodes) scanNode(node);

  return [...ids];
}

async function listAvatarGroups(userId, query) {
  const raw = await getJson('/v3/avatars', query);
  if (query?.ownership !== 'private') return raw;
  const allowed = new Set(await heygenDao.listAvatarGroupIdsForUser(userId));
  return filterPrivateListBody(raw, allowed, itemAvatarGroupId, [
    'avatar_groups',
    'avatar_group_list',
    'avatars',
    'groups',
    'list',
    'items',
    'results',
    'data',
  ]);
}

async function getAvatarLook(lookId) {
  return getJson(`/v3/avatars/looks/${encodeURIComponent(lookId)}`);
}

async function listAvatarLooks(userId, query) {
  if (query?.ownership === 'private' && query.group_id) {
    const owns = await heygenDao.userOwnsAvatarGroup(userId, String(query.group_id));
    if (!owns) {
      throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
    }
  }
  const raw = await getJson('/v3/avatars/looks', query);
  if (query?.ownership !== 'private') return raw;
  const allowed = new Set(await heygenDao.listAvatarGroupIdsForUser(userId));
  return filterPrivateListBody(raw, allowed, itemAvatarGroupId, [
    'looks',
    'avatar_looks',
    'avatars',
    'list',
    'items',
    'results',
    'data',
  ]);
}

async function createAvatar(userId, body) {
  const raw = await postJson('/v3/avatars', body);
  const avatarGroupId = extractAvatarGroupIdFromCreateResponse(raw);
  if (avatarGroupId) {
    const status =
      (raw && typeof raw === 'object' && raw.data && typeof raw.data === 'object' && raw.data.status) ||
      'processing';
    await heygenDao.recordAvatar({
      userId,
      avatarGroupId,
      avatarId: null,
      name: body?.name != null ? String(body.name) : null,
      type: body?.type != null ? String(body.type) : 'unknown',
      status: status != null ? String(status) : 'processing',
      raw,
    });
  }
  return raw;
}

async function createAvatarConsent(userId, groupId, body) {
  const owns = await heygenDao.userOwnsAvatarGroup(userId, groupId);
  if (!owns) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }
  return postJson(`/v3/avatars/${encodeURIComponent(groupId)}/consent`, body || {});
}

async function listVoices(userId, query) {
  const raw = await getJson('/v3/voices', query);
  if (query?.type !== 'private') return raw;
  const allowed = new Set(await heygenDao.listVoiceIdsForUser(userId));
  const filtered = filterPrivateListBody(raw, allowed, itemVoiceId, VOICE_LIST_ARRAY_KEYS);
  return augmentPrivateVoiceListFromDb(filtered, userId, allowed);
}

async function designVoice(_userId, body) {
  const payload = { ...(body || {}) };
  delete payload.voiceId;
  delete payload.voice_id;
  return postJson('/v3/voices', payload);
}

async function cloneVoice(userId, body) {
  const raw = await postJson('/v3/voices/clone', body);
  const voiceIds = extractVoiceIdsFromVoiceResponse(raw);
  const name = body?.voice_name != null ? String(body.voice_name) : null;
  for (const voiceId of voiceIds) {
    await heygenDao.recordVoice({
      userId,
      voiceId,
      name,
      source: 'clone',
      language: body?.language != null ? String(body.language) : null,
      raw,
    });
  }
  const voiceCloneId = voiceIds[0] || null;
  if (voiceCloneId) {
    return {
      voiceCloneId,
      voiceId: voiceCloneId,
      ...raw,
    };
  }
  return raw;
}

async function selectVoice(userId, voiceId) {
  const raw = await getJson(`/v3/voices/${encodeURIComponent(voiceId)}`);
  const data = raw && typeof raw === 'object' && 'data' in raw ? raw.data : raw;
  const name =
    data && typeof data === 'object'
      ? (data.name ?? data.voice_name ?? data.title ?? null)
      : null;
  const language =
    data && typeof data === 'object' ? (data.language ?? data.locale ?? null) : null;

  await heygenDao.recordVoice({
    userId,
    voiceId: String(voiceId),
    name: name != null ? String(name).slice(0, 255) : null,
    source: 'select',
    language: language != null ? String(language).slice(0, 50) : null,
    raw,
  });

  return {
    selected: true,
    voiceId: String(voiceId),
    voice: raw,
  };
}

async function getVoice(userId, voiceId) {
  if (await heygenDao.cloneVoiceOwnedByOtherUser(userId, voiceId)) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }
  return getJson(`/v3/voices/${encodeURIComponent(voiceId)}`);
}

async function generateSpeechPreview(body) {
  return postJson('/v3/voices/speech', body);
}

/** Normalize POST /v3/videos response */
function normalizeCreateVideoResponse(body) {
  const data = body && typeof body === 'object' && 'data' in body ? body.data : body;
  const videoId =
    (data && typeof data === 'object' && (data.video_id ?? data.id)) ?? body?.video_id;
  if (!videoId) {
    throw new AppError(messages.HEYGEN_REQUEST_FAILED, 502);
  }
  const status =
    (data && typeof data === 'object' && data.status) || body?.status || 'processing';
  return { videoId: String(videoId), status: String(status), raw: body };
}

/** Normalize GET /v3/videos/:id response */
function normalizeVideoStatusResponse(body) {
  const data = body && typeof body === 'object' && 'data' in body ? body.data : body;
  const id = (data && typeof data === 'object' && (data.id ?? data.video_id)) ?? body?.video_id;
  const statusRaw =
    (data && typeof data === 'object' && data.status) || body?.status || 'pending';
  const status = String(statusRaw).toLowerCase();
  return {
    id: id ? String(id) : null,
    status,
    video_url:
      data && typeof data === 'object' ? data.video_url ?? null : null,
    thumbnail_url:
      data && typeof data === 'object' ? data.thumbnail_url ?? null : null,
    duration: data && typeof data === 'object' ? data.duration ?? null : null,
    error:
      (data && typeof data === 'object' && data.error) || body?.error || null,
    raw: body,
  };
}

async function createVideo(jsonBody) {
  const raw = await postJson('/v3/videos', jsonBody);
  return { ...normalizeCreateVideoResponse(raw), raw };
}

async function getVideoStatus(videoId) {
  const raw = await getJson(`/v3/videos/${encodeURIComponent(videoId)}`);
  return normalizeVideoStatusResponse(raw);
}

module.exports = {
  listAvatarGroups,
  listAvatarLooks,
  getAvatarLook,
  createAvatar,
  createAvatarConsent,
  listVoices,
  designVoice,
  cloneVoice,
  selectVoice,
  getVoice,
  generateSpeechPreview,
  createVideo,
  getVideoStatus,
};
