const { getJson, getJsonSafe, postJson, deleteJson, deleteJsonSafe } = require('../../shared/services/heygenV3.client');
const { ensureHeygenAssetRef } = require('./heygenAssets.service');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const heygenDao = require('./heygen.dao');
const heygenShareDao = require('./heygenShare.dao');
const heygenAccess = require('./heygenAccess.service');
const { getEffectiveSupportedApiEnginesFromLook, usesHeygenLegacyV2VideoLook, getLookSupportedVideoEngines, enrichLookWithEngineHints } = require('../../shared/constants/heygen');
const {
  enrichVoiceWithSpeechHints,
  enrichVoicesListBodyWithSpeechHints,
  voiceSupportsStarfishSpeech,
  isHeygenStarfishSpeechUnsupportedError,
} = require('../../shared/constants/heygenVoice');

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

const LOOK_LIST_ARRAY_KEYS = [
  'looks',
  'avatar_looks',
  'avatars',
  'list',
  'items',
  'results',
  'data',
];

/**
 * HeyGen often returns looks as a bare array under `data`. Frontends expect `data.looks`.
 */
function coerceLooksArray(value) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const id = value.id ?? value.look_id ?? value.lookId;
    if (id != null && String(id).trim() !== '') return [value];
  }
  return [];
}

function unwrapHeygenLookRecord(body) {
  if (!body || typeof body !== 'object') return null;
  const data = body.data !== undefined && body.data !== null ? body.data : body;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const id = data.id ?? data.look_id ?? data.lookId;
  return id != null && String(id).trim() !== '' ? data : null;
}

function normalizeLooksListBody(body) {
  if (!body || typeof body !== 'object') return body;
  const hasEnvelope = 'data' in body && body.data != null;
  const envelopeExtras = hasEnvelope
    ? Object.fromEntries(Object.entries(body).filter(([k]) => k !== 'data'))
    : {};
  const target = hasEnvelope ? body.data : body;

  if (Array.isArray(target)) {
    return { ...envelopeExtras, data: { looks: target } };
  }

  if (!target || typeof target !== 'object') return body;

  const picked = pickArray(target, LOOK_LIST_ARRAY_KEYS);
  let looks = coerceLooksArray(target.looks);
  if (looks.length === 0) looks = coerceLooksArray(picked.list);
  if (looks.length === 0) looks = coerceLooksArray(target);

  const nextTarget = { ...target, looks };
  if (typeof nextTarget.total === 'number') nextTarget.total = looks.length;
  if (typeof nextTarget.count === 'number') nextTarget.count = looks.length;
  if (typeof nextTarget.total_count === 'number') nextTarget.total_count = looks.length;

  return hasEnvelope ? { ...body, data: nextTarget } : { data: nextTarget };
}

function enrichLooksListMetadata(body) {
  const normalized = normalizeLooksListBody(body);
  if (!normalized?.data || typeof normalized.data !== 'object' || Array.isArray(normalized.data)) {
    return normalized;
  }
  const looks = coerceLooksArray(normalized.data.looks);
  const lookCount = looks.length;
  const defaultLookId = lookCount > 0 ? String(looks[0].id ?? looks[0].look_id ?? '') : null;
  const expectedLookCount = normalized.data.expectedLookCount;
  const isSingleLookGroup =
    lookCount === 1 || expectedLookCount === 1 || normalized.data.isSingleLookGroup === true;
  return {
    ...normalized,
    data: {
      ...normalized.data,
      looks,
      lookCount,
      hasMultipleLooks: lookCount > 1,
      isSingleLookGroup,
      ...(defaultLookId ? { defaultLookId } : {}),
    },
  };
}

const GROUP_LIST_ARRAY_KEYS = [
  'avatar_groups',
  'avatar_group_list',
  'avatars',
  'groups',
  'list',
  'items',
  'results',
  'data',
];

/** Flag avatar groups with exactly one look so the UI can auto-select instead of showing an empty picker. */
function enrichAvatarGroupsListBody(body) {
  if (!body || typeof body !== 'object') return body;
  const hasEnvelope = 'data' in body && body.data != null;
  const target = hasEnvelope ? body.data : body;

  function enrichGroup(group) {
    if (!group || typeof group !== 'object' || Array.isArray(group)) return group;
    if (typeof group.looks_count === 'number' && group.looks_count === 1) {
      return { ...group, isSingleLookGroup: true };
    }
    return group;
  }

  if (Array.isArray(target)) {
    const next = target.map(enrichGroup);
    return hasEnvelope ? { ...body, data: next } : next;
  }

  if (target && typeof target === 'object') {
    const picked = pickArray(target, GROUP_LIST_ARRAY_KEYS);
    if (!picked.key || !Array.isArray(picked.list)) return body;
    const nextTarget = { ...target, [picked.key]: picked.list.map(enrichGroup) };
    return hasEnvelope ? { ...body, data: nextTarget } : nextTarget;
  }

  return body;
}

async function resolveOwnedAvatarGroupId(userId, groupOrLookId) {
  const id = String(groupOrLookId).trim();
  if (!id) return null;
  if (await heygenDao.userOwnsAvatarGroup(userId, id)) return id;

  try {
    const single = await getAvatarLook(id);
    const look = unwrapHeygenLookRecord(single);
    const groupId = look ? itemAvatarGroupId(look) : null;
    if (groupId && (await heygenDao.userOwnsAvatarGroup(userId, groupId))) {
      return groupId;
    }
  } catch {
    // not a look id — fall through
  }
  return null;
}

async function assertCanAccessLooksQuery(userId, query) {
  if (query?.ownership !== 'private' || !query.group_id) return;

  const workspaceId = heygenAccess.normalizeWorkspaceId(query.workspace_id);
  if (workspaceId) {
    const accessible = await heygenAccess.resolveAccessibleAvatarGroupId(
      userId,
      workspaceId,
      query.group_id
    );
    if (!accessible) {
      throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
    }
    return;
  }

  const ownedGroupId = await resolveOwnedAvatarGroupId(userId, query.group_id);
  if (!ownedGroupId) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }
}

async function fetchLooksListFallbackByLookId(groupOrLookId) {
  const id = String(groupOrLookId).trim();
  if (!id) return null;
  try {
    const single = await getAvatarLook(id);
    const look = unwrapHeygenLookRecord(single);
    return look ? [look] : null;
  } catch {
    return null;
  }
}

function slugifyAvatarGroupName(name) {
  return String(name || '')
    .trim()
    .replace(/\s+/g, '_');
}

async function addResolvedLookToList(looks, seen, lookId, groupId) {
  const id = String(lookId || '').trim();
  if (!id || seen.has(id)) return;
  try {
    const single = await getAvatarLook(id);
    const look = unwrapHeygenLookRecord(single);
    if (!look) return;
    const gid = itemAvatarGroupId(look);
    if (groupId && gid && gid !== groupId) return;
    seen.add(id);
    looks.push(look);
  } catch {
    // look id not found — skip
  }
}

async function collectV2AvatarLookCandidates(groupName, groupId, looks, seen) {
  const slug = slugifyAvatarGroupName(groupName);
  if (!slug) return;
  const safe = await getJsonSafe('/v2/avatars');
  if (!safe.ok) return;
  const avatars = safe.body?.data?.avatars;
  if (!Array.isArray(avatars)) return;
  const prefix = `${slug}_`;
  const candidates = avatars.filter((a) => {
    const id = String(a.avatar_id || '');
    return id === slug || id === `${slug}_public` || id.startsWith(prefix) || a.avatar_name === groupName;
  });
  for (const a of candidates) {
    await addResolvedLookToList(looks, seen, a.avatar_id, groupId);
  }
}

/**
 * HeyGen sometimes returns 400 for GET /v3/avatars/looks?group_id=… (bad created_at on a row).
 * Recover individual looks via GET /v3/avatars/looks/{id} and the legacy v2 avatar catalog.
 */
async function fetchLooksListFallbackForGroup(groupId, query) {
  const safeGroup = await getJsonSafe(`/v3/avatars/${encodeURIComponent(groupId)}`);
  if (!safeGroup.ok) return null;
  const group = safeGroup.body?.data;
  const groupName = group?.name != null ? String(group.name).trim() : '';
  const looks = [];
  const seen = new Set();

  const slug = slugifyAvatarGroupName(groupName);
  if (slug) {
    await addResolvedLookToList(looks, seen, `${slug}_public`, groupId);
    await addResolvedLookToList(looks, seen, slug, groupId);
  }

  if (looks.length === 0 && groupName) {
    await collectV2AvatarLookCandidates(groupName, groupId, looks, seen);
  }

  let filtered = looks;
  if (query?.avatar_type) {
    const typed = looks.filter((look) => String(look.avatar_type || '') === query.avatar_type);
    if (typed.length > 0) filtered = typed;
  }
  if (filtered.length === 0) return null;

  const expected =
    typeof group?.looks_count === 'number' && group.looks_count > 0 ? group.looks_count : null;
  const listIncomplete = expected != null && filtered.length < expected;
  const isSingleLookGroup = expected === 1 || filtered.length === 1;

  return {
    data: {
      looks: filtered,
      lookCount: filtered.length,
      hasMultipleLooks: filtered.length > 1,
      isSingleLookGroup,
      defaultLookId: String(filtered[0].id ?? filtered[0].look_id ?? ''),
      ...(expected != null ? { expectedLookCount: expected } : {}),
      ...(listIncomplete
        ? {
            listDegraded: true,
            heygenListUnavailable: true,
          }
        : {}),
    },
  };
}

/**
 * Recover looks when HeyGen list is empty/400 — common for single-look avatars when:
 * - the UI passes a look id as group_id
 * - avatar_type filter hides the only row (e.g. digital_twin with studio_avatar filter)
 * - HeyGen list endpoint is broken for the group
 */
async function recoverLooksListForGroup(groupOrLookId, heygenQuery) {
  const byLookId = await fetchLooksListFallbackByLookId(groupOrLookId);
  if (byLookId?.length) {
    return { data: byLookId };
  }

  if (heygenQuery?.avatar_type) {
    const relaxed = { ...heygenQuery };
    delete relaxed.avatar_type;
    try {
      const raw = await getJson('/v3/avatars/looks', relaxed);
      const looks = coerceLooksArray(enrichLooksListMetadata(raw)?.data?.looks);
      if (looks.length > 0) {
        return { data: looks };
      }
    } catch {
      // continue to slug/v2 fallback
    }
  }

  return fetchLooksListFallbackForGroup(groupOrLookId, heygenQuery);
}

async function finalizeLooksListResponse(userId, query, body) {
  let next = body;
  if (query?.ownership === 'private') {
    const workspaceId = heygenAccess.normalizeWorkspaceId(query.workspace_id);
    const { allowed, sharedMetaByGroupId } = await heygenAccess.buildAllowedAvatarGroupContext(
      userId,
      workspaceId
    );
    next = filterPrivateListBody(next, allowed, itemAvatarGroupId, LOOK_LIST_ARRAY_KEYS);
    next = annotateSharedResourceItems(
      next,
      itemAvatarGroupId,
      sharedMetaByGroupId,
      LOOK_LIST_ARRAY_KEYS
    );
  }
  return appendLookEngineBuckets(enrichLooksListMetadata(next));
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

function annotateSharedResourceItems(body, getResourceId, sharedMetaMap, arrayKeys) {
  if (!body || typeof body !== 'object' || !sharedMetaMap || sharedMetaMap.size === 0) {
    return body;
  }

  const hasEnvelope = 'data' in body && body.data != null && typeof body.data === 'object';
  const target = hasEnvelope ? body.data : body;

  function annotateItem(item) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
    const resourceId = getResourceId(item);
    if (!resourceId) return item;
    const meta = sharedMetaMap.get(String(resourceId));
    if (!meta) return item;
    return {
      ...item,
      shared: true,
      sharedByUserId: meta.sharedByUserId,
    };
  }

  if (Array.isArray(target)) {
    const next = target.map(annotateItem);
    return hasEnvelope ? { ...body, data: next } : next;
  }

  const picked = pickArray(target, arrayKeys);
  if (!picked.key || !Array.isArray(picked.list)) return body;
  const nextTarget = { ...target, [picked.key]: picked.list.map(annotateItem) };
  return hasEnvelope ? { ...body, data: nextTarget } : nextTarget;
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
      return enrichVoiceWithSpeechHints({
        ...inner,
        voice_id: id,
        voiceId: id,
        ...(row.source === 'clone' ? { type: inner.type || 'private' } : {}),
      });
    }
  }
  const id = row.voiceId;
  return enrichVoiceWithSpeechHints({
    voice_id: id,
    voiceId: id,
    ...(row.name != null ? { name: row.name } : {}),
    ...(row.language != null ? { language: row.language } : {}),
    ...(row.source === 'clone' ? { type: 'private' } : {}),
  });
}

async function augmentPrivateVoiceListFromDb(body, userId, allowedSet, sharedMetaByVoiceId = null) {
  if (!allowedSet || allowedSet.size === 0) return body;
  const present = extractVoiceIdsFromListBody(body);
  const missing = [...allowedSet].filter((id) => !present.has(id));
  if (missing.length === 0) {
    return annotateSharedResourceItems(body, itemVoiceId, sharedMetaByVoiceId, VOICE_LIST_ARRAY_KEYS);
  }

  const ownMissing = [];
  const sharedMissing = [];
  for (const voiceId of missing) {
    if (sharedMetaByVoiceId && sharedMetaByVoiceId.has(voiceId)) {
      sharedMissing.push(voiceId);
    } else {
      ownMissing.push(voiceId);
    }
  }

  const ownRows = ownMissing.length
    ? await heygenDao.listHeygenVoicesForUser(userId, ownMissing)
    : [];
  const sharedRows = sharedMissing.length
    ? await heygenDao.listHeygenVoicesByVoiceIds(sharedMissing)
    : [];

  const ownSet = new Set(ownMissing);
  const sharedSet = new Set(sharedMissing);
  const items = [
    ...ownRows.filter((row) => ownSet.has(row.voiceId)),
    ...sharedRows.filter((row) => sharedSet.has(row.voiceId)),
  ].map(dbRowToVoiceListItem);

  const merged = appendItemsToVoiceListBody(body, items);
  return annotateSharedResourceItems(merged, itemVoiceId, sharedMetaByVoiceId, VOICE_LIST_ARRAY_KEYS);
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

/**
 * Adds backend-friendly engine buckets without breaking existing HeyGen payload shape.
 * Looks supporting both engines appear in both buckets.
 */
function appendLookEngineBuckets(body) {
  if (!body || typeof body !== 'object') return body;

  const hasEnvelope = 'data' in body && body.data != null && typeof body.data === 'object';
  const target = hasEnvelope ? body.data : body;
  if (!target || typeof target !== 'object' || Array.isArray(target)) return body;

  const picked = pickArray(target, LOOK_LIST_ARRAY_KEYS);
  const looks = Array.isArray(target.looks)
    ? target.looks
    : Array.isArray(picked.list)
      ? picked.list
      : [];
  const enrichedLooks = looks.map(enrichLookWithEngineHints);

  const engineBuckets = {
    avatar_iv: [],
    avatar_v: [],
    legacy_v2: [],
    unknown: [],
  };

  for (const look of enrichedLooks) {
    if (look.usesLegacyV2Video || look.videoApi === 'v2' || usesHeygenLegacyV2VideoLook(look)) {
      engineBuckets.legacy_v2.push(look);
      continue;
    }

    const engines = Array.isArray(look.supportedApiEngines)
      ? look.supportedApiEngines
      : getLookSupportedVideoEngines(look);
    const hasIv = engines.includes('avatar_iv');
    const hasV = engines.includes('avatar_v');

    if (hasIv) engineBuckets.avatar_iv.push(look);
    if (hasV) engineBuckets.avatar_v.push(look);
    if (!hasIv && !hasV) engineBuckets.unknown.push(look);
  }

  const nextTarget = {
    ...target,
    looks: enrichedLooks,
    engineBuckets,
    engineCounts: {
      avatar_iv: engineBuckets.avatar_iv.length,
      avatar_v: engineBuckets.avatar_v.length,
      legacy_v2: engineBuckets.legacy_v2.length,
      unknown: engineBuckets.unknown.length,
      totalLooks: enrichedLooks.length,
    },
  };

  if (hasEnvelope) return { ...body, data: nextTarget };
  return nextTarget;
}

async function listAvatarGroups(userId, query) {
  const raw = await getJson('/v3/avatars', query);
  let body = raw;
  if (query?.ownership === 'private') {
    const workspaceId = heygenAccess.normalizeWorkspaceId(query.workspace_id);
    const { allowed, sharedMetaByGroupId } = await heygenAccess.buildAllowedAvatarGroupContext(
      userId,
      workspaceId
    );
    body = filterPrivateListBody(raw, allowed, itemAvatarGroupId, GROUP_LIST_ARRAY_KEYS);
    body = annotateSharedResourceItems(
      body,
      itemAvatarGroupId,
      sharedMetaByGroupId,
      GROUP_LIST_ARRAY_KEYS
    );
  }
  return enrichAvatarGroupsListBody(body);
}

async function getAvatarLook(lookId) {
  return getJson(`/v3/avatars/looks/${encodeURIComponent(lookId)}`);
}

async function listAvatarLooks(userId, query) {
  await assertCanAccessLooksQuery(userId, query);

  const groupOrLookId =
    query?.group_id != null && String(query.group_id).trim() !== ''
      ? String(query.group_id).trim()
      : null;

  let heygenQuery = query;
  if (query?.ownership === 'private' && groupOrLookId) {
    const workspaceId = heygenAccess.normalizeWorkspaceId(query.workspace_id);
    const accessibleGroupId = workspaceId
      ? await heygenAccess.resolveAccessibleAvatarGroupId(userId, workspaceId, groupOrLookId)
      : await resolveOwnedAvatarGroupId(userId, groupOrLookId);
    if (accessibleGroupId && accessibleGroupId !== groupOrLookId) {
      heygenQuery = { ...query, group_id: accessibleGroupId };
    }
  }

  let raw;
  try {
    raw = await getJson('/v3/avatars/looks', heygenQuery);
  } catch (err) {
    if (groupOrLookId && err.statusCode === 400) {
      const recovered = await recoverLooksListForGroup(groupOrLookId, heygenQuery);
      if (recovered) return finalizeLooksListResponse(userId, query, recovered);
    }
    throw err;
  }

  const looks = coerceLooksArray(enrichLooksListMetadata(raw)?.data?.looks);
  if (looks.length === 0 && groupOrLookId) {
    const recovered = await recoverLooksListForGroup(groupOrLookId, heygenQuery);
    if (recovered) return finalizeLooksListResponse(userId, query, recovered);
  }

  return finalizeLooksListResponse(userId, query, raw);
}

async function createAvatar(userId, body) {
  const payload = { ...(body || {}) };
  if (payload.file) {
    payload.file = await ensureHeygenAssetRef(payload.file);
  }
  const raw = await postJson('/v3/avatars', payload);
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

function parseExplicitVoiceIds(explicitVoiceIds) {
  if (!explicitVoiceIds) return [];
  const raw = Array.isArray(explicitVoiceIds) ? explicitVoiceIds.join(',') : String(explicitVoiceIds);
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

async function assertUserOwnsAvatarGroup(userId, groupId) {
  const owns = await heygenDao.userOwnsAvatarGroup(userId, groupId);
  if (!owns) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }
}

async function cleanupLocalAvatarGroup(userId, groupId) {
  await heygenDao.deleteAvatarRecord(userId, groupId);
  await heygenShareDao.deleteAllAvatarSharesForGroup(groupId);
}

async function cleanupLocalVoice(userId, voiceId) {
  await heygenDao.deleteVoiceRecord(userId, voiceId);
  await heygenShareDao.deleteAllVoiceSharesForVoice(voiceId);
}

async function deleteVoiceOnHeygenSafe(voiceId) {
  if (!voiceId) return;
  await deleteJsonSafe(`/v3/voices/${encodeURIComponent(voiceId)}`);
}

async function resolvePairedVoiceIdsForGroupDelete(userId, groupId, explicitVoiceIds = []) {
  let defaultVoiceId = null;
  try {
    const raw = await getJson(`/v3/avatars/${encodeURIComponent(groupId)}`);
    const data = raw && typeof raw === 'object' && 'data' in raw ? raw.data : raw;
    const dv =
      data && typeof data === 'object'
        ? data.default_voice_id ?? data.defaultVoiceId ?? null
        : null;
    if (dv != null && String(dv).trim() !== '') {
      defaultVoiceId = String(dv).trim();
    }
  } catch {
    // Group may already be removed upstream during look-delete cascade.
  }

  const candidates = new Set(parseExplicitVoiceIds(explicitVoiceIds));
  if (defaultVoiceId) candidates.add(defaultVoiceId);

  const result = [];
  for (const id of candidates) {
    if (!(await heygenDao.userOwnsVoice(userId, id))) continue;
    const row = await heygenDao.getVoiceRecord(userId, id);
    if (!row) continue;
    if (row.source === 'clone' || id === defaultVoiceId) {
      result.push(id);
    }
  }
  return result;
}

async function deleteAvatarGroup(userId, groupId, options = {}) {
  const normalizedGroupId = String(groupId || '').trim();
  if (!normalizedGroupId) {
    throw new AppError('groupId is required', 400);
  }
  await assertUserOwnsAvatarGroup(userId, normalizedGroupId);

  const explicitVoiceIds = parseExplicitVoiceIds(options.voiceIds);
  const pairedVoiceIds = await resolvePairedVoiceIdsForGroupDelete(
    userId,
    normalizedGroupId,
    explicitVoiceIds
  );

  const heygen = await deleteJsonSafe(`/v3/avatars/${encodeURIComponent(normalizedGroupId)}`);

  const deletedVoiceIds = [];
  for (const voiceId of pairedVoiceIds) {
    await deleteVoiceOnHeygenSafe(voiceId);
    await cleanupLocalVoice(userId, voiceId);
    deletedVoiceIds.push(voiceId);
  }

  await cleanupLocalAvatarGroup(userId, normalizedGroupId);

  return {
    avatarGroupId: normalizedGroupId,
    deletedVoiceIds,
    heygen,
  };
}

function looksListIsEmpty(raw) {
  if (!raw || typeof raw !== 'object') return true;
  const data = raw.data !== undefined ? raw.data : raw;
  const looks = coerceLooksArray(
    Array.isArray(data) ? data : data && typeof data === 'object' ? data.looks : null
  );
  return looks.length === 0;
}

async function deleteAvatarLook(userId, lookId, options = {}) {
  const normalizedLookId = String(lookId || '').trim();
  if (!normalizedLookId) {
    throw new AppError('lookId is required', 400);
  }

  const groupId = await heygenAccess.resolveAvatarGroupIdFromLook(normalizedLookId);
  if (!groupId) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }
  await assertUserOwnsAvatarGroup(userId, groupId);

  const heygenLook = await deleteJson(
    `/v3/avatars/looks/${encodeURIComponent(normalizedLookId)}`
  );

  let remainingLooks;
  try {
    remainingLooks = await getJson('/v3/avatars/looks', { group_id: groupId, limit: 1 });
  } catch {
    remainingLooks = null;
  }

  if (looksListIsEmpty(remainingLooks)) {
    const cascade = await deleteAvatarGroup(userId, groupId, {
      voiceIds: options.voiceIds,
    });
    return {
      lookId: normalizedLookId,
      groupId,
      cascadedGroupDelete: true,
      deletedVoiceIds: cascade.deletedVoiceIds,
      heygen: heygenLook,
      cascade,
    };
  }

  return {
    lookId: normalizedLookId,
    groupId,
    cascadedGroupDelete: false,
    deletedVoiceIds: [],
    heygen: heygenLook,
  };
}

async function deleteVoice(userId, voiceId) {
  const normalizedVoiceId = String(voiceId || '').trim();
  if (!normalizedVoiceId) {
    throw new AppError('voiceId is required', 400);
  }

  const row = await heygenDao.getVoiceRecord(userId, normalizedVoiceId);
  if (!row) {
    throw new AppError(messages.HEYGEN_FORBIDDEN, 403);
  }
  if (row.source !== 'clone') {
    throw new AppError(messages.HEYGEN_VOICE_DELETE_NOT_CLONE, 400);
  }

  await deleteVoiceOnHeygenSafe(normalizedVoiceId);
  await cleanupLocalVoice(userId, normalizedVoiceId);

  return {
    voiceId: normalizedVoiceId,
    deleted: true,
  };
}

async function listVoices(userId, query) {
  const raw = await getJson('/v3/voices', query);
  let next = enrichVoicesListBodyWithSpeechHints(raw);
  if (query?.type !== 'private') return next;
  const workspaceId = heygenAccess.normalizeWorkspaceId(query.workspace_id);
  const { allowed, sharedMetaByVoiceId } = await heygenAccess.buildAllowedVoiceContext(
    userId,
    workspaceId
  );
  const filtered = filterPrivateListBody(next, allowed, itemVoiceId, VOICE_LIST_ARRAY_KEYS);
  return enrichVoicesListBodyWithSpeechHints(
    await augmentPrivateVoiceListFromDb(filtered, userId, allowed, sharedMetaByVoiceId)
  );
}

async function designVoice(_userId, body) {
  const payload = { ...(body || {}) };
  delete payload.voiceId;
  delete payload.voice_id;
  return postJson('/v3/voices', payload);
}

async function cloneVoice(userId, body) {
  const payload = { ...(body || {}) };
  if (payload.audio) {
    payload.audio = await ensureHeygenAssetRef(payload.audio);
  }
  const raw = await postJson('/v3/voices/clone', payload);
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
  const raw = await getJson(`/v3/voices/${encodeURIComponent(voiceId)}`);
  const hasEnvelope = raw && typeof raw === 'object' && 'data' in raw && raw.data != null;
  const inner = hasEnvelope ? raw.data : raw;
  if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
    const enriched = enrichVoiceWithSpeechHints(inner);
    return hasEnvelope ? { ...raw, data: enriched } : enriched;
  }
  return raw;
}

async function assertVoiceSupportsStarfishSpeech(voiceId) {
  const normalizedVoiceId = String(voiceId || '').trim();
  if (!normalizedVoiceId) {
    throw new AppError('voice_id is required', 400);
  }

  const raw = await getJson(`/v3/voices/${encodeURIComponent(normalizedVoiceId)}`);
  const voice = unwrapHeygenData(raw);
  if (!voiceSupportsStarfishSpeech(voice)) {
    throw new AppError(messages.HEYGEN_VOICE_SPEECH_PREVIEW_UNSUPPORTED, 400);
  }
}

async function generateSpeechPreview(body) {
  try {
    return await postJson('/v3/voices/speech', body);
  } catch (err) {
    if (
      err instanceof AppError &&
      err.statusCode === 400 &&
      isHeygenStarfishSpeechUnsupportedError(err.message)
    ) {
      throw new AppError(messages.HEYGEN_VOICE_SPEECH_PREVIEW_UNSUPPORTED, 400);
    }
    throw err;
  }
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

function unwrapHeygenData(body) {
  if (body && typeof body === 'object' && 'data' in body && body.data != null) {
    return body.data;
  }
  return body;
}

function normalizeWalletBilling(wallet) {
  if (!wallet || typeof wallet !== 'object') return null;
  const remaining = wallet.remaining_balance ?? wallet.remainingBalance;
  return {
    currency: wallet.currency ?? 'usd',
    remainingBalanceUsd: remaining != null ? Number(remaining) : null,
    autoReload: wallet.auto_reload ?? wallet.autoReload ?? null,
  };
}

function normalizeSubscriptionBilling(subscription) {
  if (!subscription || typeof subscription !== 'object') return null;
  const credits = subscription.credits && typeof subscription.credits === 'object'
    ? subscription.credits
    : {};
  function mapCreditPool(pool) {
    if (!pool || typeof pool !== 'object') return null;
    return {
      remaining: pool.remaining != null ? Number(pool.remaining) : null,
      resetsAt: pool.resets_at ?? pool.resetsAt ?? null,
    };
  }
  return {
    plan: subscription.plan ?? null,
    credits: {
      premiumCredits: mapCreditPool(credits.premium_credits ?? credits.premiumCredits),
      addOnCredits: mapCreditPool(credits.add_on_credits ?? credits.addOnCredits),
    },
  };
}

function normalizeUsageBasedBilling(usageBased) {
  if (!usageBased || typeof usageBased !== 'object') return null;
  return {
    currentSpendUsd:
      usageBased.current_spend != null
        ? Number(usageBased.current_spend)
        : usageBased.currentSpend != null
          ? Number(usageBased.currentSpend)
          : null,
    spendingCapUsd:
      usageBased.spending_cap != null
        ? Number(usageBased.spending_cap)
        : usageBased.spendingCap != null
          ? Number(usageBased.spendingCap)
          : null,
  };
}

/**
 * GET /v3/users/me — API key billing (wallet USD) or OAuth (subscription / usage_based).
 */
async function getAccountBillingInfo() {
  const raw = await getJson('/v3/users/me');
  const data = unwrapHeygenData(raw);
  if (!data || typeof data !== 'object') {
    throw new AppError(messages.HEYGEN_REQUEST_FAILED, 502);
  }

  const billingType = data.billing_type ?? data.billingType ?? null;

  return {
    username: data.username ?? null,
    email: data.email ?? null,
    firstName: data.first_name ?? data.firstName ?? null,
    lastName: data.last_name ?? data.lastName ?? null,
    billingType,
    wallet: normalizeWalletBilling(data.wallet),
    subscription: normalizeSubscriptionBilling(data.subscription),
    usageBased: normalizeUsageBasedBilling(data.usage_based ?? data.usageBased),
    fetchedAt: new Date().toISOString(),
  };
}

async function createVideo(jsonBody) {
  const raw = await postJson('/v3/videos', jsonBody);
  return { ...normalizeCreateVideoResponse(raw), raw, apiVersion: 'v3' };
}

async function createVideoV2(jsonBody) {
  const raw = await postJson('/v2/video/generate', jsonBody);
  return { ...normalizeCreateVideoResponse(raw), raw, apiVersion: 'v2' };
}

async function getVideoStatus(videoId) {
  const raw = await getJson(`/v3/videos/${encodeURIComponent(videoId)}`);
  return normalizeVideoStatusResponse(raw);
}

module.exports = {
  extractAvatarGroupIdFromCreateResponse,
  listAvatarGroups,
  listAvatarLooks,
  getAvatarLook,
  createAvatar,
  createAvatarConsent,
  deleteAvatarGroup,
  deleteAvatarLook,
  deleteVoice,
  listVoices,
  designVoice,
  cloneVoice,
  selectVoice,
  getVoice,
  assertVoiceSupportsStarfishSpeech,
  generateSpeechPreview,
  getAccountBillingInfo,
  createVideo,
  createVideoV2,
  getVideoStatus,
};
