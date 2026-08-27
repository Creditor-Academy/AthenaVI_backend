/**
 * GetIllustrations API client (https://getillustrations.com/api/v1/plugin).
 * Free tier: clean free packs only; cache aggressively (1,500 calls/mo).
 */

const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const GI_BASE = 'https://getillustrations.com/api/v1/plugin';
const FETCH_TIMEOUT_MS = 15000;
const CACHE_TTL_MS = 60 * 60 * 1000; // 1h — free catalog is stable

/** @type {Map<string, { expires: number, value: any }>} */
const cache = new Map();

/** @type {{ limit: number|null, remaining: number|null, reset: string|null, tier: string|null }} */
let lastRateLimit = { limit: null, remaining: null, reset: null, tier: null };

function isConfigured() {
  const key = process.env.GETILLUSTRATIONS_API_KEY;
  return Boolean(key && String(key).trim());
}

function getApiKey() {
  const key = process.env.GETILLUSTRATIONS_API_KEY;
  if (!key || !String(key).trim()) {
    throw new AppError(messages.GETILLUSTRATIONS_NOT_CONFIGURED, 503);
  }
  return String(key).trim();
}

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return undefined;
  if (Date.now() > hit.expires) {
    cache.delete(key);
    return undefined;
  }
  return hit.value;
}

function cacheSet(key, value) {
  cache.set(key, { expires: Date.now() + CACHE_TTL_MS, value });
}

function buildQuery(params) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === '') continue;
    qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `?${s}` : '';
}

function readRateLimit(res) {
  lastRateLimit = {
    limit: Number(res.headers.get('x-ratelimit-limit')) || lastRateLimit.limit,
    remaining:
      res.headers.get('x-ratelimit-remaining') != null
        ? Number(res.headers.get('x-ratelimit-remaining'))
        : lastRateLimit.remaining,
    reset: res.headers.get('x-ratelimit-reset') || lastRateLimit.reset,
    tier: res.headers.get('x-api-tier') || lastRateLimit.tier,
  };
}

function getRateLimit() {
  return { ...lastRateLimit };
}

async function giFetch(pathname, searchParams) {
  const url = `${GI_BASE}${pathname}${buildQuery(searchParams)}`;
  const cached = cacheGet(url);
  if (cached !== undefined) return cached;

  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${getApiKey()}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new AppError(messages.GETILLUSTRATIONS_REQUEST_FAILED, 502);
  }

  readRateLimit(res);

  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }

  if (!res.ok) {
    const msg =
      (body && (body.error || body.message)) ||
      res.statusText ||
      messages.GETILLUSTRATIONS_REQUEST_FAILED;
    const status = res.status === 429 ? 429 : res.status >= 400 && res.status < 600 ? res.status : 502;
    throw new AppError(String(msg), status);
  }

  cacheSet(url, body);
  return body;
}

async function listAllPages(fetchPage) {
  const all = [];
  let page = 1;
  let totalPages = 1;
  while (page <= totalPages && page <= 40) {
    const data = await fetchPage(page);
    const items = Array.isArray(data?.items) ? data.items : [];
    all.push(...items);
    totalPages = Number(data?.totalPages) || 1;
    if (!items.length) break;
    page += 1;
  }
  return all;
}

function normalizePack(raw) {
  if (!raw) return null;
  return {
    id: String(raw.id),
    strId: raw.strId || raw.urlName || null,
    name: raw.name || 'Untitled pack',
    urlName: raw.urlName || null,
    isFree: Boolean(raw.isFree),
    hasAccess: Boolean(raw.hasAccess),
    thumbnail: raw.thumbnail || raw.heroPhoto || null,
    itemsCount: Number(raw.itemsCount || raw.illustrationCount || raw.iconCount || 0) || 0,
    svgAvailable: Boolean(raw.svgAvailable),
    style: raw.style
      ? { id: String(raw.style.id), name: raw.style.name || '' }
      : null,
    shortDescription: raw.shortDescription || '',
  };
}

function normalizeIllustration(raw, pack) {
  if (!raw) return null;
  const tags = String(raw.tags || '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  const nameFromTags = tags.slice(0, 3).join(', ') || `Illustration ${raw.id}`;
  return {
    id: String(raw.id),
    kind: 'illustration',
    name: nameFromTags,
    tags,
    categoryId: raw.categoryId != null ? String(raw.categoryId) : null,
    packId: String(raw.packId || pack?.id || ''),
    packName: pack?.name || raw.pack?.name || '',
    imageUrl: raw.imageUrl || null,
    thumbnailUrl: raw.thumbnailUrl || raw.imageUrl || null,
    svgAvailable: Boolean(raw.svgAvailable),
    hasAccess: raw.hasAccess != null ? Boolean(raw.hasAccess) : Boolean(raw.purchased || pack?.hasAccess),
    downloadUrl: raw.downloadUrl
      ? raw.downloadUrl.startsWith('http')
        ? raw.downloadUrl
        : `https://getillustrations.com${raw.downloadUrl}`
      : null,
    source: 'getillustrations',
  };
}

function normalizeIcon(raw, pack) {
  if (!raw) return null;
  const tags = String(raw.tags || '')
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);
  return {
    id: String(raw.id),
    kind: 'icon',
    name: raw.name || tags.slice(0, 2).join(' ') || `Icon ${raw.id}`,
    tags,
    categoryId: pack ? String(pack.id) : null,
    section: raw.section || null,
    packId: String(pack?.id || ''),
    packName: pack?.name || '',
    imageUrl: raw.imageUrl || null,
    thumbnailUrl: raw.thumbnailUrl || raw.imageUrl || null,
    svgAvailable: true,
    hasAccess: Boolean(raw.purchased || pack?.hasAccess),
    downloadUrl: raw.downloadUrl
      ? raw.downloadUrl.startsWith('http')
        ? raw.downloadUrl
        : `https://getillustrations.com${raw.downloadUrl}`
      : null,
    source: 'getillustrations',
  };
}

async function listCategories() {
  const data = await giFetch('/categories');
  const items = Array.isArray(data?.items) ? data.items : [];
  return items.map((c) => ({ id: String(c.id), name: c.name || String(c.id) }));
}

async function listStyles() {
  const data = await giFetch('/styles');
  const items = Array.isArray(data?.items) ? data.items : [];
  return items.map((s) => ({ id: String(s.id), name: s.name || String(s.id) }));
}

async function listFreeIllustrationPacks() {
  const cacheKey = 'gi:free-illustration-packs';
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const all = await listAllPages((page) => giFetch('/packs', { page, limit: 100 }));
  const free = all
    .map(normalizePack)
    .filter((p) => p && (p.isFree || p.hasAccess));
  cacheSet(cacheKey, free);
  return free;
}

async function listFreeIconPacks() {
  const cacheKey = 'gi:free-icon-packs';
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const all = await listAllPages((page) => giFetch('/icon-packs', { page, limit: 100 }));
  const free = all
    .map(normalizePack)
    .filter((p) => p && (p.isFree || p.hasAccess));
  cacheSet(cacheKey, free);
  return free;
}

async function listPackIllustrations(pack) {
  const packId = String(pack.id);
  const cacheKey = `gi:pack-ill:${packId}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const rawItems = await listAllPages((page) =>
    giFetch(`/packs/${encodeURIComponent(packId)}/illustrations`, { page, limit: 100 })
  );
  const items = rawItems.map((r) => normalizeIllustration(r, pack)).filter(Boolean);
  cacheSet(cacheKey, items);
  return items;
}

async function listAllPackIcons(pack) {
  const packId = String(pack.id);
  const cacheKey = `gi:pack-icons-all:${packId}`;
  const cached = cacheGet(cacheKey);
  if (cached) return cached;

  const rawItems = await listAllPages((page) =>
    giFetch(`/icon-packs/${encodeURIComponent(packId)}/icons`, { page, limit: 100 })
  );
  const items = rawItems.map((r) => normalizeIcon(r, pack)).filter(Boolean);
  cacheSet(cacheKey, items);
  return items;
}

async function listPackIconsPage(pack, { page = 1, limit = 48, q = '' } = {}) {
  const packId = String(pack.id);
  const data = await giFetch(`/icon-packs/${encodeURIComponent(packId)}/icons`, {
    page,
    limit,
  });
  let items = (Array.isArray(data?.items) ? data.items : [])
    .map((r) => normalizeIcon(r, pack))
    .filter(Boolean);
  if (q) items = items.filter((i) => matchesQuery(i, q));
  return {
    items,
    page: Number(data?.page) || page,
    limit: Number(data?.limit) || limit,
    total: Number(data?.total) || items.length,
    totalPages: Number(data?.totalPages) || 1,
  };
}

/**
 * Download a clean SVG for an icon/illustration the account can access.
 * Prefer /download, fall back to /svg/:type/:id.
 */
async function downloadSvgBuffer({ type = 'icon', packId, assetId }) {
  const key = getApiKey();
  const attempts = [
    `${GI_BASE}/download/${encodeURIComponent(type)}/${encodeURIComponent(packId)}/${encodeURIComponent(assetId)}?format=svg`,
    `${GI_BASE}/svg/${encodeURIComponent(type)}/${encodeURIComponent(assetId)}`,
  ];

  let lastErr = null;
  for (const url of attempts) {
    try {
      const res = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${key}`,
          Accept: 'image/svg+xml,application/json,*/*',
        },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      readRateLimit(res);
      if (!res.ok) {
        lastErr = new AppError(
          `GetIllustrations download failed (${res.status})`,
          res.status === 429 ? 429 : 502
        );
        continue;
      }
      const contentType = String(res.headers.get('content-type') || '').toLowerCase();
      if (contentType.includes('json')) {
        const body = await res.json();
        const inline = body?.svg_inline || body?.svg || body?.data?.svg_inline;
        if (inline && String(inline).includes('<svg')) {
          return Buffer.from(String(inline), 'utf8');
        }
        const svgUrl = body?.svg_url || body?.url;
        if (svgUrl) {
          const svgRes = await fetch(svgUrl, {
            signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          });
          if (!svgRes.ok) continue;
          const text = await svgRes.text();
          if (text.includes('<svg')) return Buffer.from(text, 'utf8');
        }
        continue;
      }
      const text = await res.text();
      if (text && text.includes('<svg')) return Buffer.from(text, 'utf8');
      lastErr = new AppError('Downloaded asset was not a valid SVG', 502);
    } catch (err) {
      if (err instanceof AppError) lastErr = err;
      else lastErr = new AppError(messages.GETILLUSTRATIONS_REQUEST_FAILED, 502);
    }
  }
  throw lastErr || new AppError(messages.GETILLUSTRATIONS_REQUEST_FAILED, 502);
}

async function getFreeIconPackById(packId) {
  const packs = await listFreeIconPacks();
  return packs.find((p) => String(p.id) === String(packId)) || null;
}

function matchesQuery(item, q) {
  if (!q) return true;
  const needle = String(q).trim().toLowerCase();
  if (!needle) return true;
  const hay = [item.name, item.packName, ...(item.tags || [])].join(' ').toLowerCase();
  return hay.includes(needle);
}

function paginate(items, page = 1, limit = 48) {
  const p = Math.max(1, Number(page) || 1);
  const l = Math.min(100, Math.max(1, Number(limit) || 48));
  const start = (p - 1) * l;
  return {
    items: items.slice(start, start + l),
    page: p,
    limit: l,
    total: items.length,
    totalPages: Math.max(1, Math.ceil(items.length / l) || 1),
  };
}

async function mapPool(items, concurrency, mapper) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) || 1 }, async () => {
    while (next < items.length) {
      const i = next;
      next += 1;
      results[i] = await mapper(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

/**
 * Free illustrations across all free packs, grouped/filterable by GI category.
 */
async function getFreeIllustrationsCatalog({ categoryId = '', q = '', page = 1, limit = 48 } = {}) {
  const [categories, packs] = await Promise.all([listCategories(), listFreeIllustrationPacks()]);
  const catName = new Map(categories.map((c) => [c.id, c.name]));

  const nested = await mapPool(packs, 4, (pack) => listPackIllustrations(pack));
  const all = nested.flat();

  const counts = new Map();
  for (const item of all) {
    const id = item.categoryId || 'uncategorized';
    counts.set(id, (counts.get(id) || 0) + 1);
  }

  const categoryOptions = [
    ...categories
      .filter((c) => counts.has(c.id))
      .map((c) => ({ id: c.id, name: c.name, count: counts.get(c.id) || 0 })),
  ];
  if (counts.has('uncategorized')) {
    categoryOptions.push({
      id: 'uncategorized',
      name: 'Uncategorized',
      count: counts.get('uncategorized'),
    });
  }

  let filtered = all;
  if (categoryId) {
    filtered = filtered.filter((i) => String(i.categoryId || 'uncategorized') === String(categoryId));
  }
  filtered = filtered.filter((i) => matchesQuery(i, q));

  const pageData = paginate(filtered, page, limit);
  return {
    kind: 'illustration',
    categories: categoryOptions,
    packs: packs.map((p) => ({
      id: p.id,
      name: p.name,
      thumbnail: p.thumbnail,
      itemsCount: p.itemsCount,
      style: p.style,
    })),
    ...pageData,
    items: pageData.items.map((i) => ({
      ...i,
      categoryName: catName.get(i.categoryId) || (i.categoryId ? String(i.categoryId) : 'Uncategorized'),
    })),
    rateLimit: getRateLimit(),
  };
}

/**
 * Free icons — packs act as categories (icon taxonomy differs from illustrations).
 */
async function getFreeIconsCatalog({ packId = '', q = '', page = 1, limit = 48 } = {}) {
  const packs = await listFreeIconPacks();
  const categories = packs.map((p) => ({
    id: p.id,
    name: p.name,
    count: p.itemsCount,
    thumbnail: p.thumbnail,
  }));

  const selectedPack = packId
    ? packs.find((p) => String(p.id) === String(packId))
    : packs[0] || null;

  if (!selectedPack) {
    return {
      kind: 'icon',
      categories,
      packs: categories,
      items: [],
      page: 1,
      limit,
      total: 0,
      totalPages: 1,
      selectedPackId: null,
      rateLimit: getRateLimit(),
    };
  }

  const pageData = await listPackIconsPage(selectedPack, { page, limit, q });

  return {
    kind: 'icon',
    categories,
    packs: categories,
    selectedPackId: selectedPack.id,
    ...pageData,
    rateLimit: getRateLimit(),
  };
}

async function getFreeCatalog(opts = {}) {
  if (!isConfigured()) {
    return {
      configured: false,
      kind: opts.kind || 'illustration',
      categories: [],
      items: [],
      page: 1,
      limit: Number(opts.limit) || 48,
      total: 0,
      totalPages: 1,
      rateLimit: null,
    };
  }

  const kind = String(opts.kind || 'illustration').toLowerCase() === 'icon' ? 'icon' : 'illustration';
  const data =
    kind === 'icon'
      ? await getFreeIconsCatalog(opts)
      : await getFreeIllustrationsCatalog(opts);

  return { configured: true, ...data };
}

async function getMeta() {
  if (!isConfigured()) {
    return {
      configured: false,
      categories: [],
      styles: [],
      freeIllustrationPacks: [],
      freeIconPacks: [],
      rateLimit: null,
    };
  }

  const [categories, styles, freeIllustrationPacks, freeIconPacks] = await Promise.all([
    listCategories(),
    listStyles(),
    listFreeIllustrationPacks(),
    listFreeIconPacks(),
  ]);

  return {
    configured: true,
    categories,
    styles,
    freeIllustrationPacks: freeIllustrationPacks.map((p) => ({
      id: p.id,
      name: p.name,
      thumbnail: p.thumbnail,
      itemsCount: p.itemsCount,
      style: p.style,
    })),
    freeIconPacks: freeIconPacks.map((p) => ({
      id: p.id,
      name: p.name,
      thumbnail: p.thumbnail,
      itemsCount: p.itemsCount,
    })),
    rateLimit: getRateLimit(),
  };
}

function clearCacheForTests() {
  cache.clear();
  lastRateLimit = { limit: null, remaining: null, reset: null, tier: null };
}

module.exports = {
  isConfigured,
  getApiKey,
  getRateLimit,
  listCategories,
  listStyles,
  listFreeIllustrationPacks,
  listFreeIconPacks,
  listAllPackIcons,
  listPackIconsPage,
  downloadSvgBuffer,
  getFreeIconPackById,
  getFreeCatalog,
  getMeta,
  clearCacheForTests,
  GI_BASE,
};
